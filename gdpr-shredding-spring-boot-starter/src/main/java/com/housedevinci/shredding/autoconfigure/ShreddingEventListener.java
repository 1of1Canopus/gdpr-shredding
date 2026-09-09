package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.domain.BlindIndex;
import com.housedevinci.shredding.domain.EncryptedValue;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.Normalisation;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingContext;
import java.math.BigDecimal;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.LocalDate;
import java.util.List;
import java.util.Objects;
import org.hibernate.event.spi.PostInsertEvent;
import org.hibernate.event.spi.PostInsertEventListener;
import org.hibernate.event.spi.PostLoadEvent;
import org.hibernate.event.spi.PostLoadEventListener;
import org.hibernate.event.spi.PostUpdateEvent;
import org.hibernate.event.spi.PostUpdateEventListener;
import org.hibernate.event.spi.PreInsertEvent;
import org.hibernate.event.spi.PreInsertEventListener;
import org.hibernate.event.spi.PreUpdateEvent;
import org.hibernate.event.spi.PreUpdateEventListener;
import org.hibernate.persister.entity.EntityPersister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The write path.
 *
 * <p>{@code PreInsertEventListener} and {@code PreUpdateEventListener} fire immediately before
 * {@code EntityInsertAction} and {@code EntityUpdateAction} bind the state array, which is when the
 * converters run; the {@code Post} listeners pop the scope again. That ordering is the load-bearing
 * assumption of the whole write path, which is why a converter with no scope fails closed rather
 * than defaulting to anything.
 *
 * <p>The same listeners fill in the {@code @BlindIndex} columns, so the write path and the query
 * path share one normalisation and one derivation (control 10), and enforce that a persisted row's
 * data subject never changes (control 14).
 */
public final class ShreddingEventListener
    implements PreInsertEventListener,
        PostInsertEventListener,
        PreUpdateEventListener,
        PostUpdateEventListener,
        PostLoadEventListener {

  private static final long serialVersionUID = 1L;

  private static final Logger log = LoggerFactory.getLogger(ShreddingEventListener.class);

  private final transient java.util.function.Supplier<ShreddedModel> modelSupplier;
  private transient volatile ShreddedModel resolvedModel;
  private final TenantSupplier tenantSupplier;
  private final transient BlindIndex blindIndex;

  /** Where the ambient tenant comes from when {@code @Shredded(tenant=...)} is not given. */
  @FunctionalInterface
  public interface TenantSupplier {
    TenantId currentTenant();
  }

  public ShreddingEventListener(
      java.util.function.Supplier<ShreddedModel> modelSupplier,
      TenantSupplier tenantSupplier,
      BlindIndex blindIndex) {
    // A supplier, not the model: the model is derived from the EntityManagerFactory's metamodel,
    // and this listener has to be handed to Hibernate while that factory is still being built.
    this.modelSupplier = Objects.requireNonNull(modelSupplier, "modelSupplier");
    this.tenantSupplier = Objects.requireNonNull(tenantSupplier, "tenantSupplier");
    this.blindIndex = blindIndex;
  }

  @Override
  public boolean onPreInsert(PreInsertEvent event) {
    var fields = model().byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return false;
    }
    var scope = scopeFor(event.getEntity(), fields);
    registerTransactionBoundaryClear(event.getSession());
    ShreddingContext.push(scope);
    // CIPHER-08: nothing between the push and the return can leak the scope past this write. A
    // converter refusal, a constraint or writeBlindIndexes itself throwing all reach PostInsert
    // never running, which is exactly when a pooled thread would otherwise keep serving the wrong
    // subject's scope to the next, unrelated write.
    try {
      writeBlindIndexes(event.getPersister(), event.getState(), scope.tenant());
    } catch (RuntimeException e) {
      ShreddingContext.pop();
      throw e;
    }
    return false;
  }

  @Override
  public void onPostInsert(PostInsertEvent event) {
    if (model().byEntityName().containsKey(entityName(event.getPersister()))) {
      ShreddingContext.pop();
    }
  }

  @Override
  public boolean onPreUpdate(PreUpdateEvent event) {
    var fields = model().byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return false;
    }
    var scope = scopeFor(event.getEntity(), fields);
    // QUESTIONS #4, ruling (c): the previous subject is read from the stored blob's own header,
    // not from a cache of what this process happened to load.
    //
    // The ruling's proposed optimisation - skip the round trip when no @Shredded field is dirty -
    // is unsound for an entity mapped the ordinary way (no @DynamicUpdate, which Customer is not):
    // Hibernate's default UPDATE rewrites every basic column, including every shredded one, so
    // every converter runs again regardless of whether its Java value changed, on every update.
    // "No shredded field dirty" therefore does not mean "no re-encryption is about to happen"; it
    // can be true on exactly the update this check exists for, when only a non-shredded property
    // such as the subject's own source field changed. Detecting the sound version of the
    // optimisation would mean reading persister.isDynamicUpdate() and reasoning about it alongside
    // dirtiness - more moving parts in a correctness-critical check than the one extra query it
    // saves. The check runs on every update to a shredded entity instead. Recorded in QUESTIONS.md
    // CIPHER-01/#4 as a considered deviation from the literal optimisation text.
    refuseIfSubjectMoved(event, fields, scope);
    registerTransactionBoundaryClear(event.getSession());
    ShreddingContext.push(scope);
    try {
      writeBlindIndexes(event.getPersister(), event.getState(), scope.tenant());
    } catch (RuntimeException e) {
      ShreddingContext.pop();
      throw e;
    }
    return false;
  }

  /**
   * CIPHER-08's second line of defence, registered once per write: whatever state the try/finally
   * above did not catch - the flush itself failing after {@code Pre*} returned successfully, most
   * notably - is cleared when the transaction ends, success or not. {@code Post} listeners by
   * construction do not run on the failure path, so they cannot be the only place this happens.
   */
  private static void registerTransactionBoundaryClear(
      org.hibernate.engine.spi.SharedSessionContractImplementor session) {
    ((org.hibernate.event.spi.EventSource) session)
        .getTransactionCompletionCallbacks()
        .registerCallback(
            (org.hibernate.engine.spi.TransactionCompletionCallbacks.AfterCompletionCallback)
                (success, s) -> ShreddingContext.clearAll());
  }

  @Override
  public void onPostUpdate(PostUpdateEvent event) {
    if (model().byEntityName().containsKey(entityName(event.getPersister()))) {
      ShreddingContext.pop();
    }
  }

  @Override
  public void onPostLoad(PostLoadEvent event) {
    var fields = model().byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return;
    }
    String entityName = entityName(event.getPersister());
    // CIPHER-13: drain every shredded field's decoded header for this row up front, whatever
    // happens next below - a field this row never decoded (its column was null) correctly has
    // nothing recorded and nothing to drain; anything that *was* decoded must not survive this
    // method to be mistaken for a later, unrelated row's header.
    var decodedByField = new java.util.LinkedHashMap<String, ShreddingContext.Decoded>();
    for (var field : fields) {
      ShreddingContext.takeDecoded(entityName + "." + field.fieldName())
          .ifPresent(d -> decodedByField.put(field.fieldName(), d));
    }
    if (decodedByField.isEmpty()) {
      // Nothing on this row was ever decrypted (every shredded column null, or this load went
      // through an explicit read scope that already verified atomically in the converter) - there
      // is nothing left to check.
      return;
    }
    // CIPHER-01: every shredded field's converter has already run by the time any load listener
    // fires (see ShreddingContext.Decoded). This is the first point at which the row's true
    // subject and tenant - resolved from the now fully-hydrated entity, the same way the write
    // path resolves them - can be compared against what each field's header actually said. A
    // mismatch throws here, before the entity is returned from the load that is in progress.
    String trueSubject;
    try {
      trueSubject = resolveSubject(event.getEntity(), fields);
    } catch (RuntimeException e) {
      // CIPHER-12: this row carries at least one already-decrypted shredded value (decodedByField
      // is non-empty, checked above) and its true subject cannot be established at all. An
      // unresolvable subject is not a reason to let the read through - it is the exact reason this
      // check exists. The attacker who can move a ciphertext between rows is by construction the
      // attacker who can null one more column, and a `return` here used to hand the moved value
      // straight back through this same code path.
      log.warn(
          "shredding: refusing to load {}: it carries a shredded value but its subject could not"
              + " be resolved ({})",
          entityName,
          e.getClass().getSimpleName());
      throw new ShreddingException(
          ErrorCodes.SUBJECT_UNRESOLVED,
          "the data subject of "
              + entityName
              + " could not be resolved while it carries at least one shredded value. An unknown"
              + " owner is never a reason to display an already-decrypted value; fix the subject"
              + " source, or erase the row if it is orphaned.",
          e);
    }
    var first = fields.get(0);
    TenantId trueTenant =
        first.tenant() != null ? TenantId.of(first.tenant().evaluate(event.getEntity())) : null;
    SubjectId subjectId = SubjectId.of(trueSubject);
    for (var entry : decodedByField.entrySet()) {
      var header = entry.getValue();
      boolean subjectMismatch = !header.subject().equals(subjectId);
      boolean tenantMismatch = trueTenant != null && !header.tenant().equals(trueTenant);
      if (subjectMismatch || tenantMismatch) {
        log.warn(
            "shredding: refusing to load {}.{}: the stored value's header names a different"
                + " {} than the row it was read from",
            entityName,
            entry.getKey(),
            subjectMismatch ? "subject" : "tenant");
        throw new ShreddingException(
            ErrorCodes.SUBJECT_MISMATCH,
            "the stored value for "
                + entityName
                + "."
                + entry.getKey()
                + " belongs to a different "
                + (subjectMismatch ? "subject" : "tenant")
                + " than the row it was read from. A ciphertext moved between rows, subjects or"
                + " tenants is refused rather than decrypted and displayed.");
      }
    }
  }

  @Override
  public boolean requiresPostCommitHandling(EntityPersister persister) {
    return false;
  }

  private ShreddedModel model() {
    ShreddedModel current = resolvedModel;
    if (current == null) {
      current = modelSupplier.get();
      resolvedModel = current;
    }
    return current;
  }

  /**
   * QUESTIONS #4, ruling (c): a second fetch of the row's current shredded columns, decoded only
   * for the header - no key material is touched. When the stored row has no shredded blob at all
   * (every shredded column null, or the field was only just added to the entity) there is nothing
   * that could have been moved out of an erasure scope, and the update is allowed.
   *
   * <p>CIPHER-14: every shredded column of the entity is read in this one query, not only {@code
   * fields.get(0)}. Checking a single column let a row whose first shredded column was null and
   * whose second held a live ciphertext escape unchecked: the subject changed, Hibernate's default
   * (non-{@code @DynamicUpdate}) UPDATE re-encrypted every shredded column under the new subject's
   * key on the very next flush, and the row left the original subject's erasure scope for good.
   * Early return happens only when *every* shredded column is null, which is the case the ruling
   * actually blessed.
   */
  private void refuseIfSubjectMoved(
      PreUpdateEvent event,
      List<ShreddedModel.ShreddedField> fields,
      ShreddingContext.Scope scope) {
    var first = fields.get(0);
    String[] idColumns = event.getPersister().getIdentifierColumnNames();
    if (idColumns.length != 1) {
      // Composite identifiers are not supported by this check; documented as a residual rather
      // than silently wrong.
      return;
    }
    String columns =
        fields.stream()
            .map(f -> quote(f.columnName()))
            .collect(java.util.stream.Collectors.joining(", "));
    String sql =
        "SELECT "
            + columns
            + " FROM "
            + quote(first.tableName())
            + " WHERE "
            + quote(idColumns[0])
            + " = ?";
    Object[] stored =
        event
            .getSession()
            .doReturningWork(
                connection -> {
                  try (PreparedStatement ps = connection.prepareStatement(sql)) {
                    ps.setObject(1, event.getId());
                    try (ResultSet rs = ps.executeQuery()) {
                      if (!rs.next()) {
                        return null;
                      }
                      Object[] row = new Object[fields.size()];
                      for (int i = 0; i < fields.size(); i++) {
                        row[i] = rs.getBytes(i + 1);
                      }
                      return row;
                    }
                  }
                });
    if (stored == null) {
      return;
    }
    for (int i = 0; i < fields.size(); i++) {
      byte[] column = (byte[]) stored[i];
      if (column == null) {
        // Not the whole row - just this one shredded column, unwritten so far. Keep checking the
        // rest; only "every column null" is the residual the ruling accepts.
        continue;
      }
      var header = EncryptedValue.decode(column);
      boolean subjectMoved = !header.subject().equals(scope.subject());
      boolean tenantMoved = !header.tenant().equals(scope.tenant());
      if (subjectMoved || tenantMoved) {
        throw new ShreddingException(
            ErrorCodes.SUBJECT_IMMUTABLE,
            "the data subject of a persisted "
                + first.entityName()
                + " row cannot change. It was captured at first persist and is bound into the"
                + " ciphertext's own header; changing it would re-encrypt the row under another"
                + " subject's key and move it out of the first subject's erasure scope.");
      }
    }
  }

  private static String quote(String identifier) {
    return "\"" + identifier.replace("\"", "\"\"") + "\"";
  }

  private ShreddingContext.Scope scopeFor(Object entity, List<ShreddedModel.ShreddedField> fields) {
    var first = fields.get(0);
    TenantId tenant =
        first.tenant() != null ? TenantId.of(first.tenant().evaluate(entity)) : requireTenant();
    return new ShreddingContext.Scope(
        tenant, SubjectId.of(resolveSubject(entity, fields)), first.entityName());
  }

  private static String resolveSubject(Object entity, List<ShreddedModel.ShreddedField> fields) {
    var first = fields.get(0);
    String subject = first.subject().evaluate(entity);
    for (var other : fields) {
      String candidate = other.subject().evaluate(entity);
      if (!subject.equals(candidate)) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "the @Shredded fields of "
                + first.entityName()
                + " resolve to different data subjects. One row belongs to one subject, or an"
                + " erasure would leave half of it readable.");
      }
    }
    return subject;
  }

  private TenantId requireTenant() {
    TenantId tenant = tenantSupplier.currentTenant();
    if (tenant == null) {
      // Control 15: no default tenant, no empty-string fallback.
      throw new ShreddingException(
          ErrorCodes.TENANT_MISSING,
          "no tenant in context. A data key is per (tenant, subject); with no tenant there is no"
              + " key to use and no erasure scope to belong to. Supply a TenantSupplier bean, or"
              + " give @Shredded a tenant expression.");
    }
    return tenant;
  }

  private void writeBlindIndexes(EntityPersister persister, Object[] state, TenantId tenant) {
    var indexes = model().blindIndexesByEntityName().get(entityName(persister));
    if (indexes == null || indexes.isEmpty()) {
      return;
    }
    if (blindIndex == null) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "shredding.blind-index.hmac-secret is required because this application declares"
              + " @BlindIndex columns");
    }
    String[] names = persister.getPropertyNames();
    for (var index : indexes) {
      int sourceIndex = indexOf(names, index.ofFieldName());
      int targetIndex = indexOf(names, index.fieldName());
      if (sourceIndex < 0 || targetIndex < 0) {
        continue;
      }
      Object value = state[sourceIndex];
      state[targetIndex] =
          value == null
              ? null
              : blindIndex.compute(
                  tenant, index.entityName(), index.ofFieldName(), normalise(value));
    }
  }

  /** One code path, shared by the write path here and by the query helper. */
  public static String normalise(Object value) {
    if (value instanceof String s) {
      return Normalisation.forText(s);
    }
    if (value instanceof LocalDate d) {
      return Normalisation.forDate(d);
    }
    if (value instanceof BigDecimal b) {
      return Normalisation.forDecimal(b);
    }
    if (value instanceof byte[] b) {
      return Normalisation.forBytes(b);
    }
    throw new ShreddingException(
        ErrorCodes.CONFIG,
        "@BlindIndex does not support " + value.getClass().getName() + " values");
  }

  private static int indexOf(String[] names, String name) {
    for (int i = 0; i < names.length; i++) {
      if (names[i].equals(name)) {
        return i;
      }
    }
    return -1;
  }

  private static String entityName(EntityPersister persister) {
    String name = persister.getEntityName();
    int dot = name.lastIndexOf('.');
    return dot < 0 ? name : name.substring(dot + 1);
  }
}
