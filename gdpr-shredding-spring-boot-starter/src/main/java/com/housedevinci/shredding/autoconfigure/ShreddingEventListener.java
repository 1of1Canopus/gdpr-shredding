package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.domain.BlindIndex;
import com.housedevinci.shredding.domain.EncryptedValue;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.Normalisation;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.Placeholders;
import com.housedevinci.shredding.jpa.ShreddingContext;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import java.math.BigDecimal;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.hibernate.event.spi.AutoFlushEvent;
import org.hibernate.event.spi.AutoFlushEventListener;
import org.hibernate.event.spi.FlushEvent;
import org.hibernate.event.spi.FlushEventListener;
import org.hibernate.event.spi.PostDeleteEvent;
import org.hibernate.event.spi.PostDeleteEventListener;
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
        PostDeleteEventListener,
        FlushEventListener,
        AutoFlushEventListener,
        PostLoadEventListener {

  private static final long serialVersionUID = 1L;

  private static final Logger log = LoggerFactory.getLogger(ShreddingEventListener.class);

  private final transient java.util.function.Supplier<ShreddedModel> modelSupplier;
  private transient volatile ShreddedModel resolvedModel;
  private final TenantSupplier tenantSupplier;
  private final transient BlindIndex blindIndex;
  private final transient RandomSource random;

  /**
   * The token of the write scope this thread's in-flight bind pushed, so the matching {@code Post*}
   * listener pops exactly that one and never another entity's (Cipher item 14).
   */
  private static final ThreadLocal<Long> writeScopeToken = new ThreadLocal<>();

  /** Where the ambient tenant comes from when {@code @Shredded(tenant=...)} is not given. */
  @FunctionalInterface
  public interface TenantSupplier {
    TenantId currentTenant();
  }

  public ShreddingEventListener(
      java.util.function.Supplier<ShreddedModel> modelSupplier,
      TenantSupplier tenantSupplier,
      BlindIndex blindIndex) {
    this(modelSupplier, tenantSupplier, blindIndex, RandomSource.secure());
  }

  public ShreddingEventListener(
      java.util.function.Supplier<ShreddedModel> modelSupplier,
      TenantSupplier tenantSupplier,
      BlindIndex blindIndex,
      RandomSource random) {
    this.random = Objects.requireNonNull(random, "random");
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
    // Design §3.1: an assigned or SEQUENCE id exists here; an IDENTITY id does not, and the row is
    // bound to a random, unbound intermediate that onPostInsert rebinds. The intermediate carries
    // tag 0x7f, which matches no real identifier, so an insert captured by change data capture, a
    // trigger or a physical replica between the two statements is bound to no row at all.
    // S-1, design addendum: the transaction is where this write is verified before it commits.
    // A write with nowhere to settle is refused here rather than performed and never checked.
    WriteVerification.requireSettlementAnchor(event.getSession(), entityName(event.getPersister()));
    Object id = event.getId();
    RowId rowId = id == null ? RowId.unboundIntermediate(random) : RowId.ofIdentifier(id);
    var scope = scopeFor(event.getEntity(), fields, rowId);
    // Cipher item 14: on the state array, before writeBlindIndexes, so a placeholder never reaches
    // a blind index and the refusal names the entity rather than only the column.
    refusePlaceholdersInState(event.getPersister(), event.getState(), fields);
    registerTransactionBoundaryClear(event.getSession());
    long token = ShreddingContext.pushBind(scope, event.getSession());
    writeScopeToken.set(token);
    // CIPHER-08: nothing between the push and the return can leak the scope past this write. A
    // converter refusal, a constraint or writeBlindIndexes itself throwing all reach PostInsert
    // never running, which is exactly when a pooled thread would otherwise keep serving the wrong
    // subject's scope to the next, unrelated write - and pushBind drops residue first anyway.
    try {
      writeBlindIndexes(event.getPersister(), event.getState(), scope);
    } catch (RuntimeException e) {
      ShreddingContext.popWrite(token);
      throw e;
    }
    return false;
  }

  /**
   * Design §3.1 and §1.3: pops the scope, rebinds an {@code IDENTITY} row to its real identifier,
   * and then checks post hoc that what actually reached the database is bound to this row and this
   * subject.
   *
   * <p>Both halves throw out of the flush on failure, which aborts the transaction (Cipher item 6).
   * There is no "log and carry on" branch: a row left bound to an intermediate would be permanently
   * unreadable, and a row bound to the wrong subject would sit in the wrong erasure scope.
   */
  @Override
  public void onPostInsert(PostInsertEvent event) {
    var fields = model().byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return;
    }
    var scope = ShreddingContext.current().orElse(null);
    Long token = writeScopeToken.get();
    if (token != null) {
      ShreddingContext.popWrite(token);
      writeScopeToken.remove();
    }
    if (scope == null) {
      return;
    }
    RowId bound = RowId.ofIdentifier(event.getId());
    if (scope.rowId().isUnboundIntermediate()) {
      rebindToGeneratedId(event, fields, scope, bound);
    }
    // The belt (design item 14): an immediate read-back, which catches an unbatched write inside
    // the flush that produced it. It is fail-open by nature - under batching the row is still in
    // the JDBC batch and there is nothing to read - so it is no longer the control.
    refuseIfStoredHeadersDisagree(
        event.getSession(), event.getPersister(), event.getId(), fields, scope, bound, "inserted");
    // The control (S-1): a debt this session cannot commit without settling.
    WriteVerification.owe(
        event.getSession(),
        entityName(event.getPersister()),
        fields.get(0).tableName(),
        singleIdColumn(event.getPersister()),
        event.getId(),
        fields,
        scope,
        bound,
        "inserted");
  }

  @Override
  public boolean onPreUpdate(PreUpdateEvent event) {
    var fields = model().byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return false;
    }
    WriteVerification.requireSettlementAnchor(event.getSession(), entityName(event.getPersister()));
    var scope = scopeFor(event.getEntity(), fields, RowId.ofIdentifier(event.getId()));
    // QUESTIONS #4, ruling (c): the previous subject is read from the stored blob's own header,
    // not from a cache of what this process happened to load.
    //
    // The ruling's proposed optimisation - skip the round trip when no @Shredded field is dirty -
    // is unsound for an entity mapped the ordinary way (no @DynamicUpdate): Hibernate's default
    // UPDATE rewrites every basic column, including every shredded one, so every converter runs
    // again regardless of whether its Java value changed. Recorded in QUESTIONS.md CIPHER-01/#4 as
    // a considered deviation. Cipher item 14: this runs on every update, unconditionally, and its
    // insert-side counterpart is the post-hoc check in onPostInsert.
    refuseIfSubjectMoved(event.getSession(), event.getPersister(), event.getId(), fields, scope);
    refusePlaceholdersInState(event.getPersister(), event.getState(), fields);
    registerTransactionBoundaryClear(event.getSession());
    long token = ShreddingContext.pushBind(scope, event.getSession());
    writeScopeToken.set(token);
    try {
      writeBlindIndexes(event.getPersister(), event.getState(), scope);
    } catch (RuntimeException e) {
      ShreddingContext.popWrite(token);
      throw e;
    }
    return false;
  }

  @Override
  public void onPostUpdate(PostUpdateEvent event) {
    var fields = model().byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return;
    }
    var scope = ShreddingContext.current().orElse(null);
    Long token = writeScopeToken.get();
    if (token != null) {
      ShreddingContext.popWrite(token);
      writeScopeToken.remove();
    }
    if (scope == null) {
      return;
    }
    refuseIfStoredHeadersDisagree(
        event.getSession(),
        event.getPersister(),
        event.getId(),
        fields,
        scope,
        scope.rowId(),
        "updated");
    WriteVerification.owe(
        event.getSession(),
        entityName(event.getPersister()),
        fields.get(0).tableName(),
        singleIdColumn(event.getPersister()),
        event.getId(),
        fields,
        scope,
        scope.rowId(),
        "updated");
  }

  /**
   * S-1, design addendum. Inside one flush Hibernate executes insertions before deletions, so a row
   * inserted and deleted in the same flush would otherwise be settled against a row that
   * legitimately no longer exists. A deleted row has no stored header left to verify.
   */
  @Override
  public void onPostDelete(PostDeleteEvent event) {
    if (model().byEntityName().get(entityName(event.getPersister())) == null) {
      return;
    }
    WriteVerification.forgive(event.getSession(), entityName(event.getPersister()), event.getId());
  }

  /**
   * S-1, design addendum: the first of the two settlement points. Registered <em>appended</em> on
   * {@code FLUSH} and {@code AUTO_FLUSH}, so it runs after Hibernate's own flush listener, which
   * means after {@code ActionQueue.executeActions} has called {@code
   * JdbcCoordinator.executeBatch()} for every action queue. That is the earliest moment at which
   * what was written is readable at any batch size, and it bounds the ledger to one flush rather
   * than one transaction.
   *
   * <p>A refusal thrown here escapes the flush and aborts the transaction, which is the point.
   */
  @Override
  public void onFlush(FlushEvent event) {
    WriteVerification.settle(event.getSession());
  }

  @Override
  public void onAutoFlush(AutoFlushEvent event) {
    WriteVerification.settle(event.getSession());
  }

  /**
   * CIPHER-08's second line of defence, registered once per write: whatever state the try/finally
   * above did not catch - the flush itself failing after {@code Pre*} returned successfully, most
   * notably - is cleared when the transaction ends, success or not. {@code Post} listeners by
   * construction do not run on the failure path, so they cannot be the only place this happens.
   *
   * <p>C-33: this clears <em>this session's write scopes only</em>. The old {@code clearAll()} also
   * dropped every read region on the thread, so a transaction that wrote a shredded entity and
   * committed inside an open read bracket erased that bracket's debt and let an unverified decode
   * out. A read region belongs to a call, never to a transaction, and nothing on the write path may
   * touch one.
   */
  private static void registerTransactionBoundaryClear(
      org.hibernate.engine.spi.SharedSessionContractImplementor session) {
    // Not cast to EventSource: a StatelessSession write reaches this listener too and
    // StatelessSessionImpl is not an EventSource. getTransactionCompletionCallbacks() is declared
    // on SharedSessionContractImplementor, which both implement.
    session
        .getTransactionCompletionCallbacks()
        .registerCallback(
            (org.hibernate.engine.spi.TransactionCompletionCallbacks.AfterCompletionCallback)
                (success, s) -> ShreddingContext.clearWriteScopesOwnedBy(session));
  }

  /**
   * The verifier (design §1, §4). Runs <strong>prepended</strong>, before Hibernate's own {@code
   * PostLoadEventListenerStandardImpl}, so no user {@code @PostLoad} method and no
   * {@code @EntityListeners} bean ever sees a placeholder (Cipher item 8).
   *
   * <p>For each shredded field whose value is currently the placeholder - which is exactly the
   * fields a converter ran on, so no query is needed to find them (C-35: this method issues no SQL
   * at all, where it used to issue one {@code SELECT} per loaded row) - it looks in the open read
   * region for a decode filed under this row's own key: the entity, the field, the tenant and
   * subject resolved from the now-hydrated entity, and the row id built from {@code event.getId()}.
   *
   * <ul>
   *   <li>Found ⇒ verified. It is this row's own header, under this region's own token (Cipher item
   *       4), so a decode left behind by another region is discarded rather than installed.
   *   <li>Not found, but the region holds a decode for this field under another subject or tenant ⇒
   *       {@code SHRED-SUBJECT-MISMATCH}: this row holds someone else's ciphertext.
   *   <li>Not found, but under this subject and another row ⇒ {@code SHRED-ROW-MISMATCH}: C-34, a
   *       ciphertext copied between two rows of one person.
   *   <li>Nothing at all ⇒ {@code SHRED-READ-UNVERIFIED}.
   * </ul>
   *
   * <p><strong>Every field is verified before any field is installed</strong> (Cipher item 9), so a
   * row that is refused is left holding placeholders: a first-level-cache retry that dodges the
   * eviction yields the marker, never the value.
   */
  @Override
  public void onPostLoad(PostLoadEvent event) {
    var fields = model().byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return;
    }
    String entityName = entityName(event.getPersister());
    Object entity = event.getEntity();

    var awaiting = new java.util.ArrayList<ShreddedModel.ShreddedField>();
    for (var field : fields) {
      if (Placeholders.isPlaceholder(readField(field, entity))) {
        awaiting.add(field);
      }
    }
    if (awaiting.isEmpty()) {
      // Every shredded column of this row was null: no converter ran, nothing was decrypted.
      return;
    }

    String trueSubject;
    try {
      trueSubject = resolveSubject(entity, fields);
    } catch (RuntimeException e) {
      // CIPHER-12: this row carries at least one decrypted shredded value and its true subject
      // cannot be established at all. An unresolvable owner is not a reason to let the read
      // through - it is the exact reason this check exists.
      log.warn(
          "shredding: refusing to load {}: it carries a shredded value but its subject could not"
              + " be resolved ({})",
          entityName,
          e.getClass().getSimpleName());
      throw refuseLoad(
          event,
          new ShreddingException(
              ErrorCodes.SUBJECT_UNRESOLVED,
              "the data subject of "
                  + entityName
                  + " could not be resolved while it carries at least one shredded value. An"
                  + " unknown owner is never a reason to display an already-decrypted value; fix"
                  + " the subject source, or erase the row if it is orphaned.",
              e));
    }
    SubjectId subjectId = SubjectId.of(trueSubject);
    RowId rowId = RowId.ofIdentifier(event.getId());

    // Verify first (Cipher item 9): collect every plaintext, refusing on the first field that
    // cannot be accounted for, and only then write anything into the entity.
    var verified = new java.util.ArrayList<byte[]>(awaiting.size());
    for (var field : awaiting) {
      // S-2: this field's own declared tenant, not the entity's first shredded field's.
      TenantId fieldTenant =
          field.tenant() != null
              ? TenantId.of(field.tenant().evaluate(entity))
              : ambientTenantOrNull();
      TenantId tenant = fieldTenant;
      if (tenant == null) {
        // No tenant expression and no ambient tenant: the region's own entry names one, and the
        // row cannot contradict what it does not carry. Fall back to whatever the single pending
        // key for this field says, so the drain is still exact on (subject, row).
        tenant = soleTenantFor(entityName, field.fieldName(), subjectId, rowId);
      }
      var key =
          new ShreddingContext.FrameKey(entityName, field.fieldName(), tenant, subjectId, rowId);
      var plaintext =
          tenant == null ? java.util.Optional.<byte[]>empty() : ShreddingContext.drain(key);
      if (plaintext.isEmpty()) {
        throw refuseLoad(event, explain(entityName, field, subjectId, rowId, fieldTenant));
      }
      verified.add(plaintext.get());
    }
    for (int i = 0; i < awaiting.size(); i++) {
      install(event, awaiting.get(i), entity, verified.get(i));
    }
  }

  /**
   * Says why a row's own decode was not in the region, in the DPO's vocabulary rather than the
   * module's. Never carries a value, a subject or a tenant: only the entity and the field.
   */
  private static ShreddingException explain(
      String entityName,
      ShreddedModel.ShreddedField field,
      SubjectId subject,
      RowId rowId,
      TenantId tenant) {
    var pending = ShreddingContext.pendingKeysFor(entityName, field.fieldName());
    boolean otherSubject =
        pending.stream()
            .anyMatch(
                k ->
                    !k.subject().equals(subject) || (tenant != null && !k.tenant().equals(tenant)));
    if (otherSubject) {
      log.warn(
          "shredding: refusing to load {}.{}: the stored value's header names a different subject"
              + " or tenant than the row it was read from",
          entityName,
          field.fieldName());
      return new ShreddingException(
          ErrorCodes.SUBJECT_MISMATCH,
          "the stored value for "
              + entityName
              + "."
              + field.fieldName()
              + " belongs to a different subject or tenant than the row it was read from. A"
              + " ciphertext moved between rows, subjects or tenants is refused rather than"
              + " decrypted and displayed.");
    }
    boolean otherRow =
        pending.stream().anyMatch(k -> k.subject().equals(subject) && !k.rowId().equals(rowId));
    if (otherRow) {
      log.warn(
          "shredding: refusing to load {}.{}: the stored value's header names a different row of"
              + " the same subject",
          entityName,
          field.fieldName());
      return new ShreddingException(
          ErrorCodes.ROW_MISMATCH,
          "the stored value for "
              + entityName
              + "."
              + field.fieldName()
              + " belongs to a different row of the same data subject. Two rows of one person are"
              + " not interchangeable: the row's own identifier is bound into the ciphertext, and a"
              + " value copied from another of their rows is refused rather than displayed as this"
              + " row's own.");
    }
    return new ShreddingException(
        ErrorCodes.READ_UNVERIFIED,
        "a decrypted value for "
            + entityName
            + "."
            + field.fieldName()
            + " could not be accounted for against the row it was loaded into. Either nothing was"
            + " filed for this row inside the open read region, or what was filed belongs to a"
            + " region that is no longer the one in force - residue an error unwound past, or a"
            + " decode from before an erasure. Neither is a proof, so the load is refused.");
  }

  /**
   * When the entity has no tenant expression and no ambient tenant is configured, the only tenant a
   * row can be checked against is the one its own header names. Exactly one candidate is required:
   * two headers for one field, subject and row that disagree about the tenant is itself a refusal.
   */
  private static TenantId soleTenantFor(
      String entityName, String fieldName, SubjectId subject, RowId rowId) {
    var candidates =
        ShreddingContext.pendingKeysFor(entityName, fieldName).stream()
            .filter(k -> k.subject().equals(subject) && k.rowId().equals(rowId))
            .map(ShreddingContext.FrameKey::tenant)
            .distinct()
            .toList();
    return candidates.size() == 1 ? candidates.get(0) : null;
  }

  private TenantId ambientTenantOrNull() {
    try {
      return tenantSupplier.currentTenant();
    } catch (RuntimeException e) {
      return null;
    }
  }

  private static Object readField(ShreddedModel.ShreddedField field, Object entity) {
    try {
      return field.javaField().get(entity);
    } catch (IllegalAccessException e) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "cannot read " + field.entityName() + "." + field.fieldName() + " to verify it",
          e);
    }
  }

  /**
   * Writes the verified plaintext into the entity <em>and</em> into the persistence context's
   * loaded state, so Hibernate's dirty checking compares plaintext against plaintext and a load
   * followed by a flush does not rewrite the column (Cipher item 11's second half). Both sides are
   * written together; there is no window in which one holds the value and the other the marker.
   */
  private void install(
      PostLoadEvent event, ShreddedModel.ShreddedField field, Object entity, byte[] plaintext) {
    Object value = field.converter().installable(plaintext);
    try {
      field.javaField().set(entity, value);
    } catch (IllegalAccessException e) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "cannot install the verified value of " + field.entityName() + "." + field.fieldName(),
          e);
    }
    var persistenceContext =
        ((org.hibernate.event.spi.EventSource) event.getSession()).getPersistenceContextInternal();
    var entry = persistenceContext.getEntry(entity);
    if (entry == null) {
      return;
    }
    Object[] loadedState = entry.getLoadedState();
    if (loadedState == null) {
      return;
    }
    int index = indexOf(event.getPersister().getPropertyNames(), field.fieldName());
    if (index >= 0 && index < loadedState.length) {
      loadedState[index] = value;
    }
  }

  /**
   * C-27: a row refused here has already been registered in the session's first-level cache, so a
   * second read of the same id in the same transaction would be a cache hit - no SQL, no converter,
   * no {@code PostLoad} - handing the instance straight back. Evicting it forces the next read
   * through a real load and through this check again.
   *
   * <p>Cipher item 9 makes the eviction a second line rather than the only one: because
   * verification runs before any install, the evicted instance is holding placeholders, not
   * plaintext, so even a caller that kept a reference to it has nothing.
   *
   * <p><strong>Deviation from Cipher's C-27 fix text (QUESTIONS.md): the transaction is not also
   * marked rollback-only.</strong> Cipher's own probes for this finding catch the refusal inside
   * the transactional callback and return a plain value; marking rollback-only makes every one of
   * them fail on {@code UnexpectedRollbackException} from the commit, outside their own try/catch.
   * One cannot both swallow the exception and avoid the commit-time one that marking rollback-only
   * exists to cause.
   */
  private ShreddingException refuseLoad(PostLoadEvent event, ShreddingException cause) {
    var session = (org.hibernate.event.spi.EventSource) event.getSession();
    try {
      session.evict(event.getEntity());
    } catch (RuntimeException e) {
      log.warn(
          "shredding: could not evict a refused {} from the persistence context",
          entityName(event.getPersister()),
          e);
    }
    return cause;
  }

  /**
   * Design §3.1, Cipher item 6: rewrites an {@code IDENTITY} row's shredded columns bound to the
   * identifier the database has just generated, in one {@code UPDATE}, in the same transaction,
   * over raw JDBC.
   *
   * <p>{@code session.doWork} and not the session's own query API or {@code flush()}: neither is
   * supported from inside the action queue, which is where a {@code PostInsert} listener runs. The
   * plaintext comes from the state array the insert itself carried, so nothing is decrypted to do
   * this.
   *
   * <p>A failure here throws, which fails the flush and aborts the transaction. Leaving the row
   * bound to the intermediate would make it permanently unreadable while looking, to every
   * application-level check, like a successful write.
   */
  private void rebindToGeneratedId(
      PostInsertEvent event,
      List<ShreddedModel.ShreddedField> fields,
      ShreddingContext.Scope scope,
      RowId bound) {
    var runtime = ShreddingRuntime.require();
    String[] names = event.getPersister().getPropertyNames();
    Object[] state = event.getState();
    var columns = new ArrayList<String>();
    var values = new ArrayList<byte[]>();
    for (var field : fields) {
      int index = indexOf(names, field.fieldName());
      if (index < 0) {
        continue;
      }
      Object value = state[index];
      if (value == null) {
        continue;
      }
      if (Placeholders.isPlaceholder(value)) {
        throw new ShreddingException(
            ErrorCodes.PLACEHOLDER,
            "refusing to rebind "
                + field.entityName()
                + "."
                + field.fieldName()
                + ": the inserted state holds the read placeholder, not a value");
      }
      columns.add(field.columnName());
      values.add(
          runtime
              .cipher()
              .encrypt(
                  // S-2: this field's own tenant, not the row's primary one.
                  scope.tenantFor(field.fieldName()),
                  scope.subject(),
                  bound,
                  field.entityName(),
                  field.fieldName(),
                  field.converter().encodeForRebind(value)));
    }
    if (columns.isEmpty()) {
      return;
    }
    String idColumn = singleIdColumn(event.getPersister());
    String sql =
        "UPDATE "
            + quote(fields.get(0).tableName())
            + " SET "
            + columns.stream()
                .map(c -> quote(c) + " = ?")
                .collect(java.util.stream.Collectors.joining(", "))
            + " WHERE "
            + quote(idColumn)
            + " = ?";
    // Not cast to EventSource: a StatelessSession insert of an IDENTITY-generated shredded entity
    // reaches this rebind too, and StatelessSessionImpl is not an EventSource.
    event
        .getSession()
        .doWork(
            connection -> {
              try (PreparedStatement ps = connection.prepareStatement(sql)) {
                for (int i = 0; i < values.size(); i++) {
                  ps.setBytes(i + 1, values.get(i));
                }
                ps.setObject(values.size() + 1, event.getId());
                if (ps.executeUpdate() != 1) {
                  throw new ShreddingException(
                      ErrorCodes.CONFIG,
                      "rebinding the shredded columns of a just-inserted "
                          + fields.get(0).entityName()
                          + " to its generated identifier updated no row. The insert is aborted"
                          + " rather than left bound to an intermediate that matches no row and"
                          + " can never be read back.");
                }
              }
            });
  }

  /**
   * Design §1.3, Cipher item 14: after the flush has written the row, what is actually stored is
   * read back and every header is compared against the scope the row was written under. A bind
   * performed under a residual scope - the shape C-41 demonstrated - is refused here, inside the
   * same flush and before the commit, rather than left sitting in another subject's erasure scope.
   */
  private void refuseIfStoredHeadersDisagree(
      org.hibernate.engine.spi.SharedSessionContractImplementor session,
      EntityPersister persister,
      Object id,
      List<ShreddedModel.ShreddedField> fields,
      ShreddingContext.Scope scope,
      RowId expectedRow,
      String what) {
    Object[] stored = readStoredShreddedColumns(session, id, fields, singleIdColumn(persister));
    if (stored == null) {
      return;
    }
    for (int i = 0; i < fields.size(); i++) {
      byte[] column = (byte[]) stored[i];
      if (column == null) {
        continue;
      }
      var header = EncryptedValue.decode(column);
      // S-2: this field's own tenant, not the row's primary one.
      if (!header.subject().equals(scope.subject())
          || !header.tenant().equals(scope.tenantFor(fields.get(i).fieldName()))
          || !header.rowId().equals(expectedRow)) {
        throw new ShreddingException(
            ErrorCodes.SUBJECT_IMMUTABLE,
            "the "
                + what
                + " "
                + fields.get(i).entityName()
                + " row's stored "
                + fields.get(i).fieldName()
                + " is not bound to the subject and row it was written for. A write scope is"
                + " consumable only by the bind it was pushed for; this row is refused before"
                + " commit rather than left in another subject's erasure scope.");
      }
    }
  }

  /**
   * Cipher item 14: the placeholder check, run on the state array in the {@code Pre*} listeners,
   * before {@code writeBlindIndexes}. The converter refuses one too, but only once Hibernate has
   * decided to bind that column; catching it here names the entity, keeps the marker out of a blind
   * index, and covers a mapping whose column is written without the converter running.
   */
  private static void refusePlaceholdersInState(
      EntityPersister persister, Object[] state, List<ShreddedModel.ShreddedField> fields) {
    String[] names = persister.getPropertyNames();
    for (var field : fields) {
      int index = indexOf(names, field.fieldName());
      if (index >= 0 && Placeholders.isPlaceholder(state[index])) {
        throw new ShreddingException(
            ErrorCodes.PLACEHOLDER,
            "refusing to write "
                + field.entityName()
                + "."
                + field.fieldName()
                + ": it holds the marker a @Shredded read returns before the verified value is"
                + " installed. Persisting it would destroy the stored ciphertext. The instance was"
                + " flushed without a verified load - a refused load that was caught and the"
                + " transaction continued, or an instance carried outside the read region it was"
                + " loaded in.");
      }
    }
  }

  private static String singleIdColumn(EntityPersister persister) {
    String[] idColumns = persister.getIdentifierColumnNames();
    if (idColumns.length != 1) {
      // ShreddedModel refuses a composite-id shredded entity at startup, so this is unreachable
      // for a mapped entity; it stays as a typed refusal rather than an array index.
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "a @Shredded entity has "
              + idColumns.length
              + " identifier columns; this module binds a stored value to a single-column"
              + " identifier and refuses the mapping at startup.");
    }
    return idColumns[0];
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
      org.hibernate.engine.spi.SharedSessionContractImplementor session,
      EntityPersister persister,
      Object id,
      List<ShreddedModel.ShreddedField> fields,
      ShreddingContext.Scope scope) {
    var first = fields.get(0);
    Object[] stored = readStoredShreddedColumns(session, id, fields, singleIdColumn(persister));
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
      // S-2: this field's own tenant, not the row's primary one.
      boolean tenantMoved = !header.tenant().equals(scope.tenantFor(fields.get(i).fieldName()));
      boolean rowMoved = !header.rowId().equals(scope.rowId());
      if (subjectMoved || tenantMoved || rowMoved) {
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

  /**
   * A fresh {@code SELECT} of one row's own shredded columns, by id, decoded only for the header -
   * no key material is touched. Shared by {@link #refuseIfSubjectMoved} (the write path, QUESTIONS
   * #4 ruling (c)) and {@link #onPostLoad} (the read path, C-26): both need to know what a row's
   * shredded columns currently, actually hold, independent of whatever a converter running on a
   * different row of the same query happened to record.
   *
   * @return one entry per {@code fields}, in the same order, {@code null} for a column with no
   *     stored value; or {@code null} for the whole array if the row no longer exists
   */
  private static Object[] readStoredShreddedColumns(
      org.hibernate.engine.spi.SharedSessionContractImplementor session,
      Object id,
      List<ShreddedModel.ShreddedField> fields,
      String idColumn) {
    String columns =
        fields.stream()
            .map(f -> quote(f.columnName()))
            .collect(java.util.stream.Collectors.joining(", "));
    String sql =
        "SELECT "
            + columns
            + " FROM "
            + quote(fields.get(0).tableName())
            + " WHERE "
            + quote(idColumn)
            + " = ?";
    return session.doReturningWork(
        connection -> {
          try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setObject(1, id);
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
  }

  private static String quote(String identifier) {
    return "\"" + identifier.replace("\"", "\"\"") + "\"";
  }

  /**
   * S-2: every field's own declared tenant, evaluated here - the one place that has both the tenant
   * expression and the entity instance to evaluate it against. A field with no tenant expression
   * falls back to the ambient tenant, exactly as before. {@code tenant} (the scope's primary) is
   * the first field's resolved tenant, kept for every use that names the row rather than one of its
   * fields (the {@code IDENTITY} rebind's WHERE clause, principally); every per-field use goes
   * through {@link ShreddingContext.Scope#tenantFor(String)}.
   */
  private ShreddingContext.Scope scopeFor(
      Object entity, List<ShreddedModel.ShreddedField> fields, RowId rowId) {
    var first = fields.get(0);
    var fieldTenants = new java.util.LinkedHashMap<String, TenantId>();
    for (var field : fields) {
      TenantId fieldTenant =
          field.tenant() != null ? TenantId.of(field.tenant().evaluate(entity)) : requireTenant();
      fieldTenants.put(field.fieldName(), fieldTenant);
    }
    TenantId tenant = fieldTenants.get(first.fieldName());
    return new ShreddingContext.Scope(
        tenant,
        SubjectId.of(resolveSubject(entity, fields)),
        first.entityName(),
        rowId,
        fieldTenants);
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

  private void writeBlindIndexes(
      EntityPersister persister, Object[] state, ShreddingContext.Scope scope) {
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
      TenantId rowTenant = rowTenant(index, names, state);
      TenantId fieldTenant = scope.tenantFor(index.ofFieldName());
      if (!fieldTenant.value().equals(rowTenant.value())) {
        throw new ShreddingException(
            ErrorCodes.UNVERIFIED_WRITE,
            "@BlindIndex on "
                + index.entityName()
                + "."
                + index.fieldName()
                + " indexes "
                + index.entityName()
                + "."
                + index.ofFieldName()
                + ", whose data key is derived under tenant \""
                + fieldTenant.value()
                + "\", while this row's tenant column \""
                + index.column().tenantColumn()
                + "\" holds \""
                + rowTenant.value()
                + "\". One erasure request names one tenant and one subject, so it can only reach"
                + " the key, the ciphertext and the index when all three are under the same tenant."
                + " Declare the @Shredded tenant as the one the tenant column holds, or write the"
                + " tenant column with the tenant the value belongs to. The write is refused.");
      }
      Object value = state[sourceIndex];
      // Design addendum 3, option (a) (applied §3.1): derived under the row's own tenantColumn
      // value - the one value the erasure's WHERE can match - read out of the same state array
      // this write is about to persist. Change 4 has just refused the write if that is not also
      // the tenant the of-field's data key was derived under, so the key, the ciphertext and the
      // index are one erasure's worth of work by construction.
      state[targetIndex] =
          value == null
              ? null
              : blindIndex.compute(
                  rowTenant, index.entityName(), index.ofFieldName(), normalise(value));
    }
  }

  /**
   * Design addendum 3, changes 3 and 4 (applied §3.3, §3.4). The tenant this row's index is derived
   * under, read out of the state array by the property {@code tenantColumn} was resolved to at
   * startup, and refused unless it is usable and unless it agrees with the tenant the of-field's
   * data key is derived under.
   *
   * <p>Change 4 is the one that closes S-13. Deriving under {@code state[tenantColumn]} alone only
   * moves the gap: the ciphertext would still be encrypted under {@code Scope.tenantFor(of-field)},
   * so an erasure for that tenant would destroy the key and match no row, and an erasure for the
   * column's tenant would clear the index and destroy a key the ciphertext was never under. For a
   * row to be erasable by one request, the tenant its data key was derived under, the tenant its
   * index was derived under and the value in its tenant column have to be one value. When they are
   * not, the write is refused here, naming both - a shape no keying this module could choose would
   * make erasable is refused at the boundary rather than written and reported as erased later.
   */
  private static TenantId rowTenant(
      ShreddedModel.BlindIndexField index, String[] names, Object[] state) {
    String where = index.entityName() + "." + index.fieldName();
    String property =
        index
            .column()
            .tenantProperty()
            .orElseThrow(
                () ->
                    new ShreddingException(
                        ErrorCodes.CONFIG,
                        "@BlindIndex on "
                            + where
                            + " has no property resolved for tenantColumn=\""
                            + index.column().tenantColumn()
                            + "\". The resolution happens at startup from the Hibernate metamodel;"
                            + " a ShreddedModel built without an EntityManagerFactory cannot write"
                            + " blind indexes, because it cannot read the tenant the erasure will"
                            + " match on out of the row."));
    int tenantIndex = indexOf(names, property);
    Object raw = tenantIndex < 0 ? null : state[tenantIndex];
    if (!(raw instanceof String tenantValue) || tenantValue.isBlank()) {
      throw new ShreddingException(
          ErrorCodes.UNVERIFIED_WRITE,
          "@BlindIndex on "
              + where
              + " derives its index under the value of "
              + index.entityName()
              + "."
              + property
              + " (column \""
              + index.column().tenantColumn()
              + "\"), which this write leaves "
              + (raw == null
                  ? "null"
                  : raw.getClass().getName() + (raw instanceof String ? " and blank" : ""))
              + ". An index no WHERE "
              + index.column().tenantColumn()
              + " = ? can match is an index no erasure can destroy, so the write is refused rather"
              + " than performed.");
    }
    return TenantId.of(tenantValue);
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
