package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.domain.BlindIndex;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.Normalisation;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingContext;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

  /** Bounded: this is a cache of "what subject did this row load under", not a session. */
  private static final int MAX_REMEMBERED = 10_000;

  private final ShreddedModel model;
  private final TenantSupplier tenantSupplier;
  private final transient BlindIndex blindIndex;

  private final transient ThreadLocal<Map<String, String>> loadedSubjects =
      ThreadLocal.withInitial(
          () ->
              new LinkedHashMap<>(16, 0.75f, true) {
                private static final long serialVersionUID = 1L;

                @Override
                protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                  return size() > MAX_REMEMBERED;
                }
              });

  /** Where the ambient tenant comes from when {@code @Shredded(tenant=...)} is not given. */
  @FunctionalInterface
  public interface TenantSupplier {
    TenantId currentTenant();
  }

  public ShreddingEventListener(
      ShreddedModel model, TenantSupplier tenantSupplier, BlindIndex blindIndex) {
    this.model = Objects.requireNonNull(model, "model");
    this.tenantSupplier = Objects.requireNonNull(tenantSupplier, "tenantSupplier");
    this.blindIndex = blindIndex;
  }

  @Override
  public boolean onPreInsert(PreInsertEvent event) {
    var fields = model.byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return false;
    }
    var scope = scopeFor(event.getEntity(), fields);
    ShreddingContext.push(scope);
    remember(event.getPersister(), event.getId(), scope.subject().value());
    writeBlindIndexes(event.getPersister(), event.getState(), scope.tenant());
    return false;
  }

  @Override
  public void onPostInsert(PostInsertEvent event) {
    if (model.byEntityName().containsKey(entityName(event.getPersister()))) {
      ShreddingContext.pop();
    }
  }

  @Override
  public boolean onPreUpdate(PreUpdateEvent event) {
    var fields = model.byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return false;
    }
    var scope = scopeFor(event.getEntity(), fields);
    String remembered = loadedSubjects.get().get(rowKey(event.getPersister(), event.getId()));
    if (remembered != null && !remembered.equals(scope.subject().value())) {
      // Control 14: silently re-encrypting under another subject's key would move the row out of
      // the first subject's erasure scope, so their erasure would leave this row readable.
      throw new ShreddingException(
          ErrorCodes.SUBJECT_IMMUTABLE,
          "the data subject of a persisted "
              + entityName(event.getPersister())
              + " row cannot change. It was captured at first persist; changing it would"
              + " re-encrypt the row under another subject's key and move it out of the first"
              + " subject's erasure scope.");
    }
    ShreddingContext.push(scope);
    writeBlindIndexes(event.getPersister(), event.getState(), scope.tenant());
    return false;
  }

  @Override
  public void onPostUpdate(PostUpdateEvent event) {
    if (model.byEntityName().containsKey(entityName(event.getPersister()))) {
      ShreddingContext.pop();
    }
  }

  @Override
  public void onPostLoad(PostLoadEvent event) {
    var fields = model.byEntityName().get(entityName(event.getPersister()));
    if (fields == null) {
      return;
    }
    try {
      remember(event.getPersister(), event.getId(), resolveSubject(event.getEntity(), fields));
    } catch (RuntimeException ignored) {
      // A row whose subject expression cannot be evaluated on load is not a reason to fail the
      // read; the update path will refuse it with a clear message if it is ever written.
    }
  }

  @Override
  public boolean requiresPostCommitHandling(EntityPersister persister) {
    return false;
  }

  private void remember(EntityPersister persister, Object id, String subject) {
    if (id != null) {
      loadedSubjects.get().put(rowKey(persister, id), subject);
    }
  }

  private static String rowKey(EntityPersister persister, Object id) {
    return persister.getEntityName() + "#" + id;
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
    var indexes = model.blindIndexesByEntityName().get(entityName(persister));
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
