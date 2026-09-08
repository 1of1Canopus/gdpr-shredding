package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Who the row being written belongs to, for the few microseconds in which Hibernate binds it.
 *
 * <p>A Hibernate {@code AttributeConverter} is handed nothing but the value: no entity, no session,
 * no attribute name. The write path therefore brackets the binding: the module's {@code
 * PreInsertEventListener} and {@code PreUpdateEventListener} push the resolved tenant and subject
 * immediately before {@code EntityInsertAction} / {@code EntityUpdateAction} bind the state array,
 * and the matching {@code PostInsert} / {@code PostUpdate} listeners pop.
 *
 * <p>The read path needs none of this: tenant and subject travel inside the stored blob.
 *
 * <p>Missing context is a typed error, never a default. A converter reached from a bulk JPQL
 * update, a criteria parameter or a detached use has no idea whose key to encrypt under, and
 * guessing would put a row under the wrong subject's erasure scope.
 */
public final class ShreddingContext {

  /** Tenant and subject of the entity instance currently being bound. */
  public record Scope(TenantId tenant, SubjectId subject, String entityName) {
    public Scope {
      Objects.requireNonNull(tenant, "tenant");
      Objects.requireNonNull(subject, "subject");
      Objects.requireNonNull(entityName, "entityName");
    }
  }

  private static final ThreadLocal<Deque<Scope>> SCOPES = ThreadLocal.withInitial(ArrayDeque::new);

  private ShreddingContext() {}

  public static void push(Scope scope) {
    SCOPES.get().push(scope);
  }

  /**
   * Drops the whole stack for this thread, whatever its depth. CIPHER-08's backstop: a write that
   * never reaches its {@code Post} listener - a converter refusal, a constraint, an exception from
   * {@code writeBlindIndexes} - would otherwise leave a scope on a pooled thread for the next,
   * unrelated write to inherit. The bracket around each push (try/finally) is the first line of
   * defence; this is the second, run at the transaction boundary regardless of how the write ended,
   * because {@code Post} listeners by construction do not run on the failure path.
   */
  public static void clearAll() {
    SCOPES.remove();
  }

  public static void pop() {
    Deque<Scope> stack = SCOPES.get();
    if (!stack.isEmpty()) {
      stack.pop();
    }
    if (stack.isEmpty()) {
      SCOPES.remove();
    }
  }

  public static Optional<Scope> current() {
    Deque<Scope> stack = SCOPES.get();
    return stack.isEmpty() ? Optional.empty() : Optional.of(stack.peek());
  }

  public static Scope require(String entity, String field) {
    return current()
        .orElseThrow(
            () ->
                new ShreddingException(
                    ErrorCodes.NO_CONTEXT,
                    "no shredding context while writing "
                        + entity
                        + "."
                        + field
                        + ". A @Shredded field can only be written through a managed entity, so"
                        + " that its data subject is known. Bulk JPQL updates, criteria parameters"
                        + " and detached writes to a shredded column are refused rather than"
                        + " encrypted under a guessed subject."));
  }

  /** Runs {@code body} with a scope pushed; for tests and for the erasure endpoint. */
  public static <T> T with(Scope scope, java.util.function.Supplier<T> body) {
    push(scope);
    try {
      return body.get();
    } finally {
      pop();
    }
  }

  /**
   * What a shredded column's stored header actually named, for the row currently being hydrated
   * (CIPHER-01).
   *
   * <p>{@code AttributeConverter.convertToEntityAttribute} is handed nothing but the column bytes:
   * no entity, no session, no row. By the time any Hibernate listener fires for a load, every
   * converter on that row has already run - confirmed against the Hibernate ORM 7.4 loader bytecode
   * this module builds against, not assumed - so there is no hook that fires <em>before</em> a
   * shredded field is decrypted on read, the way {@code PreInsertEvent}/{@code PreUpdateEvent} fire
   * before a write. The read-side check is therefore necessarily two-phase: {@code
   * ShreddedConverter} records what the header actually said the instant it decodes it, and {@code
   * ShreddingEventListener.onPostLoad} - which runs synchronously as part of the load, before the
   * entity is handed to any caller - resolves the row's true subject and tenant from the
   * now-fully-hydrated entity and compares. A mismatch throws from {@code onPostLoad}, which aborts
   * the load: the value is decrypted internally for a few instructions, but it is never returned to
   * a caller. See QUESTIONS.md CIPHER-01 for why this is not "checked before the key store is
   * touched" the way the write path is.
   */
  public record Decoded(TenantId tenant, SubjectId subject) {}

  private static final ThreadLocal<Map<String, Decoded>> DECODED_READS =
      ThreadLocal.withInitial(HashMap::new);

  /**
   * @param key qualified as {@code entityName + "." + fieldName}, so two entity types that happen
   *     to share a field name cannot collide
   */
  public static void recordDecoded(String key, TenantId tenant, SubjectId subject) {
    DECODED_READS.get().put(key, new Decoded(tenant, subject));
  }

  /**
   * Removes and returns what was recorded for {@code key}, if anything. Removing on read means a
   * value from a previous row's hydration can never be mistaken for the current row's: a field that
   * was {@code null} for this row, and so was never decoded, correctly has nothing to check.
   */
  public static Optional<Decoded> takeDecoded(String key) {
    Map<String, Decoded> map = DECODED_READS.get();
    Decoded value = map.remove(key);
    if (map.isEmpty()) {
      DECODED_READS.remove();
    }
    return Optional.ofNullable(value);
  }
}
