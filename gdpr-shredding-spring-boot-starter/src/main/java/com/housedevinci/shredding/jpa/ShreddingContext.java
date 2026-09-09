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
   *
   * <p>CIPHER-13: the same backstop covers the read side now - the read bracket, the explicit read
   * scope stack and {@code DECODED_READS} all belong to a single request/transaction and none of
   * them may outlive it, whether or not the transaction that opened them ever completes cleanly.
   */
  public static void clearAll() {
    SCOPES.remove();
    READ_BRACKET_DEPTH.remove();
    READ_SCOPES.remove();
    DECODED_READS.remove();
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
   * CIPHER-11: whether a decrypt reached from within a managed entity load is currently in
   * progress, on this thread.
   *
   * <p>Hibernate hands a shredded field's {@code AttributeConverter} nothing but the column bytes,
   * and - confirmed against the Hibernate ORM 7.4 loader bytecode this module builds against, the
   * same evidence behind {@link Decoded} below - every converter on a row has already run before
   * the first {@code PreLoadEventListener}/{@code PostLoadEventListener} callback fires for that
   * row. There is therefore no Hibernate hook that can gate an individual row's own decrypt before
   * it happens, for an entity load any more than for a projection; the only usable difference
   * between the two is that an entity load can be bracketed from <em>outside</em> Hibernate, at the
   * point the application asks for one. {@code ShreddingReadBracketRepositoryFactoryCustomizer}
   * does exactly that for every Spring Data JPA repository call; {@link #withRead} does it for a
   * caller-supplied {@link Scope} around a bare {@code EntityManager} use.
   *
   * <p>A decrypt reached with the bracket open and no explicit read scope defers verification to
   * the existing, now-fixed {@code onPostLoad}/{@code refuseIfSubjectMoved} pair (CIPHER-12,
   * CIPHER-14) once the row is fully hydrated - the same "decrypt now, refuse before return"
   * relaxation Cipher accepted for entity loads under QUESTIONS #13. A decrypt reached with the
   * bracket closed and no explicit read scope has nothing to verify against at all and is refused
   * outright ({@link com.housedevinci.shredding.domain.ErrorCodes#READ_UNSCOPED}): that is
   * precisely CIPHER-11's projection, tuple and constructor-expression case, none of which any
   * Hibernate load listener ever sees.
   */
  private static final ThreadLocal<Integer> READ_BRACKET_DEPTH = ThreadLocal.withInitial(() -> 0);

  /** Reentrant: a repository call can trigger a lazy load of another shredded entity. */
  public static void pushReadBracket() {
    READ_BRACKET_DEPTH.set(READ_BRACKET_DEPTH.get() + 1);
  }

  public static void popReadBracket() {
    int depth = READ_BRACKET_DEPTH.get() - 1;
    if (depth <= 0) {
      READ_BRACKET_DEPTH.remove();
    } else {
      READ_BRACKET_DEPTH.set(depth);
    }
  }

  public static boolean inReadBracket() {
    return READ_BRACKET_DEPTH.get() > 0;
  }

  /**
   * Runs {@code body} with the read bracket open, for a raw {@code EntityManager} call that is
   * itself a managed-entity operation - {@code find}, {@code merge}, {@code refresh}, an
   * entity-returning JPQL/Criteria query - and so deserves the same relaxation a Spring Data
   * repository call gets automatically. {@code EntityManager.merge} in particular re-loads the
   * row's current persisted state internally to reconcile it against the detached instance, which
   * reaches a shredded converter exactly like any other load. Do not reach for this around a
   * scalar, {@code Tuple} or constructor-expression projection - that is exactly the case CIPHER-11
   * refuses, and this would silently defeat it; use {@link #withRead} instead, which verifies.
   */
  public static <T> T withReadBracket(java.util.function.Supplier<T> body) {
    pushReadBracket();
    try {
      return body.get();
    } finally {
      popReadBracket();
    }
  }

  /**
   * The subject and tenant a caller vouches for, for the row a decrypt about to happen is reading.
   * Distinct from the write {@link #push}/{@link #current} stack: a read never needs a scope to
   * find the key (the header is self-describing), only to be verified against, and the two must
   * never be confused with each other.
   */
  private static final ThreadLocal<Deque<Scope>> READ_SCOPES =
      ThreadLocal.withInitial(ArrayDeque::new);

  public static void pushReadScope(Scope scope) {
    READ_SCOPES.get().push(scope);
  }

  public static void popReadScope() {
    Deque<Scope> stack = READ_SCOPES.get();
    if (!stack.isEmpty()) {
      stack.pop();
    }
    if (stack.isEmpty()) {
      READ_SCOPES.remove();
    }
  }

  public static Optional<Scope> currentReadScope() {
    Deque<Scope> stack = READ_SCOPES.get();
    return stack.isEmpty() ? Optional.empty() : Optional.of(stack.peek());
  }

  /**
   * Runs {@code body} vouching that every {@code @Shredded} field it reads belongs to {@code
   * scope}. Every converter reached inside verifies its header against this atomically, at decrypt
   * time, and refuses on a mismatch before returning the value to anyone - this is how a bare
   * projection, a {@code Tuple} query or a constructor-expression DTO opts in to CIPHER-11's check
   * when it cannot go through a managed entity load at all.
   */
  public static <T> T withRead(Scope scope, java.util.function.Supplier<T> body) {
    pushReadScope(scope);
    try {
      return body.get();
    } finally {
      popReadScope();
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
