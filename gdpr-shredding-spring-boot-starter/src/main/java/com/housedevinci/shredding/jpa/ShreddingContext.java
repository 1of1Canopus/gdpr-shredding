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
    READ_FRAMES.remove();
    READ_SCOPES.remove();
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
   * CIPHER-11 / C-17..C-22 (third pass): a bracket that owes a debt, not a permission granted by
   * the caller's identity.
   *
   * <p>Hibernate hands a shredded field's {@code AttributeConverter} nothing but the column bytes,
   * and - confirmed against the Hibernate ORM 7.4 loader bytecode this module builds against, the
   * same evidence behind {@link Decoded} below - every converter on a row has already run before
   * the first {@code PreLoadEventListener}/{@code PostLoadEventListener} callback fires for that
   * row. There is therefore no Hibernate hook that can gate an individual row's own decrypt before
   * it happens, for an entity load any more than for a projection; the only usable difference
   * between the two is that an entity load can be bracketed from <em>outside</em> Hibernate, at the
   * point the application asks for one. {@link
   * com.housedevinci.shredding.autoconfigure.ShreddingReadBracketCustomizer} does exactly that for
   * every Spring Data JPA repository call; {@link #withReadBracket} does it for a caller-supplied
   * {@code EntityManager} entity operation.
   *
   * <p>Third pass, CIPHER-11's fix text corrected by Cipher's own re-verification: the first
   * version of this bracket was a flat depth counter, and {@link #recordDecoded} wrote into a flat
   * map keyed only by {@code entity.field}. That is a permission ("you are inside something that
   * will <em>probably</em> get verified"), not a proof, and it let a repository {@code @Query}
   * projection, a Spring Data interface projection and a second, uninstrumented {@code
   * EntityManagerFactory} all decrypt with nothing ever draining the record (C-17, C-18, C-20) -
   * and let one row's undrained record be mistaken for a later, unrelated row's (C-22).
   *
   * <p>The fix: every {@link #pushReadBracket()} opens a {@code Frame}. {@link #recordDecoded}
   * files into the frame currently on top of this thread's stack, not into a shared map. A verifier
   * drains an entry out of that same frame - {@code ShreddingEventListener.onPostLoad} for the row
   * it just verified, or an explicit {@link #withRead} scope for a projection that cannot go
   * through a managed load at all. {@link #popReadBracket()} closes the frame and, if anything in
   * it was never drained, throws {@link
   * com.housedevinci.shredding.domain.ErrorCodes#READ_UNVERIFIED} - after the value was computed,
   * but strictly before the repository method that opened the bracket hands its result back to the
   * caller (the proxy that opens the bracket must let this exception replace a normal return, not
   * merely log past it). A decrypt reached with the bracket closed and no explicit read scope still
   * has nothing to verify against at all and is still refused outright ({@link
   * com.housedevinci.shredding.domain.ErrorCodes#READ_UNSCOPED}): that is CIPHER-11's original
   * projection, tuple and constructor-expression case, none of which any Hibernate load listener
   * ever sees.
   */
  /**
   * C-26: what a decode is filed under. Not {@code entity.field} alone - Hibernate ORM 7.4 defers
   * every row's {@code PostLoad} callback until the whole {@code JdbcValues} result set has been
   * hydrated, so two rows of the same entity in one query write their converters' decodes in
   * sequence, and a flat {@code entity.field} key lets the second overwrite the first: one row's
   * verification then stood in for both (the leak), or a legitimate second subject's row drained an
   * entry that was never its own header (the false refusal). {@code tenant} and {@code subject} are
   * what the header itself said at decode time - the converter has no row identity to key by (no
   * session, no entity - {@link ShreddedConverter} is handed nothing but the column bytes), but the
   * header carries tenant and subject already, so those are what the key uses instead of a row id
   * this class cannot obtain.
   *
   * <p>The verifier ({@code ShreddingEventListener.onPostLoad}) does not trust this key for
   * correctness - it independently re-reads each row's own stored bytes by id, the way {@code
   * refuseIfSubjectMoved} already does on the write path, and compares against the row's true
   * subject and tenant. This key exists only so the frame can still answer "was every decode
   * eventually looked at by somebody" (C-17/C-18/C-20): the verifier drains the exact entry its own
   * fresh, per-row header re-read names, never a different row's.
   */
  public record FrameKey(String entity, String field, TenantId tenant, SubjectId subject) {
    public FrameKey {
      Objects.requireNonNull(entity, "entity");
      Objects.requireNonNull(field, "field");
      Objects.requireNonNull(tenant, "tenant");
      Objects.requireNonNull(subject, "subject");
    }
  }

  /**
   * A multiset, not a map: one person can legitimately own several rows of the same entity in one
   * result set, and each row's converter records its own decode under the identical {@link
   * FrameKey} (same entity, same field, same tenant, same subject) as every other row of that same
   * subject. A {@code Map.put} would let the second overwrite the first exactly the way the old
   * flat key did; a count drained once per verified row is what lets N legitimate rows of one
   * subject both record N times and drain N times without ever mistaking "nothing left to drain"
   * for "nothing was ever decoded".
   */
  private static final class Frame {
    private final Map<FrameKey, Integer> pending = new HashMap<>();

    private int total() {
      return pending.values().stream().mapToInt(Integer::intValue).sum();
    }
  }

  private static final ThreadLocal<Deque<Frame>> READ_FRAMES =
      ThreadLocal.withInitial(ArrayDeque::new);

  /** Reentrant: a repository call can trigger a lazy load of another shredded entity. */
  public static void pushReadBracket() {
    READ_FRAMES.get().push(new Frame());
  }

  /**
   * Closes the innermost frame. If it still holds a decode nothing ever drained, the debt is
   * unpaid: throws {@link com.housedevinci.shredding.domain.ErrorCodes#READ_UNVERIFIED} naming the
   * field (never the plaintext), after the frame is already gone so a retry starts clean. Callers
   * that must not let this exception obscure one already in flight - the bracket unwinding on the
   * proxy's exceptional path - should call {@link #discardReadBracket()} instead.
   */
  public static void popReadBracket() {
    Frame frame = popFrame();
    if (frame != null && !frame.pending.isEmpty()) {
      // Never the tenant or subject value in the message (PII): only entity.field, the same shape
      // the pre-C-26 message used.
      FrameKey first = frame.pending.keySet().iterator().next();
      throw new ShreddingException(
          ErrorCodes.READ_UNVERIFIED,
          "a read bracket closed with "
              + frame.total()
              + " decoded @Shredded value(s) that no verifier ever drained, the first being "
              + first.entity()
              + "."
              + first.field()
              + ". Every decrypt inside ShreddingContext.pushReadBracket()/withReadBracket(...) must"
              + " be reached either by a managed entity load - which ShreddingEventListener"
              + ".onPostLoad verifies once the row is fully hydrated - or by an explicit"
              + " ShreddingContext.withRead(...) scope. A repository @Query projection, a Spring"
              + " Data interface projection, a bare EntityManager read against an uninstrumented"
              + " EntityManagerFactory, or any other decrypt that reaches a shredded converter"
              + " while the bracket is open but is never handed to a verifier, is refused rather"
              + " than returned.");
    }
  }

  /**
   * Closes the innermost frame without checking it, discarding whatever it holds. For the
   * exceptional path only: the bracket must still unwind so a pooled thread does not carry a stale
   * frame into the next, unrelated call, but a frame left non-empty because the body threw before
   * reaching its verifier is not the failure worth reporting - the original exception is.
   */
  public static void discardReadBracket() {
    popFrame();
  }

  private static Frame popFrame() {
    Deque<Frame> stack = READ_FRAMES.get();
    Frame frame = stack.isEmpty() ? null : stack.pop();
    if (stack.isEmpty()) {
      READ_FRAMES.remove();
    }
    return frame;
  }

  public static boolean inReadBracket() {
    return !READ_FRAMES.get().isEmpty();
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
   *
   * <p>Documented in {@code README.md} and {@code docs/index.md} (C-23): this is the contract for
   * every {@code EntityManager} entity read, not only an error code a user meets after the fact.
   */
  /**
   * C-32: the frame must unwind on any {@link Throwable}, not only a {@link RuntimeException}. An
   * {@code Error} - a {@code StackOverflowError} from a deep object graph, an {@code
   * AssertionError} from application code reached inside {@code body} - used to unwind past both
   * {@link #discardReadBracket()} and {@link #popReadBracket()}, leaving the frame on the thread
   * for whatever the pool handed it next. {@link
   * com.housedevinci.shredding.autoconfigure.ShreddingReadBracketCustomizer.Bracket#invoke} already
   * caught {@code Throwable}; this is the one caller of {@link #pushReadBracket()} that did not.
   * {@code try}/{@code finally} with an explicit "did the frame already close?" flag, rather than a
   * second {@code catch}, so the frame closes exactly once on every path: normal return, a checked
   * exception smuggled out as unchecked by {@code body}, a {@code RuntimeException}, and an {@code
   * Error} all reach the same {@code finally}.
   */
  public static <T> T withReadBracket(java.util.function.Supplier<T> body) {
    pushReadBracket();
    boolean threw = true;
    try {
      T result = body.get();
      threw = false;
      return result;
    } finally {
      if (threw) {
        discardReadBracket();
      } else {
        popReadBracket();
      }
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
   * Records a decode into the frame currently on top of this thread's read-bracket stack
   * (C-17/C-22/C-26): a decode with no open bracket - an explicit {@link #withRead} scope with
   * nothing bracketing it - has already been verified atomically by the caller-supplied scope and
   * has no frame to owe a debt to, so it is not recorded anywhere and there is nothing left to
   * drain.
   *
   * <p>C-26: keyed by {@link FrameKey} - entity, field, and the tenant/subject the header itself
   * named at decode time, not a row id ({@code ShreddedConverter} has none to give). Incrementing a
   * count, not overwriting a map entry, is what lets a second row of the same entity - one
   * legitimately sharing the first row's (entity, tenant, subject, field), or one whose ciphertext
   * was moved from the first and so happens to share its header - record its own entry without
   * erasing the first row's.
   */
  public static void recordDecoded(
      String entity, String field, TenantId tenant, SubjectId subject) {
    Deque<Frame> stack = READ_FRAMES.get();
    if (stack.isEmpty()) {
      return;
    }
    var key = new FrameKey(entity, field, tenant, subject);
    stack.peek().pending.merge(key, 1, Integer::sum);
  }

  /**
   * Drains one count for {@code key} from the frame currently on top of this thread's read-bracket
   * stack, if any is left. C-26: the caller - {@code ShreddingEventListener.onPostLoad} - builds
   * {@code key} from the header it just independently re-read from the row's own stored bytes by
   * id, not from anything this class handed back; draining the exact key a fresh, per-row read
   * names is what stops one row's decode from paying another row's debt (C-22's original defect,
   * one level down from where the third pass fixed it).
   *
   * @return {@code true} if a count was present and one was drained; {@code false} if the frame had
   *     nothing recorded under this exact key (no open bracket, or a decode this verifier's own
   *     re-read did not expect to find, both of which leave the count where it stood)
   */
  public static boolean drainDecoded(
      String entity, String field, TenantId tenant, SubjectId subject) {
    Deque<Frame> stack = READ_FRAMES.get();
    if (stack.isEmpty()) {
      return false;
    }
    var key = new FrameKey(entity, field, tenant, subject);
    Frame frame = stack.peek();
    Integer count = frame.pending.get(key);
    if (count == null) {
      return false;
    }
    if (count <= 1) {
      frame.pending.remove(key);
    } else {
      frame.pending.put(key, count - 1);
    }
    return true;
  }
}
