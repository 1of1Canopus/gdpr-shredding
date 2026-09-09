package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The two pieces of per-thread state the module keeps, and the rule that governs both.
 *
 * <blockquote>
 * <strong>Ambient state may accuse. It may never authorise.</strong>
 * </blockquote>
 *
 * <p>A Hibernate {@code AttributeConverter} is handed nothing but the value: no entity, no session,
 * no attribute name, and no Hibernate hook fires before it (QUESTIONS #13/#16). Anything it
 * consults has to be thread-local, and five review passes showed that any design in which the
 * converter reads thread-local state and <em>therefore returns plaintext</em> fails the moment that
 * state outlives its owner. So the converter no longer returns plaintext at all (design §1): it
 * files what it decrypted into the open read region and returns a {@link Placeholders placeholder},
 * and {@code ShreddingEventListener.onPostLoad} - the one hook that knows the row - verifies and
 * installs.
 *
 * <table>
 *   <caption>Ownership</caption>
 *   <tr><th>state</th><th>created by</th><th>destroyed by</th><th>never cleared by</th></tr>
 *   <tr>
 *     <td>write scope</td>
 *     <td>{@code onPreInsert}/{@code onPreUpdate}, tagged with the session and a fresh token</td>
 *     <td>the matching {@code Post*} by token, else that session's own after-completion callback</td>
 *     <td>another session; any read path</td>
 *   </tr>
 *   <tr>
 *     <td>read region</td>
 *     <td>the repository proxy, or {@link #withReadBracket}</td>
 *     <td>the same call, by owner token</td>
 *     <td>a transaction completion (C-33); another region</td>
 *   </tr>
 * </table>
 *
 * <p>{@code clearAll()} is gone: it dropped read regions belonging to still-open brackets whenever
 * any transaction that wrote a shredded entity completed on the thread, which is C-33. The
 * transaction callback is now {@link #clearWriteScopesOwnedBy(Object)} and may not touch a region.
 */
public final class ShreddingContext {

  private static final Logger log = LoggerFactory.getLogger(ShreddingContext.class);

  private static final AtomicLong TOKENS = new AtomicLong();

  /**
   * Who the row being written belongs to, and which row it is, for the few microseconds in which
   * Hibernate binds it.
   */
  public record Scope(TenantId tenant, SubjectId subject, String entityName, RowId rowId) {
    public Scope {
      Objects.requireNonNull(tenant, "tenant");
      Objects.requireNonNull(subject, "subject");
      Objects.requireNonNull(entityName, "entityName");
      Objects.requireNonNull(rowId, "rowId");
    }
  }

  private ShreddingContext() {}

  // ---------------------------------------------------------------- write scopes

  private record WriteEntry(Scope scope, Object session, long token) {}

  private static final ThreadLocal<Deque<WriteEntry>> WRITE_SCOPES =
      ThreadLocal.withInitial(ArrayDeque::new);

  /**
   * Pushes the scope a single bind will be performed under and returns the token that pops it
   * again.
   *
   * <p>C-41 / Cipher item 14: a write scope may not nest. Hibernate executes the action queue
   * serially and a shredded converter never triggers another entity's bind, so a scope still live
   * when a {@code Pre*} listener pushes is by construction residue from a bind whose {@code Post*}
   * listener never ran - a converter refusal, a constraint violation, a throw out of {@code
   * writeBlindIndexes}. Residue is dropped here, loudly, so it can never be consumed by the bind
   * that follows it.
   *
   * @param session the Hibernate session that owns this write, so a transaction completing on this
   *     thread clears only its own scopes
   */
  public static long pushWrite(Scope scope, Object session) {
    Objects.requireNonNull(scope, "scope");
    Deque<WriteEntry> stack = WRITE_SCOPES.get();
    if (!stack.isEmpty()) {
      log.warn(
          "shredding: dropping {} stale write scope(s) before binding {}; a previous write's Post"
              + " listener did not run",
          stack.size(),
          scope.entityName());
      stack.clear();
    }
    long token = TOKENS.incrementAndGet();
    stack.push(new WriteEntry(scope, session, token));
    return token;
  }

  /** Pops the scope {@code token} named, and nothing else. A token already gone is not an error. */
  public static void popWrite(long token) {
    Deque<WriteEntry> stack = WRITE_SCOPES.get();
    stack.removeIf(entry -> entry.token() == token);
    if (stack.isEmpty()) {
      WRITE_SCOPES.remove();
    }
  }

  /**
   * C-33: the transaction-boundary backstop, narrowed to the scopes this session pushed. The old
   * {@code clearAll()} dropped read regions too, so any transaction that wrote a shredded entity
   * and committed inside an open read bracket erased that bracket's debt and let an unverified
   * decode through.
   */
  public static void clearWriteScopesOwnedBy(Object session) {
    Deque<WriteEntry> stack = WRITE_SCOPES.get();
    stack.removeIf(entry -> entry.session() == session);
    if (stack.isEmpty()) {
      WRITE_SCOPES.remove();
    }
  }

  public static Optional<Scope> current() {
    Deque<WriteEntry> stack = WRITE_SCOPES.get();
    return stack.isEmpty() ? Optional.empty() : Optional.of(stack.peek().scope());
  }

  /**
   * The scope a bind of {@code entity.field} may be performed under, or a refusal.
   *
   * <p><strong>Cipher item 13 / C-41.</strong> The entity name is compared. Ignoring it
   * <em>was</em> C-41: a scope pushed for {@code A} and left behind was handed to a bind of {@code
   * B}, which then encrypted B's row under A's subject and put it inside A's erasure scope. A
   * mismatch is refused with {@code SHRED-CONTEXT-001}; there is no substitution and no best guess.
   */
  public static Scope require(String entity, String field) {
    Scope scope =
        current()
            .orElseThrow(
                () ->
                    new ShreddingException(
                        ErrorCodes.NO_CONTEXT,
                        "no shredding context while writing "
                            + entity
                            + "."
                            + field
                            + ". A @Shredded field can only be written through a managed entity, so"
                            + " that its data subject and its row are known. Bulk JPQL updates,"
                            + " criteria parameters and detached writes to a shredded column are"
                            + " refused rather than encrypted under a guessed subject."));
    if (!scope.entityName().equals(entity)) {
      throw new ShreddingException(
          ErrorCodes.NO_CONTEXT,
          "the shredding context in force while writing "
              + entity
              + "."
              + field
              + " was pushed for a different entity ("
              + scope.entityName()
              + "). A write scope is consumable only by the bind it was pushed for; using it here"
              + " would encrypt this row under the other entity's data subject and move it into"
              + " that subject's erasure scope.");
    }
    return scope;
  }

  /** Runs {@code body} with a scope pushed; for tests and for the erasure endpoint. */
  public static <T> T with(Scope scope, java.util.function.Supplier<T> body) {
    long token = pushWrite(scope, Thread.currentThread());
    try {
      return body.get();
    } finally {
      popWrite(token);
    }
  }

  // ---------------------------------------------------------------- read regions

  /**
   * What a decode is filed under (design §1, §4).
   *
   * <p>All five components come out of the header the converter just decoded. The row id is the one
   * C-34 added: without it, two rows of the <em>same</em> subject shared a key, so a ciphertext
   * copied from one into the other drained the other's entry and was displayed as its own.
   */
  public record FrameKey(
      String entity, String field, TenantId tenant, SubjectId subject, RowId rowId) {
    public FrameKey {
      Objects.requireNonNull(entity, "entity");
      Objects.requireNonNull(field, "field");
      Objects.requireNonNull(tenant, "tenant");
      Objects.requireNonNull(subject, "subject");
      Objects.requireNonNull(rowId, "rowId");
    }
  }

  /** One decrypted value waiting for the verifier that will install it. */
  private record Pending(byte[] plaintext, long ownerToken) {}

  /**
   * A multiset, not a map: one query can legitimately return several rows, and before the row id
   * joined the key two rows of one subject shared it entirely. It stays a multiset with the row id
   * in place because a single row can be hydrated twice inside one region (an association reached
   * from two sides), and losing one of those two decodes would turn a satisfied debt into {@code
   * SHRED-READ-UNVERIFIED}.
   */
  private static final class Region {
    private final long token;
    private final Map<FrameKey, List<Pending>> pending = new HashMap<>();

    Region(long token) {
      this.token = token;
    }

    int total() {
      return pending.values().stream().mapToInt(List::size).sum();
    }
  }

  private static final ThreadLocal<Deque<Region>> REGIONS =
      ThreadLocal.withInitial(ArrayDeque::new);

  /** Reentrant: a repository call can trigger a lazy load of another shredded entity. */
  public static long openRegion() {
    long token = TOKENS.incrementAndGet();
    REGIONS.get().push(new Region(token));
    return token;
  }

  /**
   * Closes the region {@code token} named. If it still holds a decode nothing ever drained, the
   * debt is unpaid: throws {@code SHRED-READ-UNVERIFIED} naming the field - never the plaintext -
   * after the region is already gone, so a retry starts clean.
   *
   * <p>A token that is not on the stack is itself a refusal: it means something unwound past this
   * region, and continuing as if the close had happened would let the next call inherit it.
   */
  public static void closeRegion(long token) {
    Region region = unwindTo(token);
    if (region == null) {
      throw new ShreddingException(
          ErrorCodes.READ_UNVERIFIED,
          "a read region was closed that is no longer on this thread's stack. Something unwound"
              + " past it - an Error, or a region closed out of order - and the decrypts it was"
              + " accountable for cannot be shown to have been verified.");
    }
    if (!region.pending.isEmpty()) {
      FrameKey first = region.pending.keySet().iterator().next();
      throw new ShreddingException(
          ErrorCodes.READ_UNVERIFIED,
          "a read region closed with "
              + region.total()
              + " decrypted @Shredded value(s) that no verifier ever drained, the first being "
              + first.entity()
              + "."
              + first.field()
              + ". Every decrypt inside a read region must be reached by a managed entity load,"
              + " which ShreddingEventListener.onPostLoad verifies against the row once it is"
              + " hydrated. A repository @Query projection, a Spring Data interface projection, a"
              + " Tuple or constructor-expression query, or any other read that reaches a shredded"
              + " converter without going through an entity load, is refused rather than returned."
              + " Nothing was handed back: the converter returns a placeholder, never the value.");
    }
  }

  /**
   * Closes the region {@code token} named without checking it. For the exceptional path only: the
   * region must still unwind so a pooled thread does not carry it into the next, unrelated call,
   * but a region left non-empty because the body threw before reaching its verifier is not the
   * failure worth reporting - the original exception is.
   */
  public static void discardRegion(long token) {
    unwindTo(token);
  }

  private static Region unwindTo(long token) {
    Deque<Region> stack = REGIONS.get();
    Region found = null;
    while (!stack.isEmpty()) {
      Region region = stack.pop();
      if (region.token == token) {
        found = region;
        break;
      }
    }
    if (stack.isEmpty()) {
      REGIONS.remove();
    }
    return found;
  }

  /** Whether a read region is open. An accusation, never an authority: see the class javadoc. */
  public static boolean inReadBracket() {
    return !REGIONS.get().isEmpty();
  }

  /**
   * Runs {@code body} with a read region open, for a raw {@code EntityManager} call that is itself
   * a managed-entity operation - {@code find}, {@code merge}, {@code refresh}, an entity-returning
   * JPQL/Criteria query. {@code EntityManager.merge} in particular re-loads the row's current
   * persisted state internally, which reaches a shredded converter exactly like any other load.
   *
   * <p>This is not an escape hatch for a projection: a scalar, {@code Tuple} or
   * constructor-expression query run inside a region still has nothing to install its decodes, and
   * the region refuses at close with {@code SHRED-READ-UNVERIFIED}.
   *
   * <p>C-32: the region unwinds on any {@link Throwable}, not only a {@link RuntimeException}.
   */
  public static <T> T withReadBracket(java.util.function.Supplier<T> body) {
    long token = openRegion();
    boolean threw = true;
    try {
      T result = body.get();
      threw = false;
      return result;
    } finally {
      if (threw) {
        discardRegion(token);
      } else {
        closeRegion(token);
      }
    }
  }

  /**
   * Files a decrypted value in the region currently on top, to be installed by the verifier that
   * proves which row it belongs to.
   *
   * @throws ShreddingException {@code SHRED-READ-UNSCOPED} if no region is open. Cipher item 1: a
   *     placeholder returned with nothing that will ever close a region is a value crossing the
   *     boundary with no signal at all, so the decrypt is refused instead - the case of a
   *     hand-written DAO, a bare {@code EntityManager}, a {@code Stream} drained after the
   *     repository call returned, or an {@code @Async} continuation.
   */
  public static void recordDecoded(FrameKey key, byte[] plaintext) {
    Deque<Region> stack = REGIONS.get();
    if (stack.isEmpty()) {
      throw new ShreddingException(
          ErrorCodes.READ_UNSCOPED,
          "no read region while decrypting "
              + key.entity()
              + "."
              + key.field()
              + ". A @Shredded field can only be decrypted inside a managed entity load - a Spring"
              + " Data repository call, or a raw EntityManager entity operation (find, merge,"
              + " refresh, an entity-returning query) wrapped in"
              + " ShreddingContext.withReadBracket(...), documented in README.md and"
              + " docs/index.md. This is refused, with nothing returned, for any of several causes:"
              + " a Stream-returning repository method consumed after the repository call already"
              + " returned - the region closes with the method call, not with the stream; an"
              + " @Async continuation, which runs on another thread; a hand-written DAO holding its"
              + " own EntityManager rather than a Spring Data Repository, which this module never"
              + " brackets automatically; a StatelessSession, which fires no PostLoad event at all;"
              + " or any other EntityManager use that was not itself wrapped in"
              + " withReadBracket(...).");
    }
    Region region = stack.peek();
    region
        .pending
        .computeIfAbsent(key, k -> new ArrayList<>())
        .add(new Pending(plaintext, region.token));
  }

  /**
   * Takes back one decrypted value for {@code key}, if the region currently on top holds one that
   * it itself recorded.
   *
   * <p><strong>Cipher item 4.</strong> Only under the current region's owner token. An entry whose
   * token belongs to another region - residue an {@code Error} unwound past, or a decode from
   * before an erasure - is discarded rather than installed, and the caller refuses the load. That
   * is what turns D6's "a stale value of the same row" into {@code SHRED-READ-UNVERIFIED}, and it
   * is what stops post-erasure residue standing in as a false proof that a value is still readable.
   */
  public static Optional<byte[]> drain(FrameKey key) {
    Deque<Region> stack = REGIONS.get();
    if (stack.isEmpty()) {
      return Optional.empty();
    }
    Region region = stack.peek();
    List<Pending> entries = region.pending.get(key);
    if (entries == null || entries.isEmpty()) {
      return Optional.empty();
    }
    Pending pending = entries.remove(0);
    if (entries.isEmpty()) {
      region.pending.remove(key);
    }
    if (pending.ownerToken() != region.token) {
      // Foreign-token residue: discarded, never installed, and the caller refuses.
      return Optional.empty();
    }
    return Optional.of(pending.plaintext());
  }

  /**
   * Every key the open region still holds for {@code entity.field}. The verifier uses it to say
   * <em>why</em> a row's own key was not there: a header naming another subject or tenant is {@code
   * SHRED-SUBJECT-MISMATCH}, a header naming the right subject but another row is {@code
   * SHRED-ROW-MISMATCH}, and nothing at all is {@code SHRED-READ-UNVERIFIED}.
   */
  public static List<FrameKey> pendingKeysFor(String entity, String field) {
    Deque<Region> stack = REGIONS.get();
    if (stack.isEmpty()) {
      return List.of();
    }
    return stack.peek().pending.keySet().stream()
        .filter(k -> k.entity().equals(entity) && k.field().equals(field))
        .toList();
  }
}
