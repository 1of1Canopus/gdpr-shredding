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
   *
   * <p><strong>S-2.</strong> {@code tenant} is the row's primary tenant - the first
   * {@code @Shredded} field's resolved tenant, used wherever a single tenant names the row (the
   * {@code IDENTITY} rebind's SQL parameters aside, everything else is per field). {@code
   * fieldTenants} carries the <em>actual</em> per-field tenant for every {@code @Shredded} field of
   * the entity, evaluated once, up front, in {@code scopeFor} - because a field's tenant expression
   * can only be evaluated against the entity instance, and the converter that later asks for it is
   * handed nothing but the attribute value. {@link #tenantFor(String)} is what every write-path use
   * of a per-field tenant goes through; {@code tenant()} alone is never enough once an entity
   * declares more than one tenant expression.
   */
  public record Scope(
      TenantId tenant,
      SubjectId subject,
      String entityName,
      RowId rowId,
      Map<String, TenantId> fieldTenants) {
    public Scope {
      Objects.requireNonNull(tenant, "tenant");
      Objects.requireNonNull(subject, "subject");
      Objects.requireNonNull(entityName, "entityName");
      Objects.requireNonNull(rowId, "rowId");
      fieldTenants = fieldTenants == null ? Map.of() : Map.copyOf(fieldTenants);
    }

    /** Convenience constructor for the common case of one tenant shared by every field. */
    public Scope(TenantId tenant, SubjectId subject, String entityName, RowId rowId) {
      this(tenant, subject, entityName, rowId, Map.of());
    }

    /**
     * The tenant to use for {@code fieldName}: its own declared tenant if one was resolved, else
     * this row's primary tenant.
     */
    public TenantId tenantFor(String fieldName) {
      return fieldTenants.getOrDefault(fieldName, tenant);
    }
  }

  private ShreddingContext() {}

  // ---------------------------------------------------------------- write scopes

  private record WriteEntry(Scope scope, Object session, long token) {}

  private static final ThreadLocal<Deque<WriteEntry>> WRITE_SCOPES =
      ThreadLocal.withInitial(ArrayDeque::new);

  /**
   * Pushes the scope a single bind will be performed under and returns the token that pops it
   * again. Nesting is allowed: this is the plain push, reached from {@link #with} and from the
   * erasure path, where a caller may legitimately hold one scope while opening another.
   *
   * @param session the Hibernate session that owns this write, so a transaction completing on this
   *     thread clears only its own scopes
   */
  public static long pushWrite(Scope scope, Object session) {
    Objects.requireNonNull(scope, "scope");
    long token = TOKENS.incrementAndGet();
    WRITE_SCOPES.get().push(new WriteEntry(scope, session, token));
    return token;
  }

  /**
   * What {@code onPreInsert}/{@code onPreUpdate} use: the same push, preceded by dropping anything
   * still live.
   *
   * <p>C-41 / Cipher item 14. Hibernate executes the action queue serially and a shredded converter
   * never triggers another entity's bind, so a scope still live when a {@code Pre*} listener pushes
   * is by construction residue from a bind whose {@code Post*} listener never ran - a converter
   * refusal, a constraint violation, a throw out of {@code writeBlindIndexes}. Dropping it here is
   * what makes "a write scope is consumable only by the bind it was pushed for" true on the path
   * where residue was consumable; the entity-name check in {@link #require} and the post-hoc header
   * check in the {@code Post*} listeners are the other two.
   *
   * <p>Kept apart from {@link #pushWrite} because that one is also reached from {@link #with},
   * which is public API a caller may legitimately nest. A nested {@code with} is not residue, and
   * treating it as such would both discard a live scope and log once per level.
   */
  public static long pushBind(Scope scope, Object session) {
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

  /**
   * Pops the scope {@code token} named, and nothing else. A token already gone is not an error.
   *
   * <p>The top-of-stack case is handled with a bare {@code pop()} rather than by the {@code
   * removeIf} below, and that is not a micro-optimisation. This method runs from a {@code finally},
   * including the {@code finally} of a {@link #with} nested to the point of stack exhaustion, and
   * at that depth every additional frame is another chance for the cleanup itself to throw a second
   * {@link StackOverflowError} and leave the scope behind - which is a leaked write scope, the one
   * piece of ambient state in this class that is real authority. {@code removeIf} on an {@link
   * ArrayDeque} allocates an iterator and calls through a lambda; {@code pop()} does neither.
   * Measured by {@code CipherProbeBracketUnwindTest}, which caught this exact regression at 154/200
   * leaks before the fast path was restored.
   */
  public static void popWrite(long token) {
    Deque<WriteEntry> stack = WRITE_SCOPES.get();
    WriteEntry top = stack.peek();
    if (top != null && top.token() == token) {
      stack.pop();
    } else if (top != null) {
      stack.removeIf(entry -> entry.token() == token);
    }
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

  /**
   * Runs {@code body} with a scope pushed; for tests and for the erasure endpoint.
   *
   * <p>The stack is resolved <em>before</em> the body runs and the {@code finally} unwinds it
   * in-line rather than calling {@link #popWrite}. A {@code finally} cannot survive stack
   * exhaustion - it has to *call* something, and at that depth the call is what throws the second
   * {@link StackOverflowError} (C-32) - so the only lever left is to need as few frames as possible
   * on the way out. Resolving the {@link ThreadLocal} up front and popping the deque directly is
   * measurably better than a helper call: {@code CipherProbeBracketUnwindTest} reports the number.
   *
   * <p>It is a lever, not a guarantee. The guarantee is elsewhere and does not depend on unwinding
   * at all: a scope that does survive is dropped by {@link #pushBind} before the next bind, refused
   * by {@link #require}'s entity-name check if anything else reaches for it, and caught after the
   * fact by the post-hoc header check in the {@code Post*} listeners. See QUESTIONS.md #24.
   */
  public static <T> T with(Scope scope, java.util.function.Supplier<T> body) {
    Deque<WriteEntry> stack = WRITE_SCOPES.get();
    long token = pushWrite(scope, Thread.currentThread());
    try {
      return body.get();
    } finally {
      WriteEntry top = stack.peek();
      if (top != null && top.token() == token) {
        stack.pop();
      } else {
        popWrite(token);
      }
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

  /**
   * One decrypted value waiting for the verifier that will install it.
   *
   * <p>S-4 (Cipher sixth pass): this used to also carry an {@code ownerToken}, stamped with the
   * region's own token at record time and compared against the region's own token again at drain
   * time. Both reads are {@code stack.peek()} of the <em>same</em> {@link Region} object - a {@code
   * Pending} never moves from the map it was recorded into - so {@code pending.ownerToken() !=
   * region.token} was unsatisfiable by construction: not a check that failed occasionally, one that
   * could never fail at all. Removed rather than "fixed", because making it real would mean
   * distinguishing a region legitimately open for the call in progress from one left on the deque
   * by an earlier caller that never closed it - the public, unpaired {@link #openRegion()} makes
   * that state reachable (QUESTIONS #21) - and doing that soundly needs a second piece of
   * call-scoped state whose own unwind-safety would have to be argued from scratch, the same way
   * {@link #popWrite(long)}'s javadoc argues it for write scopes.
   *
   * <p>That second piece of state is now the entry epoch (design addendum 2), and it is what makes
   * the distinction: the region a decode may use is the one this thread's bracketed <em>entry</em>
   * opened, compared by epoch equality, and nothing else on the deque is reachable at all.
   */
  private record Pending(byte[] plaintext) {}

  /**
   * A multiset, not a map: one query can legitimately return several rows, and before the row id
   * joined the key two rows of one subject shared it entirely. It stays a multiset with the row id
   * in place because a single row can be hydrated twice inside one region (an association reached
   * from two sides), and losing one of those two decodes would turn a satisfied debt into {@code
   * SHRED-READ-UNVERIFIED}.
   */
  private static final class Region {
    private final long token;

    /**
     * The entry epoch in force at the moment this region was constructed, captured once and never
     * re-read (addendum 2 change 2). {@link #NO_ENTRY} for a region opened by the public {@link
     * #openRegion()} outside any entry: such a region can never serve a decode.
     */
    private final long epoch;

    /** For an entry region, the epoch to put back on the thread when this region unwinds. */
    private final long previousEpoch;

    private final Map<FrameKey, List<Pending>> pending = new HashMap<>();

    Region(long token, long epoch, long previousEpoch) {
      this.token = token;
      this.epoch = epoch;
      this.previousEpoch = previousEpoch;
    }

    boolean isEntry() {
      return epoch != NO_ENTRY;
    }

    String firstPendingName() {
      if (pending.isEmpty()) {
        return null;
      }
      FrameKey first = pending.keySet().iterator().next();
      return first.entity() + "." + first.field();
    }

    int total() {
      return pending.values().stream().mapToInt(List::size).sum();
    }
  }

  private static final ThreadLocal<Deque<Region>> REGIONS =
      ThreadLocal.withInitial(ArrayDeque::new);

  /**
   * "No bracketed entry is in force on this thread". Never assigned to a region by an entry: {@link
   * #TOKENS} starts at zero and {@code incrementAndGet()} never returns it.
   */
  private static final long NO_ENTRY = 0L;

  /**
   * Which bracketed entry is in force on this thread (design addendum 2, option (b)).
   *
   * <p>An <em>epoch</em>, not a depth counter. A counter is accumulated state, so one exit missed
   * under a {@link StackOverflowError} (C-32) is permanently wrong in the <em>permissive</em>
   * direction - stuck positive, still authorising. An epoch is replaced state: {@link
   * #enterRegion()} assigns a fresh value unconditionally, nothing accumulates, and a missed
   * restore is overwritten by the next entry in the <em>refusing</em> direction, because a region
   * stamped with any other epoch is thereby residue. Correctness on entry, never on exit - {@link
   * #pushWrite}'s own argument.
   *
   * <p>Compared for <strong>equality only, never for age</strong> (Cipher, addendum 2 change 1). A
   * leftover region can carry an epoch <em>newer</em> than the thread's: an inner entry stamps
   * {@code n+1}, an {@link Error} inside it leaves its region on the deque, the outer frame's
   * restore puts {@code n} back and the outer call carries on. Under "older is residue" that
   * leftover is not older, so it would authorise - and it is the region on top, so it is the one
   * every later decode of the outer call would be filed into. Equality refuses both directions, and
   * takes overflow off the table: an ordering test is the one shape where a single wraparound
   * inverts every comparison at once.
   *
   * <p>A plain {@link ThreadLocal}, never an {@code InheritableThreadLocal} and never anything a
   * task decorator may copy - both this and {@link #REGIONS}. An inherited epoch would match an
   * inherited region and authorise the one case the design gets for free today, silently.
   */
  private static final ThreadLocal<Long> EPOCH = ThreadLocal.withInitial(() -> NO_ENTRY);

  /**
   * Opens a read region for a <em>bracketed entry</em> - the repository proxy or {@link
   * #withReadBracket} - stamping a fresh epoch for the call. These two are the only writers of a
   * real epoch in the module; every other way of getting a region on the deque produces one that
   * can never serve (see {@link #openRegion()}).
   *
   * <p>Before opening, any region on top whose epoch is not the epoch in force <em>at entry</em> is
   * discarded, at WARN with the count and the first {@code entity.field} (addendum 2 change 3, the
   * complement (c) of option (b)): it bounds the residual to "no entry since the failed restore",
   * and the sweep is the only moment an operator ever learns an undisciplined region existed. The
   * comparison is against the epoch in force at entry and not against the fresh one, because a
   * nested repository call must not destroy the outer call's still-live region - its pending
   * decodes would vanish and the outer close would refuse, on every nested call in the application.
   *
   * @return the token that closes this region, which is also the token {@link #closeRegion(long)}
   *     and {@link #discardRegion(long)} take
   */
  public static long enterRegion() {
    Deque<Region> stack = REGIONS.get();
    long inForce = EPOCH.get();
    sweepForeignRegions(stack, inForce);
    long epoch = TOKENS.incrementAndGet();
    long token = TOKENS.incrementAndGet();
    stack.push(new Region(token, epoch, inForce));
    EPOCH.set(epoch);
    return token;
  }

  /**
   * Opens a region that authorises nothing (addendum 2 change 2).
   *
   * <p>It is stamped {@link #NO_ENTRY} explicitly rather than with the epoch in force, and every
   * region access refuses a region whose epoch is not the thread's current entry epoch, so neither
   * of the two shapes Cipher named can serve a decode: a raw call on a thread that never entered an
   * entry (where "the initial value" would otherwise compare equal to itself and authorise), and a
   * raw call from <em>inside</em> a proxied call - a user {@code @PostLoad} method, an
   * {@code @EntityListeners} bean, a hand-written DAO reached from a repository default method -
   * whose region would otherwise sit on top of the deque and take every remaining decode of that
   * call. That second shape is S-4 itself.
   *
   * <p>Kept public only because unpaired region bookkeeping is observable in tests and because
   * removing a published method is a breaking change; there is no use for it in an application.
   * {@link #withReadBracket} is the supported entry, and {@link #closeRegion(long)} refuses a
   * region opened this way.
   *
   * @deprecated use {@link #withReadBracket} (applications) or {@link #enterRegion()} (a framework
   *     integration that owns the call boundary). A region opened here can never serve a decode.
   */
  @Deprecated(since = "0.1.0")
  public static long openRegion() {
    long token = TOKENS.incrementAndGet();
    REGIONS.get().push(new Region(token, NO_ENTRY, NO_ENTRY));
    return token;
  }

  private static void sweepForeignRegions(Deque<Region> stack, long inForce) {
    int swept = 0;
    String first = null;
    while (!stack.isEmpty() && stack.peek().epoch != inForce) {
      Region region = stack.pop();
      swept++;
      if (first == null) {
        first = region.firstPendingName();
      }
    }
    if (swept > 0) {
      log.warn(
          "shredding: dropping {} read region(s) left on this thread by a call that never closed"
              + " them{}; their decrypts were never verified and nothing was installed from them",
          swept,
          first == null ? "" : ", the first holding " + first);
    }
  }

  /**
   * The one region a decode may be filed into, drained from or counted in on this thread, or {@code
   * null} (addendum 2 change 4: one predicate, four callers). A region access with no bracketed
   * entry in force, or against a region stamped by another entry, is not a region access at all -
   * it is residue reaching for authority.
   */
  private static Region currentRegion() {
    Region top = REGIONS.get().peek();
    if (top == null) {
      return null;
    }
    long inForce = EPOCH.get();
    return inForce != NO_ENTRY && top.epoch == inForce ? top : null;
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
    long epochAtClose = EPOCH.get();
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
    refuseIfClosedUnderAnotherEntry(region, epochAtClose);
  }

  /**
   * Addendum 2 change 4, the close half. A region is closed by the entry that opened it or by
   * nobody: closing one stamped by another entry means the epoch in force is not the one this
   * region was opened under - an inner entry whose restore was skipped, or a region opened outside
   * any entry at all - and the decrypts it was accountable for cannot be shown to have been
   * verified by the call that is now returning.
   *
   * <p>Deliberately last, after the region's own unpaid-debt refusal: where both apply, the debt is
   * the more specific report and names the field.
   */
  private static void refuseIfClosedUnderAnotherEntry(Region region, long epochAtClose) {
    if (epochAtClose != NO_ENTRY && region.epoch == epochAtClose) {
      return;
    }
    throw new ShreddingException(
        ErrorCodes.READ_UNVERIFIED,
        "a read region was closed by something other than the bracketed entry that opened it"
            + (region.isEntry()
                ? ". An inner region's unwind did not put this thread's entry epoch back - an Error"
                    + " between the entry and its close - so this close cannot be shown to belong"
                    + " to the call that opened the region."
                : ". The region was opened by ShreddingContext.openRegion() outside any repository"
                    + " call or ShreddingContext.withReadBracket(...), which stamps no entry epoch"
                    + " and can therefore never have served a decrypt."));
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

  /**
   * Pops regions down to {@code token}, restoring the entry epoch of every one it pops.
   *
   * <p><strong>Contract for anything that unwinds the region deque, here or elsewhere.</strong>
   * Every pop must be paired with {@link #restoreEpoch(Region)}. An unwind that pops an entry
   * region without restoring leaves this thread's entry epoch naming a frame that has already
   * returned, and every later region access on that thread compares against it and refuses - fail
   * closed, but wrong, and wrong for the whole rest of the thread's life. The nested probes in
   * {@code CipherProbeRegionEpochTest} and {@code CipherProbeReadScopeTest} fail immediately if a
   * second unwind path is ever added without the restore.
   */
  private static Region unwindTo(long token) {
    Deque<Region> stack = REGIONS.get();
    Region found = null;
    while (!stack.isEmpty()) {
      Region region = stack.pop();
      restoreEpoch(region);
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

  /**
   * Puts back the epoch an entry region was opened under. Called for every region an unwind pops,
   * so the value left on the thread is the one belonging to the frame being returned to, whether
   * the unwind stopped at its token or ran past it. A region that is not an entry carries no epoch
   * of its own and restores nothing.
   */
  private static void restoreEpoch(Region region) {
    if (!region.isEntry()) {
      return;
    }
    if (region.previousEpoch == NO_ENTRY) {
      EPOCH.remove();
    } else {
      EPOCH.set(region.previousEpoch);
    }
  }

  /**
   * Whether a read region is open. An accusation, never an authority: see the class javadoc. Says
   * nothing about whether that region may serve anything - a region left behind by a call that
   * never closed it, and a region opened by {@link #openRegion()}, are both "open" here and are
   * both refused by every access.
   */
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
    long token = enterRegion();
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
    Region region = currentRegion();
    if (region == null) {
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
              + " withReadBracket(...). A region that is on this thread but was not opened by the"
              + " call now running - one left behind by a call that never closed it, or one opened"
              + " directly with ShreddingContext.openRegion() - is not a region this decrypt may"
              + " use, and is refused here for the same reason as no region at all.");
    }
    region.pending.computeIfAbsent(key, k -> new ArrayList<>()).add(new Pending(plaintext));
  }

  /**
   * Takes back one decrypted value for {@code key}, if the region currently on top holds one that
   * it itself recorded.
   *
   * <p><strong>S-4 (Cipher sixth pass).</strong> The most recently recorded entry, not the oldest.
   * Two decodes filed under one key inside one still-open region are always the same row's own
   * value - the multiset exists for a row hydrated twice inside one region, never for two different
   * rows - so which of them a caller takes back is only ever a question of which one a stale,
   * abandoned decode could shadow. Taking the most recent means a fresher decode is never shadowed
   * by an older one left behind by residue: an entry recorded before the current, legitimate one -
   * the shape {@code CipherProbeRegionResidueTest} builds from the public, unpaired {@link
   * #openRegion()} (QUESTIONS #21) - can therefore never be handed back in place of the value this
   * call itself just decrypted. It can still be handed back <em>instead of nothing</em> when the
   * current call never recorded one of its own. That residual - an ownerless region on the deque
   * serving a call that opened no region of its own - is what the entry epoch closes (addendum 2):
   * {@link #currentRegion()} hands back nothing at all unless the region on top is the one the
   * bracketed entry now in force opened. What remains is stated in SECURITY-NOTES.md: a read
   * opening no region of its own, on a thread where an {@link Error} skipped exactly the frame that
   * restores the epoch, still sees a matching one. A leaked region costs a refusal, never a value.
   */
  public static Optional<byte[]> drain(FrameKey key) {
    Region region = currentRegion();
    if (region == null) {
      return Optional.empty();
    }
    List<Pending> entries = region.pending.get(key);
    if (entries == null || entries.isEmpty()) {
      return Optional.empty();
    }
    Pending pending = entries.remove(entries.size() - 1);
    if (entries.isEmpty()) {
      region.pending.remove(key);
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
    Region region = currentRegion();
    if (region == null) {
      return List.of();
    }
    return region.pending.keySet().stream()
        .filter(k -> k.entity().equals(entity) && k.field().equals(field))
        .toList();
  }
}
