package com.housedevinci.shredding.jpa;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * The fifth pass: C-32's {@code Throwable} unwind, exercised with the {@code Error} its own javadoc
 * names - a {@code StackOverflowError} from a deep object graph - rather than a {@code
 * RuntimeException} standing in for one.
 *
 * <p>{@code try}/{@code finally} does not survive a {@code StackOverflowError}: the {@code finally}
 * block has to <em>call</em> the pop, and at the depths where the stack is already exhausted that
 * call throws a second {@code StackOverflowError} which replaces the first and skips the cleanup.
 * No arrangement of {@code finally} fixes that, which is why the read-path design (§1.2) stops
 * depending on unwind cleanup and rests the argument on two properties instead:
 *
 * <ol>
 *   <li>a leaked region can never hand plaintext to anybody, because the converter no longer
 *       returns plaintext at all - the most a leaked region buys an attacker is a missing loudness,
 *       never a value;
 *   <li>a drain reads the region currently on top of this thread's stack, so a decode filed inside
 *       a region an {@code Error} unwound past - popped off that stack, along with everything above
 *       it, by {@code ShreddingContext.unwindTo} - is never installed by a later, unrelated call:
 *       there is no region left on the stack to drain it from. (S-4, the sixth pass, corrected
 *       this: the owner-token comparison this javadoc used to cite was never reachable - a decode
 *       is always read back from the very region it was recorded into - and has been removed; what
 *       actually does the work is the region stack itself, exercised below.) What turns D6's "a
 *       stale value of the same row" and post-erasure residue into {@code SHRED-READ-UNVERIFIED} is
 *       that a region closes with an unpaid debt when nothing drains a decode it still holds.
 * </ol>
 *
 * <p>The write-scope probe keeps its original, stronger assertion: a leaked write scope <em>is</em>
 * real authority, and it must never survive.
 */
class CipherProbeBracketUnwindTest {

  private static final int ATTEMPTS = 200;
  private static final long STACK_BYTES = 256 * 1024;

  private static final ShreddingContext.Scope SCOPE =
      new ShreddingContext.Scope(
          TenantId.of("t"), SubjectId.of("victim"), "Widget", RowId.ofIdentifier(1L));

  /**
   * A leaked write scope means the next write on this pooled thread encrypts under the previous
   * subject's key, putting the row inside the wrong subject's erasure scope where {@code
   * SHRED-CONTEXT-001} should have refused it. This is the one leak that is authority, and it must
   * be zero.
   */
  @Test
  void probe_a_stack_overflow_inside_a_write_scope_leaves_no_scope_on_the_thread() {
    int leaked =
        countLeaks(
            () -> {
              overflow(() -> deepWriteScope(Integer.MAX_VALUE));
              return ShreddingContext.current().isPresent();
            });
    System.out.println("UNWIND write scope -> leaked on " + leaked + "/" + ATTEMPTS + " unwinds");
    assertThat(leaked).isZero();
  }

  /**
   * And when one does survive - {@code ShreddingContext.pushWrite} is the second line: a scope
   * still live when the next bind starts is by construction residue, so it is dropped rather than
   * consumed (finding item 14).
   */
  @Test
  void probe_a_leaked_write_scope_is_dropped_by_the_next_bind_rather_than_consumed() {
    var stale =
        new ShreddingContext.Scope(
            TenantId.of("t"), SubjectId.of("attacker"), "Widget", RowId.ofIdentifier(9L));
    ShreddingContext.pushWrite(stale, new Object());

    // pushBind, not pushWrite: what onPreInsert/onPreUpdate use. The plain push allows nesting,
    // because ShreddingContext.with(...) is public API a caller may legitimately nest, and a nested
    // with is not residue.
    long token = ShreddingContext.pushBind(SCOPE, new Object());
    try {
      assertThat(ShreddingContext.require("Widget", "name")).isEqualTo(SCOPE);
    } finally {
      ShreddingContext.popWrite(token);
    }
    assertThat(ShreddingContext.current()).isEmpty();
  }

  /**
   * finding item 4, the property that replaces "no frame survives". A region left behind by a
   * {@code StackOverflowError} keeps whatever it was holding, but nothing in a later call can take
   * it out: a drain reads the region currently on top, and an entry filed under another region's
   * token is discarded rather than installed. The load that asked for it refuses.
   */
  @Test
  void probe_a_decode_filed_in_a_region_an_error_unwound_past_is_never_drained_later() {
    var key =
        new ShreddingContext.FrameKey(
            "Widget", "name", TenantId.of("t"), SubjectId.of("victim"), RowId.ofIdentifier(1L));
    int drained = 0;
    for (int attempt = 0; attempt < ATTEMPTS; attempt++) {
      final int[] result = new int[1];
      Thread thread =
          new Thread(
              null,
              () -> {
                overflow(() -> deepRegionThatFiles(key, Integer.MAX_VALUE));
                // Whatever the overflow left behind, a fresh region is what a later, unrelated call
                // on this pooled thread would open. Nothing it drains may come from the residue.
                long token = ShreddingContext.openRegion();
                result[0] = ShreddingContext.drain(key).isPresent() ? 1 : 0;
                ShreddingContext.discardRegion(token);
              },
              "unwind-region-" + attempt,
              STACK_BYTES);
      thread.start();
      join(thread);
      drained += result[0];
    }
    System.out.println(
        "UNWIND region residue -> drained by a later region on " + drained + "/" + ATTEMPTS);
    assertThat(drained).isZero();
  }

  /**
   * And the whole point of the design: whatever leaks, no plaintext does. The value a converter
   * decrypts never leaves it - the converter returns a placeholder - so a region an {@code Error}
   * unwound past holds bytes that only a verified, row-matched install could ever have used.
   */
  @Test
  void probe_a_region_an_error_unwound_past_yields_no_plaintext_to_anybody() {
    var key =
        new ShreddingContext.FrameKey(
            "Widget", "name", TenantId.of("t"), SubjectId.of("victim"), RowId.ofIdentifier(1L));
    final String[] seen = new String[1];
    Thread thread =
        new Thread(
            null,
            () -> {
              overflow(() -> deepRegionThatFiles(key, Integer.MAX_VALUE));
              long token = ShreddingContext.openRegion();
              seen[0] =
                  ShreddingContext.drain(key)
                      .map(b -> new String(b, StandardCharsets.UTF_8))
                      .orElse("NOTHING");
              ShreddingContext.discardRegion(token);
            },
            "unwind-plaintext",
            STACK_BYTES);
    thread.start();
    join(thread);
    System.out.println("UNWIND leaked plaintext -> " + seen[0]);
    assertThat(seen[0]).doesNotContain("UNWIND-SECRET");
  }

  private static Object deepWriteScope(int remaining) {
    return ShreddingContext.with(
        SCOPE, () -> remaining <= 0 ? null : deepWriteScope(remaining - 1));
  }

  /**
   * Nested regions, the shape a recursive repository traversal produces: every level of a {@code
   * findChildren} -> {@code findChildren} walk opens its own region, each files a decode, and they
   * are all still open when the stack runs out.
   */
  private static Object deepRegionThatFiles(ShreddingContext.FrameKey key, int remaining) {
    return ShreddingContext.withReadBracket(
        () -> {
          ShreddingContext.recordDecoded(key, "UNWIND-SECRET".getBytes(StandardCharsets.UTF_8));
          return remaining <= 0 ? null : deepRegionThatFiles(key, remaining - 1);
        });
  }

  /** Runs {@code step} until the stack runs out, swallowing the resulting Error. */
  private static void overflow(Supplier<Object> step) {
    try {
      var unused = step.get();
    } catch (StackOverflowError | RuntimeException expected) {
      // The unwind is the subject of the test, not the error. A region that does manage to close
      // throws SHRED-READ-UNVERIFIED on the way out, which is the correct outcome and not a leak.
    }
  }

  private static int countLeaks(java.util.function.BooleanSupplier attempt) {
    int leaked = 0;
    for (int i = 0; i < ATTEMPTS; i++) {
      final boolean[] result = new boolean[1];
      Thread thread =
          new Thread(null, () -> result[0] = attempt.getAsBoolean(), "unwind-" + i, STACK_BYTES);
      thread.start();
      join(thread);
      if (result[0]) {
        leaked++;
      }
    }
    return leaked;
  }

  private static void join(Thread thread) {
    try {
      thread.join();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }
}
