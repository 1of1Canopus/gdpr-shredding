package com.housedevinci.shredding.jpa;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * Cipher fifth pass: C-32's {@code Throwable} unwind of {@code withReadBracket}, exercised with the
 * {@code Error} its own javadoc names - a {@code StackOverflowError} from a deep object graph -
 * rather than a {@code RuntimeException} standing in for one.
 *
 * <p>{@code try}/{@code finally} does not survive a {@code StackOverflowError}: the {@code finally}
 * block has to <em>call</em> {@code discardReadBracket()} / {@code pop()}, and at the depths where
 * the stack is already exhausted that call throws a second {@code StackOverflowError} which
 * replaces the first and skips the cleanup. Whether any single unwind leaks depends on exactly
 * where the stack ran out, so each probe below repeats the overflow on a fresh, small-stack thread
 * and fails if <em>any</em> attempt leaves state behind - the property is "never", not "usually".
 */
class CipherProbeBracketUnwindTest {

  private static final int ATTEMPTS = 200;
  private static final long STACK_BYTES = 256 * 1024;

  /**
   * A {@code StackOverflowError} raised inside a nested {@code withReadBracket} must leave the
   * thread with no frame at all. A pooled thread that keeps one carries a bracket the next,
   * unrelated call did not open, and a decode inside that call is then treated as "inside a managed
   * entity load" and deferred to a verifier that never runs - {@code ShreddedConverter} returns the
   * plaintext instead of refusing with {@code SHRED-READ-UNSCOPED}.
   */
  @Test
  void probe_a_stack_overflow_inside_a_read_bracket_leaves_no_frame_on_the_thread() {
    int leaked =
        countLeaks(
            () -> {
              overflow(() -> deepBracket(Integer.MAX_VALUE));
              return ShreddingContext.inReadBracket();
            });
    System.out.println("UNWIND read bracket -> leaked on " + leaked + "/" + ATTEMPTS + " unwinds");
    assertThat(leaked).isZero();
  }

  /**
   * The same for {@code withRead}'s scope stack, which is worse than a leaked frame: a leaked read
   * scope is a caller's vouched-for (tenant, subject) that the next call on this pooled thread
   * inherits, and {@code ShreddedConverter} checks a header against it and <em>returns the value</em>
   * when it matches - turning a projection that would have been refused with {@code
   * SHRED-READ-UNSCOPED} into one that decrypts and hands back the row.
   */
  @Test
  void probe_a_stack_overflow_inside_a_read_scope_leaves_no_scope_on_the_thread() {
    var scope = new ShreddingContext.Scope(TenantId.of("t"), SubjectId.of("victim"), "Widget");
    int leaked =
        countLeaks(
            () -> {
              overflow(() -> deepReadScope(scope, Integer.MAX_VALUE));
              return ShreddingContext.currentReadScope().isPresent();
            });
    System.out.println("UNWIND read scope -> leaked on " + leaked + "/" + ATTEMPTS + " unwinds");
    assertThat(leaked).isZero();
  }

  /**
   * And the write scope. {@code ShreddingContext.require} hands a converter whatever is on top of
   * this stack; a leaked entry means the next write on this pooled thread encrypts under the
   * previous subject's key, putting the row inside the wrong subject's erasure scope, where {@code
   * SHRED-CONTEXT-001} should have refused it. The transaction-completion {@code clearAll()}
   * backstop covers the listener path when a transaction exists and completes on this thread; it
   * does not cover {@code ShreddingContext.with(...)}, which is public API.
   */
  @Test
  void probe_a_stack_overflow_inside_a_write_scope_leaves_no_scope_on_the_thread() {
    var scope = new ShreddingContext.Scope(TenantId.of("t"), SubjectId.of("victim"), "Widget");
    int leaked =
        countLeaks(
            () -> {
              overflow(() -> deepWriteScope(scope, Integer.MAX_VALUE));
              return ShreddingContext.current().isPresent();
            });
    System.out.println("UNWIND write scope -> leaked on " + leaked + "/" + ATTEMPTS + " unwinds");
    assertThat(leaked).isZero();
  }

  /**
   * Nested brackets, the shape a recursive repository traversal produces: every level of a {@code
   * findChildren} -> {@code findChildren} walk opens its own bracket through {@code
   * ShreddingReadBracketCustomizer}, and they are all still open when the stack runs out. The
   * unwind then has to run one {@code finally} per level, at exactly the depths where there is no
   * stack left to call {@code discardReadBracket()} from.
   */
  private static Object deepBracket(int remaining) {
    return ShreddingContext.withReadBracket(
        () -> remaining <= 0 ? null : deepBracket(remaining - 1));
  }

  private static Object deepReadScope(ShreddingContext.Scope scope, int remaining) {
    return ShreddingContext.withRead(
        scope, () -> remaining <= 0 ? null : deepReadScope(scope, remaining - 1));
  }

  private static Object deepWriteScope(ShreddingContext.Scope scope, int remaining) {
    return ShreddingContext.with(
        scope, () -> remaining <= 0 ? null : deepWriteScope(scope, remaining - 1));
  }

  /** Runs {@code step} until the stack runs out, swallowing the resulting Error. */
  private static void overflow(Supplier<Object> step) {
    try {
      var unused = step.get();
    } catch (StackOverflowError expected) {
      // The unwind is the subject of the test, not the error.
    }
  }

  /**
   * Runs {@code attempt} on a fresh thread with a small stack, {@code ATTEMPTS} times, counting how
   * many of them reported leftover state. A fresh thread per attempt so one attempt's leak cannot
   * be mistaken for the next one's, and a small stack so the overflow is quick and the depth at
   * which it lands varies the way it would in a real, differently-loaded request thread.
   */
  private static int countLeaks(java.util.function.BooleanSupplier attempt) {
    int leaked = 0;
    for (int i = 0; i < ATTEMPTS; i++) {
      final boolean[] result = new boolean[1];
      Thread thread =
          new Thread(null, () -> result[0] = attempt.getAsBoolean(), "unwind-" + i, STACK_BYTES);
      thread.start();
      try {
        thread.join();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IllegalStateException(e);
      }
      if (result[0]) {
        leaked++;
      }
    }
    return leaked;
  }
}
