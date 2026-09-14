package com.housedevinci.shredding.jpa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The eighth pass (fa6f477). Design addendum 2 as built, attacked.
 *
 * <p>Four of these six are green today and are here to hold the ground the addendum won: three
 * entries deep each serving only their own decodes, a {@code withReadBracket} inside an entry and
 * an entry inside a {@code withReadBracket}, an inner entry discarded by a throw, and a thread that
 * stays usable after a bracket body leaked an entry region.
 *
 * <p>Two are RED.
 *
 * <ul>
 *   <li><strong>S-14.</strong> {@code unwindTo} pops the whole deque when the token it is given is
 *       not on it, so a component that closes a region another frame's sweep already took away
 *       destroys the live entry region of the call it was invoked from. Fail-closed - the outer
 *       call refuses instead of serving - but the outer call did nothing wrong, and the same lever
 *       is available to any caller of {@code closeRegion}/{@code discardRegion} with a token from
 *       another frame.
 *   <li><strong>S-15 (S-4a).</strong> A region opened outside any entry is never swept when nothing
 *       is in force ({@code NO_ENTRY == NO_ENTRY}), so leaked raw regions accumulate on a pooled
 *       thread for the life of that thread and {@code inReadBracket()} stays true forever.
 * </ul>
 */
class CipherProbeEighthPassRegionTest {

  private static ShreddingContext.FrameKey key(String subject, long row) {
    return new ShreddingContext.FrameKey(
        "Widget", "name", TenantId.of("t"), SubjectId.of(subject), RowId.ofIdentifier(row));
  }

  private static byte[] secret(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * S-14 (the eighth pass): {@code discardRegion(-1L)} - a token that is on no stack - no longer
   * empties the deque, so this thread's own {@code ShreddingContext.resetForTests()} is what leaves
   * a clean thread for the next test.
   */
  @AfterEach
  void clean() {
    ShreddingContext.resetForTests();
  }

  /** A1: three entries deep, each serving only its own decode. */
  @Test
  void probe_three_deep_entries_each_serve_only_their_own() {
    long t1 = ShreddingContext.enterRegion();
    ShreddingContext.recordDecoded(key("one", 1), secret("ONE"));
    long t2 = ShreddingContext.enterRegion();
    ShreddingContext.recordDecoded(key("two", 2), secret("TWO"));
    long t3 = ShreddingContext.enterRegion();
    ShreddingContext.recordDecoded(key("three", 3), secret("THREE"));
    assertThat(ShreddingContext.drain(key("one", 1))).isEmpty();
    assertThat(ShreddingContext.drain(key("two", 2))).isEmpty();
    assertThat(ShreddingContext.drain(key("three", 3))).contains(secret("THREE"));
    ShreddingContext.closeRegion(t3);
    assertThat(ShreddingContext.drain(key("one", 1))).isEmpty();
    assertThat(ShreddingContext.drain(key("two", 2))).contains(secret("TWO"));
    ShreddingContext.closeRegion(t2);
    assertThat(ShreddingContext.drain(key("one", 1))).contains(secret("ONE"));
    ShreddingContext.closeRegion(t1);
    assertThat(ShreddingContext.inReadBracket()).isFalse();
  }

  /** A2: a bracket inside an entry, and an entry inside a bracket. */
  @Test
  void probe_bracket_inside_entry_and_entry_inside_bracket() {
    long outer = ShreddingContext.enterRegion();
    ShreddingContext.recordDecoded(key("outer", 1), secret("OUTER"));
    String inner =
        ShreddingContext.withReadBracket(
            () -> {
              ShreddingContext.recordDecoded(key("inner", 2), secret("INNER"));
              assertThat(ShreddingContext.drain(key("outer", 1))).isEmpty();
              return new String(
                  ShreddingContext.drain(key("inner", 2)).orElseThrow(), StandardCharsets.UTF_8);
            });
    assertThat(inner).isEqualTo("INNER");
    assertThat(ShreddingContext.drain(key("outer", 1))).contains(secret("OUTER"));
    ShreddingContext.closeRegion(outer);

    ShreddingContext.withReadBracket(
        () -> {
          ShreddingContext.recordDecoded(key("b", 3), secret("B"));
          long nested = ShreddingContext.enterRegion();
          assertThat(ShreddingContext.drain(key("b", 3))).isEmpty();
          ShreddingContext.closeRegion(nested);
          assertThat(ShreddingContext.drain(key("b", 3))).contains(secret("B"));
          return null;
        });
  }

  /**
   * A3: a region swept by a nested entry, then closed by its own owner: does the close destroy the
   * live entry region of the frame it was called from?
   */
  @Test
  void probe_closing_a_swept_region_does_not_destroy_the_callers_live_region() {
    Throwable outcome =
        catchThrowable(
            () ->
                ShreddingContext.withReadBracket(
                    () -> {
                      long raw = ShreddingContext.openRegion(); // a user @PostLoad, say
                      long nested = ShreddingContext.enterRegion(); // any nested repository call
                      ShreddingContext.closeRegion(nested); // sweeps `raw` away
                      // the undisciplined component now closes what it opened
                      assertThatThrownBy(() -> ShreddingContext.closeRegion(raw))
                          .isInstanceOf(ShreddingException.class);
                      // and the well-behaved outer call carries on with its own, still-valid region
                      ShreddingContext.recordDecoded(key("outer", 1), secret("OUTER"));
                      assertThat(ShreddingContext.drain(key("outer", 1))).contains(secret("OUTER"));
                      return null;
                    }));
    assertThat(outcome)
        .describedAs("the outer bracket, which did everything right, must still complete")
        .isNull();
  }

  /** A4: an inner entry that threw is discarded; the outer keeps serving its own. */
  @Test
  void probe_outer_survives_a_discarded_inner_entry() {
    ShreddingContext.withReadBracket(
        () -> {
          ShreddingContext.recordDecoded(key("outer", 1), secret("OUTER"));
          assertThatThrownBy(
                  () ->
                      ShreddingContext.withReadBracket(
                          () -> {
                            ShreddingContext.recordDecoded(key("inner", 2), secret("INNER"));
                            throw new IllegalStateException("boom");
                          }))
              .isInstanceOf(IllegalStateException.class);
          assertThat(ShreddingContext.drain(key("outer", 1))).contains(secret("OUTER"));
          return null;
        });
  }

  /** A5: a bracket body that leaks its own entry region is refused, and the thread stays usable. */
  @Test
  void probe_a_thread_stays_usable_after_a_leaked_entry_region() {
    assertThatThrownBy(
            () ->
                ShreddingContext.withReadBracket(
                    () -> {
                      long leaked = ShreddingContext.enterRegion();
                      ShreddingContext.recordDecoded(key("leaked", 9), secret("LEAKED"));
                      return leaked;
                    }))
        .isInstanceOf(ShreddingException.class);
    assertThat(ShreddingContext.inReadBracket()).isFalse();
    // the next call on this pooled thread must be clean
    ShreddingContext.withReadBracket(
        () -> {
          ShreddingContext.recordDecoded(key("next", 10), secret("NEXT"));
          assertThat(ShreddingContext.drain(key("leaked", 9))).isEmpty();
          assertThat(ShreddingContext.drain(key("next", 10))).contains(secret("NEXT"));
          return null;
        });
  }

  /** A6: raw regions left on a pooled thread with nothing in force accumulate (S-4a). */
  @Test
  void probe_raw_regions_do_not_accumulate_on_a_pooled_thread() {
    for (int i = 0; i < 5; i++) {
      ShreddingContext.openRegion(); // leaked by an undisciplined component, nothing in force
      ShreddingContext.withReadBracket(
          () -> {
            ShreddingContext.recordDecoded(key("x", 1), secret("X"));
            assertThat(ShreddingContext.drain(key("x", 1))).contains(secret("X"));
            return null;
          });
    }
    assertThat(ShreddingContext.inReadBracket())
        .describedAs("five leaked raw regions, none of them ever swept")
        .isFalse();
  }
}
