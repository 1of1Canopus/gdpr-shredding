package com.housedevinci.shredding.jpa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * Design addendum 2 (region residue) and Cipher's six changes to it, one probe each.
 *
 * <p>The property under test: <em>a decrypt is served only inside a region opened by the same
 * bracketed entry that is reading, on the same thread; residue from an earlier call, however it
 * ended, never serves.</em> The mechanism is one {@code long} per thread - the entry epoch -
 * stamped by {@code enterRegion()} and compared for <strong>equality</strong> at every region
 * access.
 *
 * <p>Every probe here builds its state through the public API only. Nothing is reflected into and
 * nothing is mocked: the shapes below - a raw {@code openRegion()} on a fresh thread, a raw {@code
 * openRegion()} from inside a call, an inner entry whose close never runs - are the exact shapes an
 * application, a user {@code @PostLoad} method and a {@code StackOverflowError} produce.
 */
class CipherProbeRegionEpochTest {

  private static final ShreddingContext.FrameKey KEY =
      new ShreddingContext.FrameKey(
          "Widget", "name", TenantId.of("t"), SubjectId.of("victim"), RowId.ofIdentifier(1L));

  private static final ShreddingContext.FrameKey OTHER_KEY =
      new ShreddingContext.FrameKey(
          "Widget", "name", TenantId.of("t"), SubjectId.of("other"), RowId.ofIdentifier(2L));

  @AfterEach
  void leaveTheThreadClean() {
    while (ShreddingContext.inReadBracket()) {
      ShreddingContext.discardRegion(-1L);
    }
  }

  // -- change 2, first case: a thread that has never entered ----------------------------------

  /**
   * The epoch {@link ThreadLocal} has to start somewhere, and a raw {@code openRegion()} on a fresh
   * or pooled-but-never-bracketed thread must not stamp that starting value: {@code recordDecoded}
   * would compare it against itself, find them equal, and authorise. The starting value is a
   * distinguished {@code NO_ENTRY} that no entry ever assigns, and a region access with it in force
   * is refused whatever is on the deque.
   */
  @Test
  void probe_a_raw_open_region_on_a_thread_that_never_entered_is_refused() throws Exception {
    var failure = new Throwable[1];
    Thread fresh =
        new Thread(
            () -> {
              long region = ShreddingContext.openRegion();
              try {
                assertThatThrownBy(() -> ShreddingContext.recordDecoded(KEY, secret("STALE")))
                    .isInstanceOfSatisfying(
                        ShreddingException.class,
                        e -> assertThat(e.code()).isEqualTo(ErrorCodes.READ_UNSCOPED));
              } catch (Throwable t) {
                failure[0] = t;
              } finally {
                ShreddingContext.discardRegion(region);
              }
            },
            "never-entered");
    fresh.start();
    fresh.join();
    if (failure[0] != null) {
      throw new AssertionError(failure[0]);
    }
  }

  // -- change 2, second case: a raw region opened from inside a call ---------------------------

  /**
   * S-4 itself. A user {@code @PostLoad} method, an {@code @EntityListeners} bean or a hand-written
   * DAO reached from a repository default method all run with a real epoch in force; a region they
   * open sits on top of the deque and would otherwise take every remaining decode of that call and
   * hand it back at drain time. It carries no entry epoch, so all four accesses refuse it - and
   * they refuse rather than falling through to the perfectly valid entry region underneath.
   */
  @Test
  void probe_a_raw_open_region_opened_inside_an_entry_serves_nothing() {
    ShreddingContext.withReadBracket(
        () -> {
          ShreddingContext.recordDecoded(KEY, secret("ENTRY-OWN"));
          long raw = ShreddingContext.openRegion();
          try {
            assertThatThrownBy(() -> ShreddingContext.recordDecoded(OTHER_KEY, secret("SMUGGLED")))
                .isInstanceOfSatisfying(
                    ShreddingException.class,
                    e -> assertThat(e.code()).isEqualTo(ErrorCodes.READ_UNSCOPED));
            // change 4: the same predicate at every access, not only at recordDecoded.
            assertThat(ShreddingContext.drain(KEY)).isEmpty();
            assertThat(ShreddingContext.pendingKeysFor("Widget", "name")).isEmpty();
          } finally {
            ShreddingContext.discardRegion(raw);
          }
          // and the entry's own region is untouched by any of it.
          assertThat(drained(KEY)).isEqualTo("ENTRY-OWN");
          return null;
        });
  }

  /** A region that could never serve a decode may not be closed as though it had. */
  @Test
  void probe_closing_a_region_opened_outside_any_entry_is_refused() {
    long raw = ShreddingContext.openRegion();
    assertThatThrownBy(() -> ShreddingContext.closeRegion(raw))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> assertThat(e.code()).isEqualTo(ErrorCodes.READ_UNVERIFIED));
  }

  // -- change 1, equality: an inner entry's region is not the outer call's ----------------------

  /**
   * Equality, never age. An inner entry's region is newer than the outer call's and an outer call's
   * region is older than the inner one's, and neither may serve the other: the decode belongs to
   * the entry that opened the region it was filed into, full stop. Both directions are one
   * comparison, which is also why a wraparound of the counter cannot invert anything.
   */
  @Test
  void probe_an_inner_entry_and_its_caller_each_serve_only_their_own_decodes() {
    String outerSaw =
        ShreddingContext.withReadBracket(
            () -> {
              ShreddingContext.recordDecoded(KEY, secret("OUTER-VALUE"));
              String innerSaw =
                  ShreddingContext.withReadBracket(
                      () -> {
                        // the outer call's decode is not reachable from in here
                        assertThat(ShreddingContext.drain(KEY)).isEmpty();
                        assertThat(ShreddingContext.pendingKeysFor("Widget", "name")).isEmpty();
                        ShreddingContext.recordDecoded(KEY, secret("INNER-VALUE"));
                        return drained(KEY);
                      });
              assertThat(innerSaw).isEqualTo("INNER-VALUE");
              return drained(KEY);
            });
    // and the outer call's own decode survived the whole nested call and is still its own.
    assertThat(outerSaw).isEqualTo("OUTER-VALUE");
  }

  // -- change 3: the sweep is epoch-conditional, and it is never silent -------------------------

  /**
   * (c)'s sweep, as the complement it is meant to be. A nested entry discards regions on top whose
   * epoch is not the one in force at entry - here the raw region a user callback left behind - and
   * never one whose epoch equals it, which is the outer call's own still-live region. Written
   * unconditionally, the sweep would take the outer region with it: its pending decodes would
   * vanish and the outer close would raise {@code SHRED-READ-UNVERIFIED} on every nested repository
   * call in the application.
   *
   * <p>And it WARNs, with the count and the first {@code entity.field} the way {@code pushBind}
   * already does for a stale write scope. The sweep is the only moment an operator ever learns an
   * undisciplined region existed at all; a silent sweep would be a control nobody can audit.
   */
  @Test
  void probe_a_nested_entry_sweeps_a_foreign_region_loudly_and_spares_the_live_one() {
    var logs = captureWarnings();
    try {
      String outerSaw =
          ShreddingContext.withReadBracket(
              () -> {
                ShreddingContext.recordDecoded(KEY, secret("OUTER-VALUE"));
                long abandoned = ShreddingContext.openRegion(); // a user callback's leftover
                assertThat(abandoned).isPositive();
                String innerSaw =
                    ShreddingContext.withReadBracket(
                        () -> {
                          ShreddingContext.recordDecoded(OTHER_KEY, secret("INNER-VALUE"));
                          return drained(OTHER_KEY);
                        });
                assertThat(innerSaw).isEqualTo("INNER-VALUE");
                return drained(KEY);
              });
      assertThat(outerSaw).isEqualTo("OUTER-VALUE");

      var swept =
          logs.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .map(ILoggingEvent::getFormattedMessage)
              .filter(m -> m.contains("read region(s) left on this thread"))
              .toList();
      assertThat(swept).hasSize(1);
      assertThat(swept.get(0)).contains("dropping 1 read region(s)");
    } finally {
      releaseWarnings(logs);
    }
  }

  // -- change 4, the close half: a failed inner restore refuses the outer region ----------------

  /**
   * The one residue the epoch cannot see through is an inner entry whose close never ran: the epoch
   * it stamped is still in force, so the region it left behind matches it. That state is bounded
   * here - the outer call cannot return successfully through it. Its close finds the epoch in force
   * is not the one its own region was opened under and refuses, rather than handing back a result
   * assembled while an unaccounted region sat on top of its own.
   */
  @Test
  void probe_an_inner_entry_that_never_restored_the_epoch_refuses_its_callers_close() {
    long outer = ShreddingContext.enterRegion();
    long unused = ShreddingContext.enterRegion(); // an inner entry whose close never runs
    assertThat(unused).isPositive();

    assertThatThrownBy(() -> ShreddingContext.closeRegion(outer))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> assertThat(e.code()).isEqualTo(ErrorCodes.READ_UNVERIFIED));

    // and the thread is left with nothing in force: the next read refuses instead of matching.
    assertThat(ShreddingContext.inReadBracket()).isFalse();
    assertThatThrownBy(() -> ShreddingContext.recordDecoded(KEY, secret("LATER")))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> assertThat(e.code()).isEqualTo(ErrorCodes.READ_UNSCOPED));
  }

  // -- helpers ---------------------------------------------------------------------------------

  private static byte[] secret(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static String drained(ShreddingContext.FrameKey key) {
    Optional<byte[]> value = ShreddingContext.drain(key);
    return value.map(b -> new String(b, StandardCharsets.UTF_8)).orElse("NOTHING");
  }

  private static ListAppender<ILoggingEvent> captureWarnings() {
    var logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(ShreddingContext.class);
    var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void releaseWarnings(ListAppender<ILoggingEvent> appender) {
    var logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(ShreddingContext.class);
    logger.detachAppender(appender);
    appender.stop();
  }
}
