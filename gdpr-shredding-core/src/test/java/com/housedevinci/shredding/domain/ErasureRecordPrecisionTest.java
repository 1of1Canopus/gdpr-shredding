package com.housedevinci.shredding.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The hashed material must only ever contain values the store can give back unchanged.
 *
 * <p>PostgreSQL's {@code timestamptz} holds microseconds and <em>rounds</em> anything finer, so a
 * nanosecond {@link Instant} comes back as a different value and the recomputed hash no longer
 * matches: the trail reads {@code BROKEN} although nobody touched it. It went unnoticed because
 * macOS's {@code Clock.systemUTC()} is microsecond-precision while Linux's is nanosecond, so it
 * only ever failed on CI.
 */
class ErasureRecordPrecisionTest {

  private static final Instant NANOS = Instant.parse("2026-09-08T10:00:00.123456789Z");

  private static ErasureRecord recordAt(Instant timestamp, Instant backupClearAt) {
    return ErasureRecord.of(
        timestamp,
        TenantId.of("acme"),
        "pseudonym",
        "dpo",
        "art 17",
        1,
        1,
        1,
        0,
        ErasureOutcome.COMPLETE,
        List.of(),
        backupClearAt);
  }

  @Test
  void an_erasure_record_holds_only_microsecond_precision() {
    var record = recordAt(NANOS, NANOS.plus(30, ChronoUnit.DAYS));

    assertThat(record.timestamp()).isEqualTo(Instant.parse("2026-09-08T10:00:00.123456Z"));
    assertThat(record.backupRetentionUntil())
        .isEqualTo(Instant.parse("2026-10-08T10:00:00.123456Z"));
    assertThat(record.timestamp().getNano() % 1000).isZero();
  }

  @Test
  void two_records_differing_below_a_microsecond_hash_identically() {
    var chain = ErasureChain.keyed(new byte[32], "k1");
    // both offsets stay inside the same microsecond as NANOS (.123456|789)
    var a = recordAt(NANOS, NANOS);
    var b = recordAt(NANOS.plusNanos(1), NANOS.plusNanos(200));

    assertThat(chain.hashOf(a, ErasureChain.GENESIS))
        .isEqualTo(chain.hashOf(b, ErasureChain.GENESIS));
  }

  @Test
  void truncation_never_moves_a_timestamp_forward() {
    // Rounding, which is what the database would do on its own, can push an erasure into the
    // future. Truncating cannot.
    assertThat(recordAt(NANOS, NANOS).timestamp()).isBeforeOrEqualTo(NANOS);
  }

  @Test
  void a_record_that_is_already_microsecond_precise_is_unchanged() {
    var exact = Instant.parse("2026-09-08T10:00:00.123456Z");
    assertThat(recordAt(exact, exact).timestamp()).isEqualTo(exact);
  }

  @Test
  void withChain_and_withSequence_keep_the_truncated_values() {
    var record = recordAt(NANOS, NANOS).withChain("prev", "sh2h", "k1", "hash").withSequence(7);

    assertThat(record.timestamp().getNano() % 1000).isZero();
    assertThat(record.backupRetentionUntil().getNano() % 1000).isZero();
  }
}
