package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.HookOutcome;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Security review of PR 22 (P-1 fix), 2026-10-05. The probe_* tests fail on 8134d70: decodeHooks
 * stops when the running byte count reaches OR PASSES the declared length, and parseInt accepts
 * signs and leading zeros, so a hook_outcomes value that is not what hookMaterial writes still
 * decodes. The hash binds the decoded objects, so the meaning cannot change, but the column is
 * malleable and the "not in canonical form" contract is not enforced. The remaining tests pin the
 * properties the fix must keep (round trip, chain verification across the fix, lone surrogates).
 */
class CipherProbeP1ReviewTest {

  private static String field(String v) {
    return "|" + v.getBytes(StandardCharsets.UTF_8).length + ":" + v;
  }

  private static void assertRefused(String material) {
    assertThatThrownBy(() -> JdbcErasureStore.decodeHooks(material))
        .isInstanceOf(ShreddingException.class);
  }

  @Test
  void probe_length_prefix_ending_inside_a_code_point_is_accepted() {
    // 1 declared, the lock is 4 UTF-8 bytes: the loop overshoots and keeps the whole code point.
    assertRefused("|1:🔒" + field("true") + field(""));
  }

  @Test
  void probe_length_prefix_longer_than_the_material_is_accepted() {
    assertRefused(field("a") + field("true") + "|9:xy");
  }

  @Test
  void probe_non_canonical_length_digits_are_accepted() {
    assertRefused(field("a") + field("true") + "|-1:");
    assertRefused("|+1:a" + field("true") + field(""));
    assertRefused("|01:a" + field("true") + field(""));
  }

  private static ErasureRecord record(List<HookOutcome> hooks) {
    Instant t = Instant.parse("2026-10-05T10:00:00.123456Z");
    return ErasureRecord.of(
        t,
        TenantId.of("t1"),
        "p",
        "ops",
        "art17",
        1,
        1,
        1,
        0,
        ErasureOutcome.COMPLETE,
        hooks,
        t.plusSeconds(86_400));
  }

  @Test
  void non_bmp_names_round_trip_and_a_record_written_before_the_fix_verifies() {
    // Encoder is unchanged by the fix, so a record a 0.1.x writer linked is exactly this one.
    var hooks =
        List.of(
            new HookOutcome("🔒", true, ""),
            new HookOutcome("", false, "😀|4:true"),
            new HookOutcome("a|3:b𐀀", true, "􏿿"));
    ErasureRecord written = ErasureChain.unkeyed().link(record(hooks), ErasureChain.GENESIS);
    String stored = ErasureChain.hookMaterial(written);

    List<HookOutcome> decoded = JdbcErasureStore.decodeHooks(stored);
    assertThat(decoded).isEqualTo(hooks);
    ErasureRecord read =
        new ErasureRecord(
            written.sequence(),
            written.timestamp(),
            written.tenant(),
            written.subjectPseudonym(),
            written.requestedBy(),
            written.reason(),
            written.keysDestroyed(),
            written.entityCount(),
            written.fieldCount(),
            written.blindIndexColumnsCleared(),
            written.outcome(),
            decoded,
            written.backupRetentionUntil(),
            written.chainVersion(),
            written.keyId(),
            written.prevHash(),
            written.hash());
    assertThat(ErasureChain.unkeyed().verify(read, ErasureChain.GENESIS)).isTrue();
  }

  @Test
  void lone_surrogate_is_counted_as_the_replacement_byte_on_both_sides() {
    // String.getBytes(UTF_8) writes '?' for an unpaired surrogate; both encoder and decoder see
    // 1 byte, so the boundary holds. PostgreSQL cannot store the surrogate itself, so the row
    // read back holds '?', and "a\uD800" and "a?" share a hash: writer-side input only.
    var hooks = List.of(new HookOutcome("a\uD800", true, "\uDC00z"));
    String stored = ErasureChain.hookMaterial(record(hooks));
    assertThat(JdbcErasureStore.decodeHooks(stored)).isEqualTo(hooks);
    String asPostgresReturnsIt =
        new String(stored.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    assertThat(JdbcErasureStore.decodeHooks(asPostgresReturnsIt))
        .containsExactly(new HookOutcome("a?", true, "?z"));
    assertThat(ErasureChain.unkeyed().hashOf(record(hooks), ErasureChain.GENESIS))
        .isEqualTo(
            ErasureChain.unkeyed()
                .hashOf(record(List.of(new HookOutcome("a?", true, "?z"))), ErasureChain.GENESIS));
  }
}
