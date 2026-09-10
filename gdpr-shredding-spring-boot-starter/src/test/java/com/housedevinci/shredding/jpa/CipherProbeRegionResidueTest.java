package com.housedevinci.shredding.jpa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Cipher sixth pass, QUESTIONS #21 and #24, design item 4 - S-4's two probes, promoted from {@code
 * src/test-pending/java} by design addendum 2 and green.
 *
 * <p>What they were written against: a region still on the thread's deque with no owner alive, the
 * state #21 describes. Cipher could not reproduce it from a {@code StackOverflowError} - measured
 * 0/200, because {@code unwindTo} pops every region above the token it is given - and built it the
 * honest way instead, from the public, unpaired {@code openRegion()} that nothing pairs with a
 * close. Both probes keep that construction.
 *
 * <p>What changed under addendum 2: a region carries the <em>entry epoch</em> in force when it was
 * constructed, and {@code openRegion()} stamps the distinguished "no entry in force" value. So the
 * ownerless region can no longer even be armed - R1's helper used to fill it with a decode, and
 * that call is now itself refused, which is a stronger statement of the same property and is
 * asserted as one. R2 therefore builds its armed residue the only way that remains: an inner entry
 * whose close never runs, the {@code StackOverflowError} shape, and asserts what R2 always asserted
 * - that the stale plaintext is never what gets installed.
 */
class CipherProbeRegionResidueTest {

  private static final ShreddingContext.FrameKey KEY =
      new ShreddingContext.FrameKey(
          "Widget", "name", TenantId.of("t"), SubjectId.of("victim"), RowId.ofIdentifier(1L));

  @AfterEach
  void leaveTheThreadClean() {
    while (ShreddingContext.inReadBracket()) {
      ShreddingContext.discardRegion(-1L);
    }
  }

  /**
   * R1. A read that opens no region of its own - a bare {@code EntityManager} call, a hand-written
   * DAO, a {@code Stream} drained after the repository call returned, an {@code @Async}
   * continuation - must be refused with {@code SHRED-READ-UNSCOPED} (item 1). With an ownerless
   * region on the deque it was not: {@code recordDecoded} found that region on top and filed into
   * it, and {@code onPostLoad} then drained it and installed. It is refused now, and so is the
   * filing that armed the region in the first place.
   */
  @Test
  void probe_a_decode_with_no_region_of_its_own_is_refused_even_when_an_ownerless_region_is_open() {
    long abandoned = ShreddingContext.openRegion();
    try {
      assertThat(ShreddingContext.inReadBracket()).isTrue();
      assertThatThrownBy(
              () -> ShreddingContext.recordDecoded(KEY, "FRESH".getBytes(StandardCharsets.UTF_8)))
          .isInstanceOfSatisfying(
              ShreddingException.class,
              e -> assertThat(e.code()).isEqualTo(ErrorCodes.READ_UNSCOPED));
    } finally {
      ShreddingContext.discardRegion(abandoned);
    }
  }

  /**
   * R2. And #21's stated boundary - "a leaked region can cost a refusal, never a value" - did not
   * hold either: {@code drain} took the oldest entry under the key, and the ownerless region held
   * one for this exact (entity, field, tenant, subject, row), so the value installed into the row
   * was the stale plaintext that region decrypted. A value rectified under Article 16 kept being
   * served as the row's own for as long as the pooled thread lived, and every check downstream
   * agreed with it.
   *
   * <p>The residue is built here as an inner entry whose close never ran, which is the only shape
   * that can still hold a decode at all. A later entry files and drains its own decode; the stale
   * one is never handed to it, whether it decrypted something of its own or nothing.
   */
  @Test
  void probe_a_stale_decode_in_an_ownerless_region_is_not_installed_over_the_fresh_one() {
    long stale = ShreddingContext.enterRegion();
    ShreddingContext.recordDecoded(KEY, "STALE-SECRET".getBytes(StandardCharsets.UTF_8));
    assertThat(stale).isPositive();

    long later = ShreddingContext.enterRegion();
    ShreddingContext.recordDecoded(KEY, "FRESH".getBytes(StandardCharsets.UTF_8));
    String installed =
        ShreddingContext.drain(KEY)
            .map(b -> new String(b, StandardCharsets.UTF_8))
            .orElse("NOTHING");
    System.out.println("R2 installed value -> " + installed);
    assertThat(installed).isNotEqualTo("STALE-SECRET").isEqualTo("FRESH");

    // and a call that decrypted nothing of its own is handed nothing, not the leftover.
    long emptyHanded = ShreddingContext.enterRegion();
    assertThat(emptyHanded).isPositive();
    assertThat(ShreddingContext.drain(KEY)).isEmpty();
    assertThat(ShreddingContext.pendingKeysFor("Widget", "name")).isEmpty();

    // and the leftover cannot be closed off as though it had been accounted for.
    assertThatThrownBy(() -> ShreddingContext.closeRegion(later))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> assertThat(e.code()).isEqualTo(ErrorCodes.READ_UNVERIFIED));
  }
}
