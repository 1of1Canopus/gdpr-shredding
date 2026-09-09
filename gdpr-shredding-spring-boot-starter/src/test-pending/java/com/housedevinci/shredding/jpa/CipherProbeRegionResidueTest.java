package com.housedevinci.shredding.jpa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Cipher sixth pass, QUESTIONS #21 and #24, and design item 4.
 *
 * <p>Item 4 reads "drain only under the current region's owner token; a foreign-token entry is
 * discarded and the load refuses", and both open questions rest on it. As built the branch cannot
 * fire: {@code recordDecoded} files into {@code stack.peek()} and stamps the entry with <em>that
 * same region's</em> token, and {@code drain} reads {@code stack.peek()} and compares against
 * <em>that same region's</em> token, so {@code pending.ownerToken() != region.token} is
 * unsatisfiable. {@code CipherProbeBracketUnwindTest
 * .probe_a_decode_filed_in_a_region_an_error_unwound_past_is_never_drained_later} passes because it
 * opens a fresh region first and drains an empty one: it exercises the region <em>stack</em>, never
 * the token.
 *
 * <p>What the token was there to cover is a region that is still on the thread's deque with no
 * owner alive - the state #21 describes. Cipher could not reproduce that state from a {@code
 * StackOverflowError}: measured 0/200 nested and 0/200 single-level, because {@code
 * ShreddingContext.unwindTo} pops every region above the token it is given, so the outermost
 * surviving {@code finally} reclaims all the inner ones. The state is reachable the other way -
 * {@code openRegion()} is public on a published class and nothing pairs it with a close - and both
 * probes below build it that way rather than pretending an {@code Error} produced it.
 */
class CipherProbeRegionResidueTest {

  private static final ShreddingContext.FrameKey KEY =
      new ShreddingContext.FrameKey(
          "Widget", "name", TenantId.of("t"), SubjectId.of("victim"), RowId.ofIdentifier(1L));

  /**
   * R1. A read that opens no region of its own - a bare {@code EntityManager} call, a hand-written
   * DAO, a {@code Stream} drained after the repository call returned, an {@code @Async}
   * continuation - must be refused with {@code SHRED-READ-UNSCOPED} (item 1). With an ownerless
   * region on the deque it is not: {@code recordDecoded} finds that region on top and files into
   * it, and {@code onPostLoad} then drains it under a matching token and installs.
   */
  @Test
  void probe_a_decode_with_no_region_of_its_own_is_refused_even_when_an_ownerless_region_is_open() {
    onOwnerlessRegion(
        () ->
            assertThatThrownBy(
                    () ->
                        ShreddingContext.recordDecoded(
                            KEY, "FRESH".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(ShreddingException.class)
                .hasMessageContaining("SHRED-READ-UNSCOPED"));
  }

  /**
   * R2. And #21's stated boundary - "a leaked region can cost a refusal, never a value" - does not
   * hold either. {@code drain} takes {@code entries.remove(0)}, the <em>oldest</em> entry under the
   * key, and the ownerless region already holds one for this exact (entity, field, tenant, subject,
   * row). The value installed into the row is then the stale plaintext that region decrypted, not
   * the one the current read just took out of the column: a value rectified under Article 16 keeps
   * being served as the row's own for as long as the pooled thread lives, and every check downstream
   * agrees with it because the row, subject, tenant and field all match.
   */
  @Test
  void probe_a_stale_decode_in_an_ownerless_region_is_not_installed_over_the_fresh_one() {
    onOwnerlessRegion(
        () -> {
          try {
            ShreddingContext.recordDecoded(KEY, "FRESH".getBytes(StandardCharsets.UTF_8));
          } catch (ShreddingException expected) {
            return; // R1's refusal; then there is nothing to install and this probe is moot.
          }
          String installed =
              ShreddingContext.drain(KEY)
                  .map(b -> new String(b, StandardCharsets.UTF_8))
                  .orElse("NOTHING");
          System.out.println("R2 installed value -> " + installed);
          assertThat(installed).isNotEqualTo("STALE-SECRET");
        });
  }

  /** Opens a region, files {@code STALE-SECRET} in it, abandons it, then runs {@code body}. */
  private static void onOwnerlessRegion(Runnable body) {
    long abandoned = ShreddingContext.openRegion();
    ShreddingContext.recordDecoded(KEY, "STALE-SECRET".getBytes(StandardCharsets.UTF_8));
    try {
      assertThat(ShreddingContext.inReadBracket()).isTrue();
      body.run();
    } finally {
      ShreddingContext.discardRegion(abandoned);
    }
  }
}
