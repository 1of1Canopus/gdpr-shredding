package com.housedevinci.shredding.jpa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Cipher, seventh pass (e2c2bdd). Two properties the read-region bookkeeping and the placeholder
 * markers claim and do not have. Both are pure, in-process probes: no Hibernate, no container.
 */
class CipherProbeSeventhPassTest {

  private static final ShreddingContext.FrameKey KEY =
      new ShreddingContext.FrameKey(
          "Widget",
          "name",
          TenantId.of("default"),
          SubjectId.of("owner-1"),
          RowId.ofIdentifier(1L));

  @AfterEach
  void clean() {
    // S-14 (Cipher eighth pass): discardRegion(-1L) no longer empties the deque for a token that
    // is not on it, so this thread's own resetForTests() replaces the loop that used to rely on
    // that behaviour.
    ShreddingContext.resetForTests();
  }

  /**
   * S-7/1. {@code closeRegion} unwinds the deque to its own token and throws {@code
   * SHRED-READ-UNVERIFIED} when <em>its own</em> region still holds a decode nothing drained. Every
   * region it pops on the way there - an inner region whose own close was skipped, which is exactly
   * what {@code C-32}'s {@code StackOverflowError} window and a {@code withReadBracket} body that
   * threw an {@code Error} inside a repository call both leave behind - is dropped by {@code
   * unwindTo} without its pending map ever being looked at.
   *
   * <p>So a decrypted {@code @Shredded} value that no verifier ever installed is discarded in
   * silence on the <em>normal</em> return path of the outer call, and the outer call returns its
   * result. The accounting that {@code SHRED-READ-UNVERIFIED} exists to make loud - "this call
   * decrypted something and nothing proved which row it belonged to" - is simply not performed for
   * any region below the one being closed. {@code discardRegion} may drop unchecked, because the
   * original exception is the failure worth reporting; {@code closeRegion} may not. Built on {@code
   * enterRegion()} (the addendum-2 epoch mechanism's entry point) rather than the deprecated,
   * unpaired {@code openRegion()}, since the inner region here is meant to be a legitimate,
   * epoch-stamped entry whose own close was simply never reached - not an ownerless region (S-4).
   */
  @Test
  void probe_an_inner_regions_undrained_decode_is_discarded_in_silence_by_the_outer_close() {
    long outer = ShreddingContext.enterRegion();
    ShreddingContext.enterRegion(); // an inner entry whose own close never runs
    ShreddingContext.recordDecoded(KEY, "SEVENTH-SECRET".getBytes(StandardCharsets.UTF_8));

    assertThatThrownBy(() -> ShreddingContext.closeRegion(outer))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("Widget.name");
  }

  /**
   * S-7/2. {@code Placeholders.isPlaceholder} was widened to value equality by S-3 (46d6a89) so a
   * value-equal copy of the marker - a Jackson round trip, a {@code new String(...)}, a defensive
   * {@code clone()} - cannot be written back over a live ciphertext. {@code STRING} and {@code
   * BYTES} are 128 random bits per JVM, so no application value collides with them. {@code
   * LOCAL_DATE} and {@code BIG_DECIMAL} are fixed constants, and {@code LOCAL_DATE} is exactly
   * {@link LocalDate#MIN} - an ordinary application value for an open-ended validity range.
   *
   * <p>The class javadoc still claims the property those two constants had before S-3 ("this exact
   * instance - an equal {@code LocalDate.MIN} obtained elsewhere is not this object"), which the
   * code no longer has. The consequence is a false positive in a refusal: an application storing
   * {@code LocalDate.MIN} in a {@code @Shredded LocalDate} field has every insert and update of
   * that entity refused with {@code SHRED-PLACEHOLDER-001}, permanently, with a message that says
   * its own data is this module's marker. A marker that is compared by value has to be as
   * unguessable as {@code STRING} and {@code BYTES} are.
   */
  @Test
  void probe_a_legitimate_local_date_min_is_taken_for_the_read_placeholder() {
    assertThat(Placeholders.isPlaceholder(LocalDate.MIN)).isFalse();
  }
}
