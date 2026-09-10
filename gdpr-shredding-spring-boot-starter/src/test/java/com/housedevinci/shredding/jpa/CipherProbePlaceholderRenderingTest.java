package com.housedevinci.shredding.jpa;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Cipher, eighth pass (fa6f477). S-17 (INFO), and the prescription that caused it is Cipher's own:
 * the seventh pass told S-10 to draw {@code BIG_DECIMAL} "at a scale of the order of 10^6".
 *
 * <p>The unguessability of the marker comes from the 64 random bits of the unscaled value, not from
 * the exponent - but the exponent decides what the marker <em>renders</em> as. {@code toString()}
 * is 29 characters (scientific notation); {@code toPlainString()} is 1 000 559. A refused load is
 * documented to leave the marker in a detached entity and to have it copied around by ordinary
 * application code - a DTO round trip, a log line, a JSON body - and any of those that reaches
 * {@code toPlainString()} (Jackson with {@code WRITE_BIGDECIMAL_AS_PLAIN}, a {@code DecimalFormat},
 * a {@code String.format("%f", ...)}) turns one refused field into a megabyte, and a refused page
 * of two hundred rows into two hundred of them. A scale in the low thousands is just as implausible
 * for real data and costs nothing to render.
 */
class CipherProbePlaceholderRenderingTest {

  @Test
  void probe_the_big_decimal_placeholder_renders_in_a_bounded_number_of_characters() {
    assertThat(Placeholders.BIG_DECIMAL.toPlainString().length())
        .describedAs("characters produced by rendering this module's own BigDecimal marker")
        .isLessThan(4096);
  }

  @Test
  void probe_the_big_decimal_placeholder_still_carries_its_random_bits() {
    // The property S-10 actually needs, kept explicit so the fix cannot shrink the wrong thing.
    assertThat(Placeholders.BIG_DECIMAL.unscaledValue().bitLength()).isGreaterThan(32);
    assertThat(Placeholders.isPlaceholder(Placeholders.BIG_DECIMAL)).isTrue();
    assertThat(Placeholders.isPlaceholder(new java.math.BigDecimal("1.50"))).isFalse();
  }
}
