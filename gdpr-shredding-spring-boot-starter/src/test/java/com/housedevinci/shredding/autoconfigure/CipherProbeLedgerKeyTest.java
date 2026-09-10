package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.math.BigDecimal;
import org.junit.jupiter.api.Test;

/**
 * Cipher, seventh pass (e2c2bdd). {@code WriteVerification} identifies a written row by {@code
 * (entityName, normalise(id))} - both in the ledger's own key, where a collision <em>drops</em> a
 * debt, and in the settlement result map, where a collision verifies one row's debt against another
 * row's stored bytes.
 *
 * <p>{@code normalise} maps every {@link Number} through {@code longValue()}. JPA permits a {@code
 * BigDecimal}, {@code Double} or {@code Float} identifier, and for those {@code longValue()} is
 * lossy: {@code 1} and {@code 1.5} are one key. Two rows of one entity whose ids differ only below
 * the decimal point therefore share a ledger entry - {@code owe} is a {@code Map.put}, so the
 * second silently replaces the first - and the row whose debt was replaced commits with its stored
 * header never compared against anything. That is S-1's property, reopened by an identifier type.
 *
 * <p>Reflection because {@code normalise} is private; the collision is the finding, not the access
 * path. The fix is a normalisation that is injective over every identifier type JPA allows: exact
 * for integral values, {@code BigDecimal#toPlainString} or equivalent for the rest, never a
 * truncation.
 */
class CipherProbeLedgerKeyTest {

  @Test
  void probe_two_distinct_numeric_identifiers_collide_in_the_settlement_ledger() throws Exception {
    Method normalise = WriteVerification.class.getDeclaredMethod("normalise", Object.class);
    normalise.setAccessible(true);

    Object one = normalise.invoke(null, BigDecimal.ONE);
    Object oneAndAHalf = normalise.invoke(null, new BigDecimal("1.5"));

    assertThat(oneAndAHalf).isNotEqualTo(one);
  }
}
