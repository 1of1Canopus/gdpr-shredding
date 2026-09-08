package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;

/**
 * A {@code BigDecimal} field, stored as its plain-string form so the scale survives the round trip.
 *
 * <p>As with {@link ShreddedLocalDateConverter} there is no {@code BigDecimal} that means "erased":
 * an erased amount reads as {@code null}, and {@code 0} is deliberately not used, because a zero
 * balance is a fact and an erased balance is not.
 */
public abstract class ShreddedBigDecimalConverter extends ShreddedConverter<BigDecimal> {

  protected ShreddedBigDecimalConverter(String entity, String field) {
    super(entity, field);
  }

  @Override
  protected byte[] toBytes(BigDecimal attribute) {
    return attribute.toPlainString().getBytes(StandardCharsets.UTF_8);
  }

  @Override
  protected BigDecimal fromBytes(byte[] plaintext) {
    try {
      return new BigDecimal(new String(plaintext, StandardCharsets.UTF_8));
    } catch (NumberFormatException e) {
      throw new ShreddingException(
          ErrorCodes.FORMAT,
          "a decrypted value in " + entity() + "." + field() + " is not a decimal");
    }
  }

  @Override
  protected BigDecimal erasedSentinel() {
    return null;
  }

  @Override
  protected boolean isErasedSentinel(BigDecimal attribute) {
    return false;
  }
}
