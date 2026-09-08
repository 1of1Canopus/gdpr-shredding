package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;

/**
 * A {@code LocalDate} field, stored as its ISO-8601 text.
 *
 * <p>There is no {@code LocalDate} that can stand for "erased", so the sentinel policy cannot
 * apply: an erased date reads as {@code null} whatever {@code shredding.erased-value.policy} says.
 * That is stated here and in the docs rather than hidden, because a date field is exactly where a
 * silent {@code null} would be mistaken for "never filled in".
 */
public abstract class ShreddedLocalDateConverter extends ShreddedConverter<LocalDate> {

  protected ShreddedLocalDateConverter(String entity, String field) {
    super(entity, field);
  }

  @Override
  protected byte[] toBytes(LocalDate attribute) {
    return attribute.toString().getBytes(StandardCharsets.UTF_8);
  }

  @Override
  protected LocalDate fromBytes(byte[] plaintext) {
    try {
      return LocalDate.parse(new String(plaintext, StandardCharsets.UTF_8));
    } catch (DateTimeParseException e) {
      throw new ShreddingException(
          ErrorCodes.FORMAT, "a decrypted value in " + entity() + "." + field() + " is not a date");
    }
  }

  @Override
  protected LocalDate erasedSentinel() {
    return null;
  }

  /** No date can stand for "erased"; see {@link ShreddedConverter#carriesSentinel()}. */
  @Override
  public boolean carriesSentinel() {
    return false;
  }

  @Override
  protected boolean isErasedSentinel(LocalDate attribute) {
    return false;
  }
}
