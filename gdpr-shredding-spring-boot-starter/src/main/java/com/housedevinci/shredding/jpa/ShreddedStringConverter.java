package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.ErasedValue;
import java.nio.charset.StandardCharsets;

/** A {@code String} field. Extend it once per shredded field. */
public abstract class ShreddedStringConverter extends ShreddedConverter<String> {

  protected ShreddedStringConverter(String entity, String field) {
    super(entity, field);
  }

  @Override
  protected byte[] toBytes(String attribute) {
    return attribute.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  protected String fromBytes(byte[] plaintext) {
    return new String(plaintext, StandardCharsets.UTF_8);
  }

  @Override
  protected String erasedSentinel() {
    return ErasedValue.MARKER;
  }

  @Override
  protected boolean isErasedSentinel(String attribute) {
    return isStringMarker(attribute);
  }

  /** Design §1.1: the marker this type reads as until onPostLoad installs the value. */
  @Override
  protected String placeholder() {
    return Placeholders.STRING;
  }
}
