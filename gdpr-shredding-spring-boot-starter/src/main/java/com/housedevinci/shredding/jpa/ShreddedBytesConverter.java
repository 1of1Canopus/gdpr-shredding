package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.ErasedValue;

/**
 * A {@code byte[]} field. The erased sentinel is the shared empty array, compared by identity, so a
 * genuine empty value is never mistaken for an erasure.
 */
public abstract class ShreddedBytesConverter extends ShreddedConverter<byte[]> {

  protected ShreddedBytesConverter(String entity, String field) {
    super(entity, field);
  }

  @Override
  protected byte[] toBytes(byte[] attribute) {
    return attribute.clone();
  }

  @Override
  protected byte[] fromBytes(byte[] plaintext) {
    return plaintext;
  }

  @Override
  protected byte[] erasedSentinel() {
    return ErasedValue.BYTES_MARKER;
  }

  @Override
  protected boolean isErasedSentinel(byte[] attribute) {
    return attribute == ErasedValue.BYTES_MARKER;
  }
}
