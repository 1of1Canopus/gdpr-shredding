package com.housedevinci.shredding.jpa;

/**
 * A JSON document held as a {@code String}. Identical to {@link ShreddedStringConverter} on the
 * wire; it exists so the intent is visible at the mapping and so a future canonicalisation of the
 * JSON has one place to live.
 *
 * <p>The document is encrypted whole. Encrypting per field inside a document would leak its shape
 * and its key names, which are often as identifying as the values.
 */
public abstract class ShreddedJsonConverter extends ShreddedStringConverter {

  protected ShreddedJsonConverter(String entity, String field) {
    super(entity, field);
  }
}
