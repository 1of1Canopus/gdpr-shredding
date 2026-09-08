package com.housedevinci.shredding.domain;

/**
 * The data subject whose key encrypts a value and whose key an erasure destroys.
 *
 * <p>Captured at first persist and immutable afterwards (control 14): changing it would re-encrypt
 * a row under another subject's key and quietly move it out of the first subject's erasure scope.
 */
public record SubjectId(String value) implements Comparable<SubjectId> {

  public SubjectId {
    value = Identifiers.validate("subject id", value);
  }

  public static SubjectId of(String value) {
    return new SubjectId(value);
  }

  @Override
  public int compareTo(SubjectId o) {
    return value.compareTo(o.value);
  }

  @Override
  public String toString() {
    return value;
  }
}
