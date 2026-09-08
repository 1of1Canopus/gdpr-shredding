package com.housedevinci.shredding.domain;

/**
 * The tenant an encrypted value and its data key belong to. Mandatory everywhere and fails closed:
 * there is no default tenant and no empty-string fallback (control 15).
 */
public record TenantId(String value) implements Comparable<TenantId> {

  public TenantId {
    value = Identifiers.validate("tenant id", value);
  }

  public static TenantId of(String value) {
    return new TenantId(value);
  }

  @Override
  public int compareTo(TenantId o) {
    return value.compareTo(o.value);
  }

  @Override
  public String toString() {
    return value;
  }
}
