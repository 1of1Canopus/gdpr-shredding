package com.housedevinci.shredding.domain;

import java.time.Instant;
import java.util.Objects;

/**
 * A per-(tenant, subject, version) data key as it lives in the key store: wrapped, never in the
 * clear.
 *
 * <p>The key material is <em>random</em>, 256 bits from {@code SecureRandom}, never derived from
 * the master key (control 1). A {@code HKDF(master, subjectId)} design would leave the key
 * re-derivable forever by anyone holding the master, which makes erasure a no-op and the whole
 * product a lie.
 *
 * @param tenant owning tenant
 * @param subject data subject
 * @param version key version, from 1; a new version is minted when the encryption counter runs out
 * @param wrappedKey the data key sealed under the master key with AAD {@code
 *     tenant|subject|version}
 * @param state lifecycle
 * @param encryptionCount how many values this key has encrypted (control 3)
 * @param createdAt when the key was minted, truncated to {@link ErasureRecord#STORAGE_PRECISION} so
 *     a key held in memory and the same key read back out of its column are equal
 */
public record DataKey(
    TenantId tenant,
    SubjectId subject,
    int version,
    byte[] wrappedKey,
    KeyState state,
    long encryptionCount,
    Instant createdAt) {

  public DataKey {
    Objects.requireNonNull(tenant, "tenant");
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(state, "state");
    createdAt =
        Objects.requireNonNull(createdAt, "createdAt").truncatedTo(ErasureRecord.STORAGE_PRECISION);
    if (version < 1) {
      throw new ShreddingException(ErrorCodes.INVALID, "key version must be >= 1, was " + version);
    }
    if (encryptionCount < 0) {
      throw new ShreddingException(ErrorCodes.INVALID, "encryption count must be >= 0");
    }
    wrappedKey = Objects.requireNonNull(wrappedKey, "wrappedKey").clone();
  }

  @Override
  public byte[] wrappedKey() {
    return wrappedKey.clone();
  }

  /** Value equality on the wrapped bytes, not array identity. */
  @Override
  public boolean equals(Object o) {
    return o instanceof DataKey d
        && version == d.version
        && encryptionCount == d.encryptionCount
        && tenant.equals(d.tenant)
        && subject.equals(d.subject)
        && state == d.state
        && createdAt.equals(d.createdAt)
        && java.util.Arrays.equals(wrappedKey, d.wrappedKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        tenant,
        subject,
        version,
        state,
        encryptionCount,
        createdAt,
        java.util.Arrays.hashCode(wrappedKey));
  }

  /** Never prints the wrapped bytes. */
  @Override
  public String toString() {
    return "DataKey[" + tenant + "/" + subject + "/v" + version + " " + state + "]";
  }
}
