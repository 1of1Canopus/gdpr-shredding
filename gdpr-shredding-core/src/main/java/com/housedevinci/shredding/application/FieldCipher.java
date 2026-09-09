package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.Aad;
import com.housedevinci.shredding.domain.Aes256Gcm;
import com.housedevinci.shredding.domain.EncryptedValue;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.KeyDestroyedException;
import com.housedevinci.shredding.domain.KeyState;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encrypts and decrypts one field value, binding it to tenant, subject, entity, field and key
 * version through the AAD (control 2).
 *
 * <p>Every read and every write checks the key's state (control 7): {@code DESTROYING} and {@code
 * DESTROYED} are refused on both sides, because a read that still succeeds inside the erasure
 * window produces a plaintext copy the erasure record then claims does not exist.
 *
 * <p>The per-key encryption counter is enforced here (control 3): a WARN at 2^31 and a hard refusal
 * at the configured limit, which triggers a rotation to key version n+1 rather than a nonce reuse.
 */
public final class FieldCipher {

  /** 2^32: the point at which a 96-bit random nonce under one key stops being comfortable. */
  public static final long DEFAULT_MAX_ENCRYPTIONS_PER_KEY = 4_294_967_296L;

  /** 2^31: half way, where an operator should still have time to plan a rotation. */
  public static final long WARN_ENCRYPTIONS_PER_KEY = 2_147_483_648L;

  private static final Logger log = LoggerFactory.getLogger(FieldCipher.class);

  private final KeyProvider keys;
  private final DataKeyCache cache;
  private final RandomSource random;
  private final long maxEncryptionsPerKey;

  public FieldCipher(
      KeyProvider keys, DataKeyCache cache, RandomSource random, long maxEncryptionsPerKey) {
    this.keys = Objects.requireNonNull(keys, "keys");
    this.cache = Objects.requireNonNull(cache, "cache");
    this.random = Objects.requireNonNull(random, "random");
    if (maxEncryptionsPerKey < 1 || maxEncryptionsPerKey > DEFAULT_MAX_ENCRYPTIONS_PER_KEY) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "shredding.crypto.max-encryptions-per-key must be 1.."
              + DEFAULT_MAX_ENCRYPTIONS_PER_KEY
              + ", was "
              + maxEncryptionsPerKey);
    }
    this.maxEncryptionsPerKey = maxEncryptionsPerKey;
  }

  /**
   * @return the bytes to store in the {@code bytea} column
   */
  public byte[] encrypt(
      TenantId tenant,
      SubjectId subject,
      RowId rowId,
      String entity,
      String field,
      byte[] plaintext) {
    var current = keys.currentForWrite(tenant, subject);
    refuseUnusable(tenant, subject, current.state());

    long used = keys.recordEncryptions(tenant, subject, current.version(), 1);
    KeyProvider.Unwrapped key = current;
    if (used > maxEncryptionsPerKey) {
      // Not "carry on and hope": a rotation is the only safe answer, and the value about to be
      // written goes under the new version.
      log.warn(
          "shredding: data key v{} reached the per-key encryption limit of {}; rotating to the next"
              + " version. Increase shredding.crypto.max-encryptions-per-key only up to {}.",
          current.version(),
          maxEncryptionsPerKey,
          DEFAULT_MAX_ENCRYPTIONS_PER_KEY);
      key = keys.rotate(tenant, subject);
      refuseUnusable(tenant, subject, key.state());
      keys.recordEncryptions(tenant, subject, key.version(), 1);
    } else if (used == WARN_ENCRYPTIONS_PER_KEY) {
      log.warn(
          "shredding: data key v{} has encrypted {} values; plan a rotation before {}.",
          current.version(),
          used,
          maxEncryptionsPerKey);
    }

    byte[] material = key.key();
    try {
      byte[] aad =
          Aad.forValue(
              tenant, subject, rowId, entity, field, key.version(), EncryptedValue.ALG_AES_256_GCM);
      var sealed = Aes256Gcm.encrypt(material, random.nonce(), plaintext, aad);
      cache.put(tenant, subject, key.version(), material);
      return new EncryptedValue(
              EncryptedValue.FORMAT_VERSION,
              EncryptedValue.ALG_AES_256_GCM,
              key.version(),
              tenant,
              subject,
              rowId,
              sealed.nonce(),
              sealed.ciphertext())
          .encode();
    } finally {
      Aes256Gcm.wipe(material);
    }
  }

  /**
   * @return the plaintext, or empty when the key is gone and the policy is a sentinel
   * @throws KeyDestroyedException when the key is gone and the policy is {@link
   *     ErasedValuePolicy#EXCEPTION}
   * @throws com.housedevinci.shredding.domain.KeyUnavailableException when the key store is down;
   *     never confused with a destroyed key (control 16)
   */
  public Optional<byte[]> decrypt(
      String entity, String field, byte[] stored, ErasedValuePolicy policy) {
    EncryptedValue value = EncryptedValue.decode(stored);
    TenantId tenant = value.tenant();
    SubjectId subject = value.subject();

    Optional<byte[]> cached = cache.get(tenant, subject, value.keyVersion());
    byte[] material;
    if (cached.isPresent()) {
      // The cache is a copy of key material, not of authority: the row still decides whether the
      // key may be used at all (control 7).
      var live = keys.forRead(tenant, subject, value.keyVersion());
      if (live.isEmpty() || !live.get().state().usable()) {
        cache.evict(tenant, subject, value.keyVersion());
        return erased(policy, tenant, subject);
      }
      material = cached.get();
    } else {
      var live = keys.forRead(tenant, subject, value.keyVersion());
      if (live.isEmpty() || !live.get().state().usable()) {
        return erased(policy, tenant, subject);
      }
      material = live.get().key();
      cache.put(tenant, subject, value.keyVersion(), material);
    }

    try {
      byte[] aad =
          Aad.forValue(
              tenant, subject, value.rowId(), entity, field, value.keyVersion(), value.algId());
      return Optional.of(Aes256Gcm.decrypt(material, value.nonce(), value.ciphertext(), aad));
    } finally {
      Aes256Gcm.wipe(material);
    }
  }

  private Optional<byte[]> erased(ErasedValuePolicy policy, TenantId tenant, SubjectId subject) {
    if (policy == ErasedValuePolicy.EXCEPTION) {
      throw new KeyDestroyedException(
          "the data key for this subject has been destroyed; the value cannot be read"
              + " (tenant "
              + tenant
              + ")");
    }
    return Optional.empty();
  }

  private static void refuseUnusable(TenantId tenant, SubjectId subject, KeyState state) {
    if (!state.usable()) {
      throw new ShreddingException(
          ErrorCodes.ERASED,
          "the data key for this subject is "
              + state
              + "; a shredded value cannot be written for an erased subject (tenant "
              + tenant
              + ")");
    }
  }
}
