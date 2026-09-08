package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.KeyState;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.Optional;

/**
 * The SPI for where per-subject data keys live. Core ships a JDBC implementation (a keys table
 * wrapped with a master key from the environment) and an in-memory one for tests; Vault, AWS KMS,
 * Azure Key Vault and GCP KMS are Pro adapters.
 *
 * <h2>Contract</h2>
 *
 * <ul>
 *   <li><b>Data keys are random, never derived.</b> An implementation MUST mint a 256-bit key from
 *       a cryptographic random source. A {@code HKDF(master, subjectId)} design would leave every
 *       key re-derivable forever by anyone holding the master, which makes erasure a no-op (control
 *       1).
 *   <li><b>Two failure kinds, never conflated</b> (control 16). {@link
 *       com.housedevinci.shredding.domain.KeyUnavailableException} means the store could not be
 *       reached and the caller should retry; {@link
 *       com.housedevinci.shredding.domain.KeyDestroyedException} means the key is gone for good. An
 *       implementation that reports an outage as a destruction turns a KMS incident into an
 *       apparent completed erasure.
 *   <li><b>No stale-cache fallback and no plaintext fallback</b>, and no property to enable either.
 * </ul>
 */
public interface KeyProvider {

  /** Unwrapped key material plus the state and version it was read under. */
  record Unwrapped(byte[] key, int version, KeyState state) {
    public Unwrapped {
      key = key.clone();
    }

    @Override
    public byte[] key() {
      return key.clone();
    }

    @Override
    public String toString() {
      return "Unwrapped[v" + version + " " + state + "]";
    }
  }

  /**
   * The current key for encryption, minting one if the subject has none yet.
   *
   * @throws com.housedevinci.shredding.domain.ShreddingException {@link
   *     com.housedevinci.shredding.domain.ErrorCodes#ERASED} if the subject's key is DESTROYING or
   *     DESTROYED: a subject that has been erased is never given a fresh key, or the erasure would
   *     silently undo itself on the next write (control 11).
   */
  Unwrapped currentForWrite(TenantId tenant, SubjectId subject);

  /** The key of a given version for decryption, or empty if that version never existed. */
  Optional<Unwrapped> forRead(TenantId tenant, SubjectId subject, int version);

  /**
   * Records that {@code count} more values were encrypted under this key and returns the new total,
   * so the caller can enforce the per-key limit (control 3).
   */
  long recordEncryptions(TenantId tenant, SubjectId subject, int version, int count);

  /** Mints the next version for a subject whose current key is exhausted (control 3). */
  Unwrapped rotate(TenantId tenant, SubjectId subject);

  /** True when the store is reachable; drives the health indicator. */
  boolean healthy();
}
