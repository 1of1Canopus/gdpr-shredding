package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.application.DataKeyCache;
import com.housedevinci.shredding.application.FieldCipher;
import com.housedevinci.shredding.domain.BlindIndex;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Every knob this module has. There is deliberately <b>no fail-open property anywhere</b>: the
 * secure mode is the default, and each weaker mode is an explicit property that logs a WARN at
 * every startup, not only the first.
 */
@ConfigurationProperties(prefix = "shredding")
public class ShreddingProperties {

  /**
   * Base64 master key that wraps every data key. Required, at least 32 bytes, from the environment.
   * No default and none is generated; sample-looking values are refused at startup.
   */
  private String masterKey;

  /**
   * Keeps data keys in the heap and loses them on restart. For local development only; WARNs at
   * every startup while it is on.
   */
  private boolean devMode = false;

  /**
   * Allows a {@code @Shredded} entity to be second-level cached. Off, because a cached entity keeps
   * serving plaintext after the key is destroyed. WARNs at every startup while it is on.
   */
  private boolean allowSecondLevelCache = false;

  private final ErasedValueProperties erasedValue = new ErasedValueProperties();
  private final CryptoProperties crypto = new CryptoProperties();
  private final DataKeyCacheProperties dataKeyCache = new DataKeyCacheProperties();
  private final ErasureLogProperties erasureLog = new ErasureLogProperties();
  private final BlindIndexProperties blindIndex = new BlindIndexProperties();
  private final ErasureProperties erasure = new ErasureProperties();
  private final SubjectPseudonymProperties subjectPseudonym = new SubjectPseudonymProperties();

  public String getMasterKey() {
    return masterKey;
  }

  public void setMasterKey(String masterKey) {
    this.masterKey = masterKey;
  }

  public boolean isDevMode() {
    return devMode;
  }

  public void setDevMode(boolean devMode) {
    this.devMode = devMode;
  }

  public boolean isAllowSecondLevelCache() {
    return allowSecondLevelCache;
  }

  public void setAllowSecondLevelCache(boolean allowSecondLevelCache) {
    this.allowSecondLevelCache = allowSecondLevelCache;
  }

  public ErasedValueProperties getErasedValue() {
    return erasedValue;
  }

  public CryptoProperties getCrypto() {
    return crypto;
  }

  public DataKeyCacheProperties getDataKeyCache() {
    return dataKeyCache;
  }

  public ErasureLogProperties getErasureLog() {
    return erasureLog;
  }

  public BlindIndexProperties getBlindIndex() {
    return blindIndex;
  }

  public ErasureProperties getErasure() {
    return erasure;
  }

  public SubjectPseudonymProperties getSubjectPseudonym() {
    return subjectPseudonym;
  }

  /** What a read returns once the key is gone. One policy per application, never per call. */
  public static class ErasedValueProperties {
    /** {@code sentinel} (default), {@code exception}, or {@code null} (WARNs at every startup). */
    private ErasedValuePolicy policy = ErasedValuePolicy.SENTINEL;

    public ErasedValuePolicy getPolicy() {
      return policy;
    }

    public void setPolicy(ErasedValuePolicy policy) {
      this.policy = policy;
    }
  }

  public static class CryptoProperties {
    /** Values one data key may encrypt before it is rotated. Cannot be raised above 2^32. */
    private long maxEncryptionsPerKey = FieldCipher.DEFAULT_MAX_ENCRYPTIONS_PER_KEY;

    public long getMaxEncryptionsPerKey() {
      return maxEncryptionsPerKey;
    }

    public void setMaxEncryptionsPerKey(long maxEncryptionsPerKey) {
      this.maxEncryptionsPerKey = maxEncryptionsPerKey;
    }
  }

  public static class DataKeyCacheProperties {
    /** How long a node may hold an unwrapped data key. Also the erasure's cross-node window. */
    private Duration ttl = DataKeyCache.DEFAULT_TTL;

    /** How many unwrapped data keys a node may hold. */
    private int maxSize = DataKeyCache.DEFAULT_MAX_SIZE;

    public Duration getTtl() {
      return ttl;
    }

    public void setTtl(Duration ttl) {
      this.ttl = ttl;
    }

    public int getMaxSize() {
      return maxSize;
    }

    public void setMaxSize(int maxSize) {
      this.maxSize = maxSize;
    }
  }

  public static class ErasureLogProperties {
    /**
     * HMAC secret for the erasure chain, at least 32 bytes. Required unless {@code unkeyed=true}.
     * It is not a data key and is never destroyed by an erasure: destroying it would break the
     * record that proves the erasure.
     */
    private String hmacSecret;

    /** Key id written into the hashed material of every row. */
    private String hmacKeyId = "k1";

    /** Every key id that may have signed a row, for verification across a rotation. */
    private Map<String, String> hmacKeys = new LinkedHashMap<>();

    /** Runs the chain unkeyed. A loud opt-out: WARNs at every startup. */
    private boolean unkeyed = false;

    public String getHmacSecret() {
      return hmacSecret;
    }

    public void setHmacSecret(String hmacSecret) {
      this.hmacSecret = hmacSecret;
    }

    public String getHmacKeyId() {
      return hmacKeyId;
    }

    public void setHmacKeyId(String hmacKeyId) {
      this.hmacKeyId = hmacKeyId;
    }

    public Map<String, String> getHmacKeys() {
      return hmacKeys;
    }

    public void setHmacKeys(Map<String, String> hmacKeys) {
      this.hmacKeys = hmacKeys;
    }

    public boolean isUnkeyed() {
      return unkeyed;
    }

    public void setUnkeyed(boolean unkeyed) {
      this.unkeyed = unkeyed;
    }
  }

  public static class BlindIndexProperties {
    /** Its own secret, never the data key or the chain material. Required if any @BlindIndex. */
    private String hmacSecret;

    /** Index width. A prefilter: the query path always re-verifies by decrypting. */
    private int bits = BlindIndex.DEFAULT_BITS;

    public String getHmacSecret() {
      return hmacSecret;
    }

    public void setHmacSecret(String hmacSecret) {
      this.hmacSecret = hmacSecret;
    }

    public int getBits() {
      return bits;
    }

    public void setBits(int bits) {
      this.bits = bits;
    }
  }

  /**
   * CIPHER-07: the pepper for the subject pseudonym when the erasure log itself runs unkeyed. The
   * two are independent (control 9's chain-integrity secret is not the same secret as its
   * pseudonym-hardness secret): {@code shredding.erasure-log.unkeyed=true} says nothing signs the
   * chain, but the pseudonym still has to be unrecoverable without a secret, or an unkeyed log's
   * subject column is an HMAC anyone can recompute from the module's own published constant.
   */
  public static class SubjectPseudonymProperties {
    /**
     * Base64, at least 32 bytes, from the environment. Required whenever {@code
     * shredding.erasure-log.unkeyed=true}; startup refuses to start without it. Ignored, and not
     * required, when the erasure log is keyed - the chain's own HMAC secret is the pseudonym pepper
     * in that mode, exactly as before.
     */
    private String pepper;

    public String getPepper() {
      return pepper;
    }

    public void setPepper(String pepper) {
      this.pepper = pepper;
    }
  }

  public static class ErasureProperties {
    /**
     * How long backups, PITR archives and WAL keep a copy of the wrapped key. The erasure is
     * complete only at {@code erasedAt + this}, and the proof of erasure prints that date.
     */
    private Duration backupRetention = Duration.ofDays(30);

    public Duration getBackupRetention() {
      return backupRetention;
    }

    public void setBackupRetention(Duration backupRetention) {
      this.backupRetention = backupRetention;
    }
  }
}
