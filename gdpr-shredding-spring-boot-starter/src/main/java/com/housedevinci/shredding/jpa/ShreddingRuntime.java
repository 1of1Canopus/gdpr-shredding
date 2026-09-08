package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.application.FieldCipher;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.util.Objects;

/**
 * The one piece of static state in the module, and it exists because Hibernate instantiates {@code
 * AttributeConverter}s itself, outside the application context, with no injection point.
 *
 * <p>It is set once by the auto-configuration and cleared on shutdown. A converter that runs before
 * it is set fails closed rather than encrypting under a half-built configuration.
 */
public final class ShreddingRuntime {

  private static volatile ShreddingRuntime instance;

  private final FieldCipher cipher;
  private final ErasedValuePolicy policy;

  public ShreddingRuntime(FieldCipher cipher, ErasedValuePolicy policy) {
    this.cipher = Objects.requireNonNull(cipher, "cipher");
    this.policy = Objects.requireNonNull(policy, "policy");
  }

  public static void set(ShreddingRuntime runtime) {
    instance = runtime;
  }

  public static void clear() {
    instance = null;
  }

  public static ShreddingRuntime require() {
    ShreddingRuntime current = instance;
    if (current == null) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "GDPR Shredding is not configured yet: a @Shredded field was read or written before the"
              + " auto-configuration finished. Check that gdpr-shredding-spring-boot-starter is on"
              + " the classpath and that shredding.master-key is set.");
    }
    return current;
  }

  public FieldCipher cipher() {
    return cipher;
  }

  public ErasedValuePolicy policy() {
    return policy;
  }
}
