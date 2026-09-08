package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.ErasedValue;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import jakarta.persistence.AttributeConverter;
import java.util.Objects;

/**
 * Base class for the per-field converters. A concrete subclass names the entity and the field it
 * protects:
 *
 * <pre>{@code
 * @Converter
 * public class CustomerEmailConverter extends ShreddedStringConverter {
 *   public CustomerEmailConverter() {
 *     super("Customer", "email");
 *   }
 * }
 * }</pre>
 *
 * <p>One class per shredded field is the price of using an {@code AttributeConverter} at all:
 * Hibernate resolves a converter through the managed-bean registry, which caches one instance per
 * <em>class</em>, so a single shared converter could not know which entity and field it was
 * protecting - and that pair is exactly what the AAD binds. See QUESTIONS #1 for the alternative
 * (generating a class per field at bootstrap) and why it was not taken for the free core.
 *
 * <p>The startup scan cross-checks every {@code @Shredded} field against the converter that maps it
 * and refuses to start if the names disagree, so a copy-pasted converter cannot silently bind two
 * fields to the same AAD.
 *
 * @param <T> the entity attribute type
 */
public abstract class ShreddedConverter<T> implements AttributeConverter<T, byte[]> {

  private final String entity;
  private final String field;

  protected ShreddedConverter(String entity, String field) {
    this.entity = require(entity, "entity");
    this.field = require(field, "field");
  }

  public final String entity() {
    return entity;
  }

  public final String field() {
    return field;
  }

  /** Encodes the attribute for encryption. Never called with {@code null}. */
  protected abstract byte[] toBytes(T attribute);

  /** Decodes a decrypted value. */
  protected abstract T fromBytes(byte[] plaintext);

  /** What a read returns once the key is gone and the policy is {@code sentinel}. */
  protected abstract T erasedSentinel();

  /** True when the value handed back for writing is the erased sentinel this type reads as. */
  protected abstract boolean isErasedSentinel(T attribute);

  /**
   * Whether this type has a value that can stand for "erased".
   *
   * <p>{@code String} and {@code byte[]} do. {@code LocalDate} and {@code BigDecimal} do not: every
   * date and every number is a legitimate value, and picking {@code 0} or {@code LocalDate.EPOCH}
   * would make an erased amount indistinguishable from a real zero balance. Those fields read as
   * {@code null} under the {@code sentinel} policy, and the startup check WARNs with the full list
   * so nobody discovers it from a null pointer (Dollar's ruling on QUESTIONS #5). Under the {@code
   * exception} policy they throw like every other type.
   */
  public boolean carriesSentinel() {
    return true;
  }

  @Override
  public final byte[] convertToDatabaseColumn(T attribute) {
    if (attribute == null) {
      return null;
    }
    if (isErasedSentinel(attribute)) {
      // Control 11, the belt to the dirty-checking braces: the sentinel round-trips to the
      // identical Java value, so Hibernate should never get here; if anything ever does, it is
      // refused rather than allowed to write a new ciphertext for an erased subject.
      throw new ShreddingException(
          ErrorCodes.ERASED,
          "refusing to encrypt the erased-value sentinel back into "
              + entity
              + "."
              + field
              + ": the subject's key is gone and a fresh value cannot be written for them");
    }
    var scope = ShreddingContext.require(entity, field);
    return ShreddingRuntime.require()
        .cipher()
        .encrypt(scope.tenant(), scope.subject(), entity, field, toBytes(attribute));
  }

  @Override
  public final T convertToEntityAttribute(byte[] dbData) {
    if (dbData == null) {
      return null;
    }
    var runtime = ShreddingRuntime.require();
    var plaintext = runtime.cipher().decrypt(entity, field, dbData, runtime.policy());
    if (plaintext.isPresent()) {
      return fromBytes(plaintext.get());
    }
    // EXCEPTION already threw inside the cipher; only SENTINEL and NULL reach here.
    return runtime.policy() == ErasedValuePolicy.NULL ? null : erasedSentinel();
  }

  private static String require(String value, String what) {
    Objects.requireNonNull(value, what);
    if (value.isBlank()) {
      throw new IllegalArgumentException("@Shredded converter " + what + " must not be blank");
    }
    return value;
  }

  /** Never the value. */
  @Override
  public final String toString() {
    return getClass().getSimpleName() + "[" + entity + "." + field + "]";
  }

  /** Shared by the {@code String}-shaped converters. */
  static boolean isStringMarker(String value) {
    return ErasedValue.MARKER.equals(value);
  }
}
