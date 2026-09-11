package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.EncryptedValue;
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
 * protecting - and that pair is exactly what the AAD binds. The alternative (generating a class per
 * field at bootstrap) and why it was not taken for the free core.
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
   * so nobody discovers it from a null pointer (the maintainers' decision). Under the {@code
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
    if (Placeholders.isPlaceholder(attribute)) {
      // Design §1.1, finding item 2. This value never came from the application: it is what
      // convertToEntityAttribute returns while onPostLoad has not yet installed the real one. An
      // entity whose install never ran - a projection into a managed type, a refused load caught
      // and flushed anyway, a detached instance carried across a region - would otherwise write
      // this marker, or under the old design a null, straight over a live ciphertext.
      throw new ShreddingException(
          ErrorCodes.PLACEHOLDER,
          "refusing to write the read placeholder back into "
              + entity
              + "."
              + field
              + ". This instance holds the marker a @Shredded read returns before"
              + " ShreddingEventListener.onPostLoad installs the verified value; persisting it"
              + " would destroy the stored ciphertext. It means the entity was flushed without a"
              + " verified load - a refused load that was caught and the transaction continued, or"
              + " an instance carried outside the read region it was loaded in.");
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
        .encrypt(
            scope.tenantFor(field),
            scope.subject(),
            scope.rowId(),
            entity,
            field,
            toBytes(attribute));
  }

  /**
   * Decrypts, files the plaintext in the open read region, and returns a {@link Placeholders
   * placeholder} - never the value (design §1).
   *
   * <p>Five review passes reached the same shape of finding: whatever thread-local state this
   * method consulted, treating the <em>presence</em> of that state as <em>permission</em> to return
   * plaintext failed the moment the state outlived its owner (C-17, C-18, C-20, C-26, C-33, C-39,
   * C-40). The authority is gone rather than re-accounted for. This method cannot verify anything:
   * it has no session, no entity and no row, and no Hibernate 7.4 hook fires before it. So it
   * accuses - "here is a value that claims to belong to this tenant, subject and row" - and {@code
   * ShreddingEventListener.onPostLoad}, which does know the row, verifies the claim and installs
   * the value over the placeholder.
   *
   * <p>Consequences, all of them deliberate:
   *
   * <ul>
   *   <li>No open region ⇒ {@code SHRED-READ-UNSCOPED}, thrown from {@link
   *       ShreddingContext#recordDecoded} before anything is returned (finding item 1). A
   *       projection, a hand-written DAO, a {@code Stream} drained after the call returned: all
   *       loud.
   *   <li>A decrypt inside a region that no verifier ever installs ⇒ {@code SHRED-READ-UNVERIFIED}
   *       when the region closes, before the caller sees the result.
   *   <li>A value whose header names another subject, tenant or row ⇒ the verifier finds no entry
   *       under the row's own key and refuses, {@code SHRED-SUBJECT-MISMATCH} or {@code
   *       SHRED-ROW-MISMATCH}.
   * </ul>
   */
  @Override
  public final T convertToEntityAttribute(byte[] dbData) {
    if (dbData == null) {
      return null;
    }
    // CIPHER-01: the header is decoded the instant it is available. A v1 blob - one with no row
    // identity at all - is refused here, by EncryptedValue.decode.
    var header = EncryptedValue.decode(dbData);
    var runtime = ShreddingRuntime.require();
    var plaintext = runtime.cipher().decrypt(entity, field, dbData, runtime.policy());
    if (plaintext.isEmpty()) {
      // The key is gone. EXCEPTION already threw inside the cipher; only SENTINEL and NULL reach
      // here, and neither has anything for a verifier to install: an erased value is not a decrypt.
      return runtime.policy() == ErasedValuePolicy.NULL ? null : erasedSentinel();
    }
    ShreddingContext.recordDecoded(
        new ShreddingContext.FrameKey(
            entity, field, header.tenant(), header.subject(), header.rowId()),
        plaintext.get());
    return placeholder();
  }

  /**
   * The marker this converter returns until {@code onPostLoad} installs the verified value. Never
   * {@code null} (finding item 2), always the same instance, always compared by reference identity.
   */
  protected abstract T placeholder();

  /**
   * Decodes a value the verifier is about to install into the entity. Public because the verifier -
   * {@code ShreddingEventListener.onPostLoad} - lives in the auto-configuration package; it is not
   * part of the user-facing API and it decrypts nothing: the plaintext was produced by this
   * converter's own {@code convertToEntityAttribute} and filed in the open read region.
   */
  public final T installable(byte[] plaintext) {
    return fromBytes(plaintext);
  }

  /**
   * Re-encodes a value the {@code IDENTITY} rebind is about to write again (design §3.1). Takes the
   * attribute straight off the insert's state array, so nothing is decrypted to rebind a row.
   */
  @SuppressWarnings("unchecked")
  public final byte[] encodeForRebind(Object attribute) {
    return toBytes((T) attribute);
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
