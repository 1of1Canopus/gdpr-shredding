package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.EncryptedValue;
import com.housedevinci.shredding.domain.ErasedValue;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import jakarta.persistence.AttributeConverter;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

  private static final Logger log = LoggerFactory.getLogger(ShreddedConverter.class);

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
    // CIPHER-01: record what the header actually says the instant it is decoded, so
    // ShreddingEventListener.onPostLoad can compare it against the row's true subject once the
    // whole entity is hydrated and refuse before the value is handed to any caller. See
    // ShreddingContext.Decoded for why this cannot be checked earlier than that.
    var header = EncryptedValue.decode(dbData);
    // CIPHER-11: the header-versus-row check now lives here, at the one place every decrypt goes
    // through, not only on the entity-load event. Three cases:
    //   1. An explicit read scope is present (ShreddingContext.withRead) - a caller vouching for
    //      this row's subject/tenant, typically a projection that cannot be verified any other
    //      way. Checked atomically, right now, before this method returns anything.
    //   2. No explicit scope, but the read bracket is open - this decrypt is happening inside a
    //      managed entity load (a Spring Data repository call, or an application's own
    //      ShreddingContext.withRead around a raw EntityManager use). Hibernate gives no hook
    //      earlier than this one to verify against here, so verification is deferred to
    //      onPostLoad/refuseIfSubjectMoved once the row is fully hydrated - the same relaxation
    //      Cipher accepted for entity loads under QUESTIONS #13.
    //   3. Neither: a projection, a native query, a detached use, or an EntityManager call made
    //      outside any repository or explicit scope. Nothing here can be verified against, so this
    //      is refused rather than decrypted and handed back unverified. This is CIPHER-11's actual
    //      repro (`select d.title from Doc d ...`).
    var explicitReadScope = ShreddingContext.currentReadScope();
    if (explicitReadScope.isPresent()) {
      var scope = explicitReadScope.get();
      boolean subjectMismatch = !header.subject().equals(scope.subject());
      boolean tenantMismatch = !header.tenant().equals(scope.tenant());
      if (subjectMismatch || tenantMismatch) {
        log.warn(
            "shredding: refusing to decrypt {}.{}: the stored value's header names a different"
                + " {} than the caller-supplied read scope",
            entity,
            field,
            subjectMismatch ? "subject" : "tenant");
        throw subjectMismatchError(subjectMismatch);
      }
    } else if (!ShreddingContext.inReadBracket()) {
      log.warn(
          "shredding: refusing to decrypt {}.{}: no read scope at all - not a managed entity load"
              + " and not an explicit ShreddingContext.withRead(...)",
          entity,
          field);
      throw new ShreddingException(
          ErrorCodes.READ_UNSCOPED,
          "no read scope while decrypting "
              + entity
              + "."
              + field
              + ". A @Shredded field can only be decrypted through a managed entity load (a Spring"
              + " Data repository call, or a raw EntityManager entity operation - find, merge,"
              + " refresh, an entity-returning query - wrapped in"
              + " ShreddingContext.withReadBracket(...)) or an explicit read scope"
              + " (ShreddingContext.withRead(...)). A scalar, Tuple or constructor-expression"
              + " projection has neither by default and is refused rather than decrypted with"
              + " nothing to verify its header against.");
    }
    ShreddingContext.recordDecoded(entity + "." + field, header.tenant(), header.subject());
    var runtime = ShreddingRuntime.require();
    var plaintext = runtime.cipher().decrypt(entity, field, dbData, runtime.policy());
    if (plaintext.isPresent()) {
      return fromBytes(plaintext.get());
    }
    // EXCEPTION already threw inside the cipher; only SENTINEL and NULL reach here.
    return runtime.policy() == ErasedValuePolicy.NULL ? null : erasedSentinel();
  }

  private ShreddingException subjectMismatchError(boolean subjectMismatch) {
    return new ShreddingException(
        ErrorCodes.SUBJECT_MISMATCH,
        "the stored value for "
            + entity
            + "."
            + field
            + " belongs to a different "
            + (subjectMismatch ? "subject" : "tenant")
            + " than the read scope it was read under. A ciphertext moved between rows, subjects or"
            + " tenants is refused rather than decrypted and displayed.");
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
