package com.housedevinci.shredding.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.adapter.memory.InMemoryKeyProvider;
import com.housedevinci.shredding.domain.EncryptedValue;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.KeyDestroyedException;
import com.housedevinci.shredding.domain.KeyUnavailableException;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Cipher probes on the value path: AAD binding, key-store outage, tenant isolation, key limits. */
class CipherProbeFieldCipherTest {

  /** Design §3: every stored value is bound to a row; these probes use one fixed row. */
  private static final RowId ROW = RowId.ofIdentifier(1L);

  private static final TenantId A = TenantId.of("tenant-a");
  private static final TenantId B = TenantId.of("tenant-b");
  private static final SubjectId SUBJECT = SubjectId.of("s-1");
  private static final byte[] PLAINTEXT = "alice@example.com".getBytes(StandardCharsets.UTF_8);

  private InMemoryKeyProvider keys;
  private DataKeyCache cache;
  private FieldCipher cipher;

  @BeforeEach
  void setUp() {
    keys = new InMemoryKeyProvider(RandomSource.secure(), true);
    cache = new DataKeyCache(Duration.ofSeconds(60), 100, Clock.systemUTC());
    cipher =
        new FieldCipher(
            keys, cache, RandomSource.secure(), FieldCipher.DEFAULT_MAX_ENCRYPTIONS_PER_KEY);
  }

  /**
   * A ciphertext lifted out of one row and dropped into another must not decrypt. Without the
   * subject and the field in the AAD, a customer-support row and a customer row hold
   * interchangeable blobs and moving one is undetectable.
   */
  @Test
  void probe_ciphertext_moved_between_rows_still_decrypts() {
    byte[] stored = cipher.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);

    // same tenant and subject, different field: the row it was moved into
    assertThatThrownBy(
            () -> cipher.decrypt("Customer", "phone", stored, ErasedValuePolicy.SENTINEL))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.DECRYPT);

    // same field, different entity
    assertThatThrownBy(
            () -> cipher.decrypt("Supplier", "email", stored, ErasedValuePolicy.SENTINEL))
        .isInstanceOf(ShreddingException.class);

    // and the row it belongs to still reads
    assertThat(cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.SENTINEL))
        .get()
        .isEqualTo(PLAINTEXT);
  }

  /**
   * The same subject id under two tenants is two subjects. If tenant B can read tenant A's value
   * the erasure scope is wrong too: erasing the subject in A would leave B's copy readable.
   */
  @Test
  void probe_tenant_b_decrypts_tenant_a_value_for_the_same_subject_id() {
    byte[] storedForA = cipher.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);
    byte[] storedForB = cipher.encrypt(B, SUBJECT, ROW, "Customer", "email", PLAINTEXT);

    assertThat(storedForA).isNotEqualTo(storedForB);
    assertThat(EncryptedValue.decode(storedForA).tenant()).isEqualTo(A);

    // rewrite A's blob to claim tenant B, the way a row copied between schemas would
    var a = EncryptedValue.decode(storedForA);
    byte[] relabelled =
        new EncryptedValue(
                a.formatVersion(),
                a.algId(),
                a.keyVersion(),
                B,
                a.subject(),
                a.rowId(),
                a.nonce(),
                a.ciphertext())
            .encode();

    assertThatThrownBy(
            () -> cipher.decrypt("Customer", "email", relabelled, ErasedValuePolicy.SENTINEL))
        .isInstanceOf(ShreddingException.class);
  }

  /**
   * CIPHER-10 / M8. The probe above is honest but does not test what its name claims: relabelling
   * the header's tenant makes {@code MasterKey.unwrap} fail on the <em>wrap</em> AAD before {@code
   * Aad.forValue} - the value AAD control 2 requires tenant to be in - is ever reached. With {@code
   * tenant} removed from {@code Aad.forValue} that probe stays green, because tenant A and tenant B
   * never share key material in the normal case, so *something* always fails regardless of which
   * AAD carries the tenant.
   *
   * <p>To isolate the value AAD specifically, this test uses a {@link KeyProvider} that hands back
   * the <em>same</em> key material for every tenant - the one variable the wrap layer can no longer
   * explain a failure with - and then rewrites only the header's tenant on a blob whose nonce and
   * ciphertext are untouched. If {@code Aad.forValue} did not bind tenant, GCM authentication would
   * succeed: same key, same nonce, same ciphertext, same AAD but for the tenant component. It must
   * fail.
   */
  @Test
  void probe_value_aad_binds_tenant_independently_of_the_wrap_layer() {
    byte[] sharedKey = new byte[32];
    java.util.Arrays.fill(sharedKey, (byte) 0x42);
    KeyProvider sameKeyForEveryTenant =
        new KeyProvider() {
          @Override
          public Unwrapped currentForWrite(TenantId tenant, SubjectId subject) {
            return new Unwrapped(sharedKey, 1, com.housedevinci.shredding.domain.KeyState.ACTIVE);
          }

          @Override
          public java.util.Optional<Unwrapped> forRead(
              TenantId tenant, SubjectId subject, int version) {
            return java.util.Optional.of(
                new Unwrapped(sharedKey, 1, com.housedevinci.shredding.domain.KeyState.ACTIVE));
          }

          @Override
          public long recordEncryptions(
              TenantId tenant, SubjectId subject, int version, int count) {
            return 1;
          }

          @Override
          public Unwrapped rotate(TenantId tenant, SubjectId subject) {
            return new Unwrapped(sharedKey, 1, com.housedevinci.shredding.domain.KeyState.ACTIVE);
          }

          @Override
          public boolean healthy() {
            return true;
          }
        };
    var isolatedCache = new DataKeyCache(Duration.ofSeconds(60), 100, Clock.systemUTC());
    var isolatedCipher =
        new FieldCipher(
            sameKeyForEveryTenant,
            isolatedCache,
            RandomSource.secure(),
            FieldCipher.DEFAULT_MAX_ENCRYPTIONS_PER_KEY);

    byte[] storedForA = isolatedCipher.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);
    var a = EncryptedValue.decode(storedForA);
    byte[] relabelledForB =
        new EncryptedValue(
                a.formatVersion(),
                a.algId(),
                a.keyVersion(),
                B,
                a.subject(),
                a.rowId(),
                a.nonce(),
                a.ciphertext())
            .encode();

    // Sanity: with the same key material and the same header otherwise, tenant A's own blob
    // still decrypts - proving the failure below is caused by the tenant change, not by anything
    // else this rewrite might have disturbed.
    assertThat(isolatedCipher.decrypt("Customer", "email", storedForA, ErasedValuePolicy.SENTINEL))
        .get()
        .isEqualTo(PLAINTEXT);

    assertThatThrownBy(
            () ->
                isolatedCipher.decrypt(
                    "Customer", "email", relabelledForB, ErasedValuePolicy.SENTINEL))
        .as(
            "same key material for both tenants: only the value AAD's tenant component can be"
                + " what makes this fail")
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.DECRYPT);
  }

  /**
   * A key store that is merely down must not read as an erasure. Conflating the two turns a KMS
   * outage into an apparent completed erasure, and with the re-encryption refusal in place into a
   * real one.
   */
  @Test
  void probe_key_store_outage_reads_as_erased() {
    byte[] stored = cipher.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);
    cache.evictSubject(A, SUBJECT);
    keys.setAvailable(false);

    assertThatThrownBy(
            () -> cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.SENTINEL))
        .isInstanceOf(KeyUnavailableException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.KEY_UNAVAILABLE);

    assertThat(keys.healthy()).isFalse();
  }

  /** And a genuinely destroyed key does read as erased, under whichever policy is configured. */
  @Test
  void a_destroyed_key_reads_as_erased_under_the_configured_policy() {
    byte[] stored = cipher.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);
    keys.destroy(A, SUBJECT);
    cache.evictSubject(A, SUBJECT);

    assertThat(cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.SENTINEL)).isEmpty();
    assertThatThrownBy(
            () -> cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.EXCEPTION))
        .isInstanceOf(KeyDestroyedException.class);
  }

  /**
   * A GCM key must not encrypt more values than its random 96-bit nonce comfortably allows. The
   * answer is a rotation, not a warning that a busy service will never read.
   */
  @Test
  void probe_encryption_passes_the_per_key_2_32_limit() {
    var small = new FieldCipher(keys, cache, RandomSource.secure(), 3);

    byte[] first = small.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);
    small.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);
    small.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);
    byte[] afterLimit = small.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);

    assertThat(EncryptedValue.decode(first).keyVersion()).isEqualTo(1);
    assertThat(EncryptedValue.decode(afterLimit).keyVersion()).isEqualTo(2);
    // both versions still read: rotation is not a data loss
    assertThat(small.decrypt("Customer", "email", first, ErasedValuePolicy.SENTINEL)).isPresent();
    assertThat(small.decrypt("Customer", "email", afterLimit, ErasedValuePolicy.SENTINEL))
        .isPresent();
  }

  @Test
  void a_limit_above_2_32_is_refused_at_construction() {
    assertThatThrownBy(
            () ->
                new FieldCipher(
                    keys,
                    cache,
                    RandomSource.secure(),
                    FieldCipher.DEFAULT_MAX_ENCRYPTIONS_PER_KEY + 1))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("max-encryptions-per-key");
  }

  @Test
  void a_write_for_a_destroying_subject_is_refused() {
    cipher.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);
    keys.markDestroying(A, SUBJECT);

    assertThatThrownBy(() -> cipher.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.ERASED);
  }

  @Test
  void a_cached_key_does_not_outrank_the_row_state() {
    byte[] stored = cipher.encrypt(A, SUBJECT, ROW, "Customer", "email", PLAINTEXT);
    assertThat(cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.SENTINEL)).isPresent();

    // the key is now cached; the row says DESTROYING
    keys.markDestroying(A, SUBJECT);

    assertThat(cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.SENTINEL)).isEmpty();
  }

  @Test
  void the_cache_is_bounded_and_expires() {
    var ticking = new java.util.concurrent.atomic.AtomicReference<>(java.time.Instant.EPOCH);
    var clock =
        new Clock() {
          @Override
          public ZoneOffset getZone() {
            return ZoneOffset.UTC;
          }

          @Override
          public Clock withZone(java.time.ZoneId zone) {
            return this;
          }

          @Override
          public java.time.Instant instant() {
            return ticking.get();
          }
        };
    var bounded = new DataKeyCache(Duration.ofSeconds(60), 2, clock);
    bounded.put(A, SubjectId.of("s-1"), 1, new byte[32]);
    bounded.put(A, SubjectId.of("s-2"), 1, new byte[32]);
    bounded.put(A, SubjectId.of("s-3"), 1, new byte[32]);

    assertThat(bounded.size()).isEqualTo(2);
    assertThat(bounded.get(A, SubjectId.of("s-3"), 1)).isPresent();

    ticking.set(java.time.Instant.EPOCH.plusSeconds(61));
    assertThat(bounded.get(A, SubjectId.of("s-3"), 1)).isEmpty();
  }

  @Test
  void the_in_memory_provider_refuses_to_start_outside_dev_mode() {
    assertThatThrownBy(() -> new InMemoryKeyProvider(RandomSource.secure(), false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("shredding.dev-mode=true");
  }
}
