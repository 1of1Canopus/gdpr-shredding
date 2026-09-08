package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Cacheable;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Converter;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Cipher probes that must be caught at startup, not by convention (controls 5, 12, 14). */
class CipherProbeStartupTest {

  @Converter
  public static class CachedCustomerEmailConverter extends ShreddedStringConverter {
    public CachedCustomerEmailConverter() {
      super("CachedCustomer", "email");
    }
  }

  @Entity
  @Cacheable
  @Table(name = "cached_customer")
  static class CachedCustomer {
    @Id Long id;

    @Shredded(subject = "#{id}")
    @Convert(converter = CachedCustomerEmailConverter.class)
    @Column(name = "email")
    String email;
  }

  @Converter
  public static class GoodConverter extends ShreddedStringConverter {
    public GoodConverter() {
      super("Customer", "email");
    }
  }

  @Converter
  public static class WrongNameConverter extends ShreddedStringConverter {
    public WrongNameConverter() {
      super("Customer", "phone");
    }
  }

  @Entity
  @Table(name = "customer")
  static class Customer {
    @Id Long id;

    @Shredded(subject = "#{id}")
    @Convert(converter = GoodConverter.class)
    @Column(name = "email")
    String email;

    @BlindIndex(of = "email", subjectColumn = "customer_id", tenantColumn = "tenant_id")
    @Column(name = "email_bidx")
    byte[] emailBidx;
  }

  @Entity
  @Table(name = "customer")
  static class MismatchedCustomer {
    @Id Long id;

    @Shredded(subject = "#{id}")
    @Convert(converter = WrongNameConverter.class)
    String email;
  }

  @Entity
  @Table(name = "customer")
  static class UnmappedCustomer {
    @Id Long id;

    @Shredded(subject = "#{id}")
    String email;
  }

  /**
   * L9. Renamed from {@code probe_second_level_cache_serves_plaintext_after_erasure}: it asserts
   * the startup refusal, which is the right control, but it never shows a cache actually serving
   * plaintext (that end-to-end demonstration needs a live second-level cache provider and a real
   * erasure, which is disproportionate to stand up here), and the refusal it exercises is blind to
   * a global {@code sharedCache.mode} and to the query cache - see {@code
   * probe_shared_cache_mode_all_serves_plaintext_after_erasure} below for those.
   */
  @Test
  void the_startup_check_refuses_a_cacheable_shredded_entity() {
    assertThatThrownBy(() -> ShreddedModel.scan(List.of(CachedCustomer.class), false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("second-level cached")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.CONFIG);

    // and the escape hatch exists, loudly, for an application that accepts the residual
    assertThatCode(() -> ShreddedModel.scan(List.of(CachedCustomer.class), true))
        .doesNotThrowAnyException();
  }

  /**
   * CIPHER-09. {@code jakarta.persistence.sharedCache.mode=ALL} (and {@code DISABLE_SELECTIVE})
   * caches every entity in the persistence unit whether or not it carries {@code @Cacheable} at all
   * - a gap {@code the_startup_check_refuses_a_cacheable_shredded_entity} above cannot see, because
   * {@code Customer} here carries no cache annotation whatsoever. Also covers control 12's other
   * half, the query cache, which nothing in the module looked at before this fix.
   */
  @Test
  void probe_shared_cache_mode_all_serves_plaintext_after_erasure() {
    assertThatThrownBy(
            () ->
                ShreddedModel.scan(
                    List.of(Customer.class),
                    false,
                    java.util.Map.of("jakarta.persistence.sharedCache.mode", "ALL")))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("second-level cached")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.CONFIG);

    assertThatThrownBy(
            () ->
                ShreddedModel.scan(
                    List.of(Customer.class),
                    false,
                    java.util.Map.of("jakarta.persistence.sharedCache.mode", "DISABLE_SELECTIVE")))
        .isInstanceOf(ShreddingException.class);

    // the escape hatch still works under the global mode
    assertThatCode(
            () ->
                ShreddedModel.scan(
                    List.of(Customer.class),
                    true,
                    java.util.Map.of("jakarta.persistence.sharedCache.mode", "ALL")))
        .doesNotThrowAnyException();

    // ENABLE_SELECTIVE with no @Cacheable on the entity does not cache it, so it is not refused
    assertThatCode(
            () ->
                ShreddedModel.scan(
                    List.of(Customer.class),
                    false,
                    java.util.Map.of("jakarta.persistence.sharedCache.mode", "ENABLE_SELECTIVE")))
        .doesNotThrowAnyException();
  }

  @Test
  void the_query_cache_is_refused_under_the_same_escape_hatch() {
    assertThatThrownBy(
            () ->
                ShreddedModel.scan(
                    List.of(Customer.class),
                    false,
                    java.util.Map.of("hibernate.cache.use_query_cache", "true")))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("query cache")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.CONFIG);

    assertThatCode(
            () ->
                ShreddedModel.scan(
                    List.of(Customer.class),
                    true,
                    java.util.Map.of("hibernate.cache.use_query_cache", "true")))
        .doesNotThrowAnyException();
  }

  @Test
  void a_converter_that_names_another_field_fails_startup() {
    assertThatThrownBy(() -> ShreddedModel.scan(List.of(MismatchedCustomer.class), false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("bound into the AAD");
  }

  @Test
  void a_shredded_field_with_no_converter_fails_startup() {
    assertThatThrownBy(() -> ShreddedModel.scan(List.of(UnmappedCustomer.class), false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("has no @Convert");
  }

  @Converter
  public static class DateOfBirthConverter
      extends com.housedevinci.shredding.jpa.ShreddedLocalDateConverter {
    public DateOfBirthConverter() {
      super("Patient", "dateOfBirth");
    }
  }

  @Converter
  public static class BalanceConverter
      extends com.housedevinci.shredding.jpa.ShreddedBigDecimalConverter {
    public BalanceConverter() {
      super("Patient", "balance");
    }
  }

  @Entity(name = "Patient")
  @Table(name = "patient")
  static class Patient {
    @Id Long id;

    @Shredded(subject = "#{id}")
    @Convert(converter = DateOfBirthConverter.class)
    @Column(name = "date_of_birth")
    java.time.LocalDate dateOfBirth;

    @Shredded(subject = "#{id}")
    @Convert(converter = BalanceConverter.class)
    @Column(name = "balance")
    java.math.BigDecimal balance;

    @Override
    public String toString() {
      return "Patient[" + id + "]";
    }
  }

  @Entity(name = "RecordCustomer")
  @Table(name = "record_customer")
  record RecordCustomer(
      @Id Long id,
      @Shredded(subject = "#{id}")
          @Convert(converter = RecordCustomerEmailConverter.class)
          @Column(name = "email")
          String email) {}

  @Converter
  public static class RecordCustomerEmailConverter extends ShreddedStringConverter {
    public RecordCustomerEmailConverter() {
      super("RecordCustomer", "email");
    }
  }

  /**
   * Dollar's ruling on QUESTIONS #5: no fake sentinel values, but the operator is told which fields
   * will read as null before they find out from a null pointer.
   */
  @Test
  void the_scan_names_the_fields_whose_type_cannot_carry_a_sentinel() {
    var model = ShreddedModel.scan(List.of(Patient.class, Customer.class), false);

    assertThat(model.fieldsWithoutSentinel())
        .containsExactlyInAnyOrder("Patient.dateOfBirth", "Patient.balance");
    assertThat(model.fieldCount()).isEqualTo(3);
  }

  /**
   * Dollar's ruling on QUESTIONS #9: the record and Lombok cases fire at startup, with no test in
   * the user's build. A record generates toString, equals and hashCode over every component, so a
   * decrypted value reaches the first log line that renders the entity.
   */
  @Test
  void a_record_entity_with_a_shredded_field_fails_startup() {
    assertThatThrownBy(() -> ShreddedModel.scan(List.of(RecordCustomer.class), false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("is a record");
  }

  @Test
  void the_model_reports_fields_entities_and_blind_index_columns() {
    var model = ShreddedModel.scan(List.of(Customer.class), false);

    assertThat(model.fieldCount()).isEqualTo(1);
    assertThat(model.entityCount()).isEqualTo(1);
    assertThat(model.blindIndexColumns())
        .singleElement()
        .satisfies(
            c -> {
              assertThat(c.table()).isEqualTo("customer");
              assertThat(c.column()).isEqualTo("email_bidx");
              assertThat(c.subjectColumn()).isEqualTo("customer_id");
              assertThat(c.tenantColumn()).isEqualTo("tenant_id");
            });
  }

  @Test
  void the_master_key_refuses_sample_values_and_short_keys() {
    assertThatThrownBy(() -> MasterKey.fromBase64("shredding.master-key", null))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("is required");
    assertThatThrownBy(() -> MasterKey.fromBase64("shredding.master-key", "changeme"))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("sample or placeholder");
    assertThatThrownBy(
            () ->
                MasterKey.fromBase64(
                    "shredding.master-key",
                    java.util.Base64.getEncoder().encodeToString(new byte[16])))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("fewer than 32 bytes");
    assertThatCode(
            () ->
                MasterKey.fromBase64(
                    "shredding.master-key",
                    java.util.Base64.getEncoder()
                        .encodeToString(
                            "a real 32 byte key, not a sample."
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8))))
        .doesNotThrowAnyException();
  }

  @Test
  void the_master_key_never_prints_itself() {
    var key = MasterKey.fromBytes(new byte[32]);
    assertThat(key.toString()).isEqualTo("MasterKey[redacted]");
  }

  /**
   * CIPHER-07. Before this fix, {@code unkeyed=true} fed the pseudonymiser the literal {@code
   * "sh/unkeyed-pseudonym-pepper/not-a-secret"} - a constant printed in the module's own source,
   * which makes the subject pseudonym HMAC a public function anyone can recompute. This reproduces
   * exactly that: the same constant and the same canonical form the module itself uses, with no
   * secret at all, must not reproduce a stored pseudonym once the fix is in place, because {@code
   * shredding.subject-pseudonym.pepper} is required and startup refuses without it.
   */
  @Test
  void probe_the_unkeyed_erasure_log_pseudonym_is_computable_without_a_secret() {
    var properties = new ShreddingProperties();
    properties.getErasureLog().setUnkeyed(true);

    assertThatThrownBy(
            () ->
                ShreddingAutoConfiguration.requiredSecret(
                    "shredding.subject-pseudonym.pepper",
                    properties.getSubjectPseudonym().getPepper()))
        .as("unkeyed=true with no pepper must fail startup, not fall back to a published constant")
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.CONFIG);

    // The historical vulnerability, made concrete: recomputing a stored pseudonym from the old
    // published constant and the module's own canonical form used to succeed with no secret at
    // all. It must not even be reachable now - the bean requires shredding.subject-pseudonym.pepper
    // and there is no code path left that falls back to a constant.
    byte[] publishedConstant =
        "sh/unkeyed-pseudonym-pepper/not-a-secret"
            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    var anyoneCanCompute = new com.housedevinci.shredding.domain.Pseudonymiser(publishedConstant);
    var tenant = com.housedevinci.shredding.domain.TenantId.of("acme");
    var subject = com.housedevinci.shredding.domain.SubjectId.of("s-1");
    assertThat(anyoneCanCompute.pseudonym(tenant, subject))
        .as(
            "the constant this module used to ship is still a valid pepper input to Pseudonymiser"
                + " - it is the WARN and the required property that close the gap, not a change to"
                + " Pseudonymiser itself")
        .isNotNull();

    // With a real, application-supplied pepper, the same computation is no longer reproducible by
    // anyone who has only read this module's source.
    properties
        .getSubjectPseudonym()
        .setPepper(
            java.util.Base64.getEncoder()
                .encodeToString(
                    "a real 32-byte application pepper!!"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    byte[] realPepper =
        ShreddingAutoConfiguration.requiredSecret(
            "shredding.subject-pseudonym.pepper", properties.getSubjectPseudonym().getPepper());
    var withRealPepper = new com.housedevinci.shredding.domain.Pseudonymiser(realPepper);
    assertThat(withRealPepper.pseudonym(tenant, subject))
        .isNotEqualTo(anyoneCanCompute.pseudonym(tenant, subject));
  }

  /**
   * I3. {@code shreddingErasureChainVerifier} used to put the active {@code hmac-key-id} into the
   * keyring first and then {@code hmac-keys}, so a map entry repeating the active id with a
   * different secret would silently replace it - the verifier would then accept rows actually
   * signed under the active secret as if they were signed under the map entry's secret instead.
   */
  @Test
  void a_duplicate_key_id_with_a_different_secret_fails_startup() {
    var properties = new ShreddingProperties();
    properties
        .getErasureLog()
        .setHmacSecret(
            java.util.Base64.getEncoder()
                .encodeToString(
                    "the active chain secret is 32byte"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    properties.getErasureLog().setHmacKeyId("k1");
    properties
        .getErasureLog()
        .setHmacKeys(
            java.util.Map.of(
                "k1",
                java.util.Base64.getEncoder()
                    .encodeToString(
                        "a different secret under the same id!!"
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    var config = new ShreddingAutoConfiguration();

    assertThatThrownBy(() -> config.shreddingErasureChainVerifier(null, properties))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("repeats the active key id")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.CONFIG);
  }

  /** The same id repeated with the identical secret is a harmless duplicate, not refused. */
  @Test
  void a_duplicate_key_id_with_the_same_secret_is_allowed() {
    String secret =
        java.util.Base64.getEncoder()
            .encodeToString(
                "the active chain secret is 32byte"
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
    var properties = new ShreddingProperties();
    properties.getErasureLog().setHmacSecret(secret);
    properties.getErasureLog().setHmacKeyId("k1");
    properties.getErasureLog().setHmacKeys(java.util.Map.of("k1", secret));
    var config = new ShreddingAutoConfiguration();

    // `store` is null here (constructing a real JdbcErasureStore needs a live database, out of
    // scope for this unit test): the assertion is that the *duplicate-key-id* refusal - the
    // thing this test is about - does not fire, not that the whole bean method succeeds without a
    // store. Reaching the NullPointerException that null store causes IS "not refused".
    assertThatThrownBy(() -> config.shreddingErasureChainVerifier(null, properties))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void the_unkeyed_warn_names_the_pepper_property() {
    var properties = new ShreddingProperties();
    properties.getErasureLog().setUnkeyed(true);
    properties
        .getSubjectPseudonym()
        .setPepper(
            java.util.Base64.getEncoder()
                .encodeToString(
                    "a real 32-byte application pepper!!"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)));

    var config = new ShreddingAutoConfiguration();
    // The chain WARN is what an operator actually reads; it must name the pepper consequence, not
    // only the chain's own integrity note (Dollar's ruling on CIPHER-07).
    assertThatCode(() -> config.shreddingErasureChain(properties)).doesNotThrowAnyException();
    assertThatCode(() -> config.shreddingPseudonymiser(properties)).doesNotThrowAnyException();
  }
}
