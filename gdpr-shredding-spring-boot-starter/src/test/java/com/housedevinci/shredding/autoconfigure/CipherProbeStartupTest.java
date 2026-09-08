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
   * A second-level cached entity keeps handing out the decrypted value from the cache after the key
   * is gone. The erasure is then invisible for as long as the region lives, and nothing in the
   * application says so.
   */
  @Test
  void probe_second_level_cache_serves_plaintext_after_erasure() {
    assertThatThrownBy(() -> ShreddedModel.scan(List.of(CachedCustomer.class), false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("second-level cached")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.CONFIG);

    // and the escape hatch exists, loudly, for an application that accepts the residual
    assertThatCode(() -> ShreddedModel.scan(List.of(CachedCustomer.class), true))
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
}
