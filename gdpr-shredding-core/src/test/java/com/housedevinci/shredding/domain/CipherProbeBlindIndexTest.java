package com.housedevinci.shredding.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * The security review's probe: the blind index is per tenant, versioned, and a prefilter only
 * (control 10).
 */
class CipherProbeBlindIndexTest {

  private static final byte[] SECRET =
      "blind-index-secret-at-least-32-bytes!".getBytes(java.nio.charset.StandardCharsets.UTF_8);
  private static final BlindIndex INDEX = new BlindIndex(SECRET, 64);

  /**
   * One index key for every tenant turns the blind index into a cross-tenant join: tenant B learns
   * that its subject and tenant A's subject share an email address without holding either key.
   */
  @Test
  void probe_blind_index_matches_the_same_value_across_tenants() {
    byte[] a = INDEX.compute(TenantId.of("tenant-a"), "Customer", "email", "alice@example.com");
    byte[] b = INDEX.compute(TenantId.of("tenant-b"), "Customer", "email", "alice@example.com");

    assertThat(a).isNotEqualTo(b);
  }

  @Test
  void the_same_value_in_the_same_tenant_and_field_indexes_identically() {
    TenantId t = TenantId.of("tenant-a");
    assertThat(INDEX.compute(t, "Customer", "email", "alice@example.com"))
        .isEqualTo(INDEX.compute(t, "Customer", "email", "alice@example.com"));
  }

  @Test
  void the_same_value_in_two_fields_does_not_correlate() {
    TenantId t = TenantId.of("tenant-a");
    assertThat(INDEX.compute(t, "Customer", "email", "a@b.c"))
        .isNotEqualTo(INDEX.compute(t, "Customer", "backupEmail", "a@b.c"));
    assertThat(INDEX.compute(t, "Customer", "email", "a@b.c"))
        .isNotEqualTo(INDEX.compute(t, "Supplier", "email", "a@b.c"));
  }

  @Test
  void the_index_is_truncated_to_the_configured_width() {
    TenantId t = TenantId.of("tenant-a");
    assertThat(INDEX.compute(t, "Customer", "email", "a@b.c")).hasSize(8);
    assertThat(new BlindIndex(SECRET, 32).compute(t, "Customer", "email", "a@b.c")).hasSize(4);
  }

  @Test
  void a_short_secret_or_an_odd_width_is_refused() {
    assertThatThrownBy(() -> new BlindIndex(new byte[31], 64))
        .isInstanceOf(ShreddingException.class);
    assertThatThrownBy(() -> new BlindIndex(SECRET, 24)).isInstanceOf(ShreddingException.class);
    assertThatThrownBy(() -> new BlindIndex(SECRET, 65)).isInstanceOf(ShreddingException.class);
    assertThatThrownBy(() -> new BlindIndex(SECRET, 512)).isInstanceOf(ShreddingException.class);
  }

  @Test
  void normalisation_is_one_code_path_for_write_and_query() {
    assertThat(Normalisation.forText("  ALICE@Example.COM ")).isEqualTo("alice@example.com");
    assertThat(Normalisation.forText("ﬁn")).isEqualTo("fin");
    assertThat(Normalisation.forDecimal(new java.math.BigDecimal("1.50")))
        .isEqualTo(Normalisation.forDecimal(new java.math.BigDecimal("1.5")));
    assertThat(Normalisation.forDate(java.time.LocalDate.of(2026, 1, 2))).isEqualTo("2026-01-02");
    assertThat(Normalisation.forBytes(new byte[] {0x0a, (byte) 0xff})).isEqualTo("0aff");
  }

  @Test
  void the_pseudonym_is_keyed_and_separated_from_the_chain_secret() {
    var p = new Pseudonymiser(SECRET);
    String one = p.pseudonym(TenantId.of("t"), SubjectId.of("s-1"));

    assertThat(one).hasSize(64).isNotEqualTo(Hashes.sha256Hex("s-1"));
    assertThat(p.pseudonym(TenantId.of("t"), SubjectId.of("s-2"))).isNotEqualTo(one);
    assertThat(p.pseudonym(TenantId.of("u"), SubjectId.of("s-1"))).isNotEqualTo(one);
    assertThat(
            new Pseudonymiser("another-secret-that-is-also-32-bytes".getBytes())
                .pseudonym(TenantId.of("t"), SubjectId.of("s-1")))
        .isNotEqualTo(one);
  }
}
