package com.housedevinci.shredding.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Cipher probe: AAD is length-prefixed and canonical (control 2). */
class CipherProbeAadTest {

  private static final TenantId TENANT = TenantId.of("acme");
  private static final SubjectId SUBJECT = SubjectId.of("s-1");

  /**
   * Unprefixed concatenation lets {@code entity="Custom"} + {@code field="erEmail"} produce the
   * same authenticated material as {@code entity="Customer"} + {@code field="Email"}, so a
   * ciphertext written for one field authenticates under the other.
   */
  @Test
  void probe_field_and_entity_names_collide_in_the_aad() {
    byte[] a = Aad.forValue(TENANT, SUBJECT, "Custom", "erEmail", 1, (byte) 1);
    byte[] b = Aad.forValue(TENANT, SUBJECT, "Customer", "Email", 1, (byte) 1);

    assertThat(a).isNotEqualTo(b);
  }

  @Test
  void a_separator_inside_a_value_cannot_move_a_field_boundary() {
    byte[] a = Aad.forValue(TENANT, SUBJECT, "Customer|Email", "x", 1, (byte) 1);
    byte[] b = Aad.forValue(TENANT, SUBJECT, "Customer", "Email|x", 1, (byte) 1);

    assertThat(a).isNotEqualTo(b);
  }

  @Test
  void the_aad_binds_every_component() {
    byte[] base = Aad.forValue(TENANT, SUBJECT, "Customer", "email", 1, (byte) 1);
    assertThat(Aad.forValue(TenantId.of("other"), SUBJECT, "Customer", "email", 1, (byte) 1))
        .isNotEqualTo(base);
    assertThat(Aad.forValue(TENANT, SubjectId.of("s-2"), "Customer", "email", 1, (byte) 1))
        .isNotEqualTo(base);
    assertThat(Aad.forValue(TENANT, SUBJECT, "Customer", "email", 2, (byte) 1)).isNotEqualTo(base);
    assertThat(Aad.forValue(TENANT, SUBJECT, "Customer", "email", 1, (byte) 2)).isNotEqualTo(base);
    assertThat(new String(base, StandardCharsets.UTF_8)).startsWith("sh1|");
  }

  @Test
  void the_wrap_aad_binds_tenant_subject_and_key_version() {
    byte[] base = Aad.forWrap(TENANT, SUBJECT, 1);
    assertThat(Aad.forWrap(TenantId.of("other"), SUBJECT, 1)).isNotEqualTo(base);
    assertThat(Aad.forWrap(TENANT, SubjectId.of("s-2"), 1)).isNotEqualTo(base);
    assertThat(Aad.forWrap(TENANT, SUBJECT, 2)).isNotEqualTo(base);
  }
}
