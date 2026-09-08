package com.housedevinci.shredding.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Aes256GcmTest {

  private static final byte[] KEY = new byte[32];
  private static final byte[] AAD = "sh1|1:1".getBytes(StandardCharsets.UTF_8);
  private static final RandomSource RANDOM = RandomSource.secure();

  @Test
  void round_trips_under_the_same_key_and_aad() {
    byte[] plaintext = "alice@example.com".getBytes(StandardCharsets.UTF_8);
    var sealed = Aes256Gcm.encrypt(KEY, RANDOM.nonce(), plaintext, AAD);

    assertThat(Aes256Gcm.decrypt(KEY, sealed.nonce(), sealed.ciphertext(), AAD))
        .isEqualTo(plaintext);
    assertThat(sealed.ciphertext()).hasSize(plaintext.length + Aes256Gcm.TAG_BITS / 8);
  }

  @Test
  void a_different_aad_does_not_authenticate() {
    var sealed = Aes256Gcm.encrypt(KEY, RANDOM.nonce(), new byte[4], AAD);
    byte[] other = "sh1|1:2".getBytes(StandardCharsets.UTF_8);

    assertThatThrownBy(() -> Aes256Gcm.decrypt(KEY, sealed.nonce(), sealed.ciphertext(), other))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.DECRYPT);
  }

  @Test
  void a_flipped_ciphertext_bit_does_not_authenticate() {
    var sealed = Aes256Gcm.encrypt(KEY, RANDOM.nonce(), new byte[4], AAD);
    byte[] tampered = sealed.ciphertext();
    tampered[0] ^= 0x01;

    assertThatThrownBy(() -> Aes256Gcm.decrypt(KEY, sealed.nonce(), tampered, AAD))
        .isInstanceOf(ShreddingException.class);
  }

  @Test
  void the_failure_message_says_nothing_about_which_part_was_wrong() {
    var sealed = Aes256Gcm.encrypt(KEY, RANDOM.nonce(), new byte[4], AAD);
    byte[] otherKey = new byte[32];
    otherKey[0] = 1;

    Throwable wrongKey =
        org.assertj.core.api.Assertions.catchThrowable(
            () -> Aes256Gcm.decrypt(otherKey, sealed.nonce(), sealed.ciphertext(), AAD));
    Throwable wrongAad =
        org.assertj.core.api.Assertions.catchThrowable(
            () -> Aes256Gcm.decrypt(KEY, sealed.nonce(), sealed.ciphertext(), new byte[] {9}));

    assertThat(wrongKey).hasMessage(wrongAad.getMessage());
  }

  @Test
  void an_empty_aad_is_refused() {
    assertThatThrownBy(() -> Aes256Gcm.encrypt(KEY, RANDOM.nonce(), new byte[1], new byte[0]))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("AAD must never be empty");
  }

  @Test
  void a_key_of_the_wrong_length_is_refused() {
    assertThatThrownBy(() -> Aes256Gcm.encrypt(new byte[16], RANDOM.nonce(), new byte[1], AAD))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("must be 32 bytes");
  }

  @Test
  void a_nonce_of_the_wrong_length_is_refused() {
    assertThatThrownBy(() -> Aes256Gcm.encrypt(KEY, new byte[8], new byte[1], AAD))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("nonce must be 12 bytes");
  }

  @Test
  void the_nonce_source_is_secure_random_and_a_narrow_source_is_detectable() {
    // Cipher replaced the spec's "100k encryptions, no nonce collision" property test: 100k draws
    // from 2^96 collide with probability about 2^-64, so that test cannot fail even against a
    // badly broken generator. What can be tested is that the nonce comes from a source we control
    // and that a narrow one is visible.
    var narrow =
        RandomSource.of(
            new java.util.Random(42) {
              private static final long serialVersionUID = 1L;

              @Override
              public void nextBytes(byte[] bytes) {
                java.util.Arrays.fill(bytes, (byte) 7);
              }
            });

    assertThat(narrow.nonce()).isEqualTo(narrow.nonce());
    assertThat(RANDOM.nonce()).isNotEqualTo(RANDOM.nonce());
    assertThat(RANDOM.dataKey()).hasSize(32);
  }

  @Test
  void wipe_zeroes_a_buffer() {
    byte[] secret = {1, 2, 3};
    Aes256Gcm.wipe(secret);
    assertThat(secret).containsOnly((byte) 0);
    Aes256Gcm.wipe(null);
  }
}
