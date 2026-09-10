package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexsubject.SplitNote;
import com.housedevinci.shredding.autoconfigure.blindindexsubject.SplitNoteRepository;
import com.housedevinci.shredding.domain.BlindIndex;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Cipher, ninth pass. S-20: design addendum 3 bound one of the two axes of a blind index to the
 * row. {@code tenantColumn} is resolved to a property at startup, read out of the state array at
 * write time and refused when it disagrees with the tenant the data key is derived under.
 * {@code subjectColumn} gets none of that: it is validated as an identifier and then interpolated
 * into the erasure's {@code WHERE}, and nothing ever compares it with {@code @Shredded(subject =
 * ...)}. An entity whose subject expression evaluates to something other than the subject column
 * writes an index no erasure can reach - the same finding as S-13, on the other axis, with the
 * same consequence: the key dies, the ciphertext dies, the erasure record says COMPLETE, and
 * {@code HMAC(secret, tenant | entity | field | plaintext)} stays in the table as a cross-row
 * correlator and a confirmation oracle for the erased subject.
 */
@SpringBootTest(classes = CipherProbeBlindIndexSubjectColumnTest.SplitApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeBlindIndexSubjectColumnTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add("shredding.master-key", () -> b64("starter-integration-master-key32"));
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = SplitNote.class)
  @EnableJpaRepositories(basePackageClasses = SplitNoteRepository.class)
  static class SplitApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-b");
    }
  }

  @Autowired SplitNoteRepository notes;
  @Autowired ErasureService erasures;
  @Autowired DataSource dataSource;
  @Autowired BlindIndex blindIndex;

  /**
   * The write is accepted - nothing at startup or at write time looks at {@code subjectColumn} -
   * and the erasure of the subject the key belongs to matches no row, clears nothing, verifies
   * nothing and records success. The property this probe asserts is addendum 3's own: every blind
   * index value that exists is reachable and destroyed by the erasure of the subject it was derived
   * for. Either the write is refused (as the disagreeing tenant is) or the erasure destroys the
   * index; both are acceptable outcomes and both make this probe green.
   */
  @Test
  void probe_a_blind_index_whose_subject_column_is_not_the_shredded_subject_survives_erasure()
      throws Exception {
    String rowOwner = "owner-" + System.nanoTime();
    String subject = "subject-" + System.nanoTime();

    notes.saveAndFlush(new SplitNote(rowOwner, subject, "org-b", "victim@example.test"));

    var result =
        erasures.erase(
            new ErasureRequest(TenantId.of("org-b"), SubjectId.of(subject), "dpo", "art 17"));

    List<byte[]> left = indexBytes(rowOwner);
    assertThat(left)
        .describedAs(
            "erasure reported %s and cleared %s index column(s); what is left in split_note.email"
                + "_idx is HMAC(secret, org-b | SplitNote | email | victim@example.test), a stable"
                + " correlator for an erased subject",
            result.outcome(), result.blindIndexColumnsCleared())
        .isEmpty();
  }

  /** The surviving bytes are exactly the index of the erased plaintext, recomputed here. */
  @Test
  void probe_the_surviving_index_is_the_hmac_of_the_erased_plaintext() throws Exception {
    String rowOwner = "owner2-" + System.nanoTime();
    String subject = "subject2-" + System.nanoTime();

    notes.saveAndFlush(new SplitNote(rowOwner, subject, "org-b", "victim@example.test"));
    erasures.erase(
        new ErasureRequest(TenantId.of("org-b"), SubjectId.of(subject), "dpo", "art 17"));

    assertThat(indexBytes(rowOwner))
        .describedAs("nothing derived from the erased plaintext may survive its erasure")
        .doesNotContain(
            blindIndex.compute(
                TenantId.of("org-b"), "SplitNote", "email", "victim@example.test"));
  }

  private List<byte[]> indexBytes(String owner) throws Exception {
    var found = new ArrayList<byte[]>();
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement(
                "select email_idx from split_note where owner_id = ? and email_idx is not null")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        while (rs.next()) {
          found.add(rs.getBytes(1));
        }
      }
    }
    return found;
  }
}
