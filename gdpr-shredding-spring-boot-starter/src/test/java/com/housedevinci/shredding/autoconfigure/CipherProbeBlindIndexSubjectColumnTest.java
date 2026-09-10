package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexsubject.AlignedNote;
import com.housedevinci.shredding.autoconfigure.blindindexsubject.AlignedNoteRepository;
import com.housedevinci.shredding.autoconfigure.blindindexsubject.LooseSubjectNote;
import com.housedevinci.shredding.autoconfigure.blindindexsubject.LooseSubjectNoteRepository;
import com.housedevinci.shredding.autoconfigure.blindindexsubject.SplitNote;
import com.housedevinci.shredding.autoconfigure.blindindexsubject.SplitNoteRepository;
import com.housedevinci.shredding.domain.BlindIndex;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
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
 * write time and refused when it disagrees with the tenant the data key is derived under. {@code
 * subjectColumn} got none of that: it was validated as an identifier and then interpolated into the
 * erasure's {@code WHERE}, and nothing ever compared it with {@code @Shredded(subject = ...)}. An
 * entity whose subject expression evaluates to something other than the subject column wrote an
 * index no erasure could reach - the same finding as S-13, on the other axis, with the same
 * consequence: the key dies, the ciphertext dies, the erasure record says COMPLETE, and {@code
 * HMAC(secret, tenant | entity | field | plaintext)} stays in the table as a cross-row correlator
 * and a confirmation oracle for the erased subject.
 *
 * <p><b>Why the first two probes assert a refusal rather than a clearing (change 8, applied
 * §3.8d).</b> The same deviation, for the same reason, as change 4's on {@code Note}: deriving the
 * index under {@code state[subjectColumn]} instead would only move the gap, because the data key is
 * per {@code (tenant, subject)} and {@code SplitNote}'s ciphertext is under the
 * <em>expression's</em> subject. One erasure request names one subject; it can only reach the key,
 * the ciphertext and the index when all three are under it. {@code SplitNote}'s shape is erasable
 * under no keying this module can choose, so it never reaches the table, and there is no surviving
 * HMAC to assert about. {@link AlignedNote}, below, is the same application shape declared
 * correctly, and it erases key, ciphertext and index together.
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
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add("shredding.master-key", () -> b64("starter-integration-master-key32"));
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    registry.add(
        "spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
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
  @Autowired AlignedNoteRepository alignedNotes;
  @Autowired LooseSubjectNoteRepository looseNotes;
  @Autowired ErasureService erasures;
  @Autowired DataSource dataSource;
  @Autowired BlindIndex blindIndex;
  @Autowired ShreddedModel model;

  /**
   * The property this probe asserts is addendum 3's own: every blind index value that exists is
   * reachable and destroyed by the erasure of the subject it was derived for. On {@code SplitNote}
   * that is kept by refusing the write, naming both values, so no index value exists at all.
   */
  @Test
  void probe_a_blind_index_whose_subject_column_is_not_the_shredded_subject_survives_erasure()
      throws Exception {
    String rowOwner = "owner-" + System.nanoTime();
    String subject = "subject-" + System.nanoTime();

    ShreddingException refusal =
        refusalOf(
            () ->
                notes.saveAndFlush(
                    new SplitNote(rowOwner, subject, "org-b", "victim@example.test")));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.UNVERIFIED_WRITE);
    assertThat(refusal.getMessage())
        .contains(rowOwner)
        .contains(subject)
        .contains("owner_id")
        .contains("email");

    assertThat(indexBytes("split_note", rowOwner))
        .describedAs(
            "the write was refused, so there is no HMAC of the plaintext to survive an erasure")
        .isEmpty();
  }

  /** The bytes that would have survived are never derived, so they are nowhere in the table. */
  @Test
  void probe_the_surviving_index_is_the_hmac_of_the_erased_plaintext() throws Exception {
    String rowOwner = "owner2-" + System.nanoTime();
    String subject = "subject2-" + System.nanoTime();

    refusalOf(
        () -> notes.saveAndFlush(new SplitNote(rowOwner, subject, "org-b", "victim@example.test")));
    erasures.erase(
        new ErasureRequest(TenantId.of("org-b"), SubjectId.of(subject), "dpo", "art 17"));

    assertThat(allIndexBytes("split_note"))
        .describedAs("nothing derived from the plaintext may exist for a refused write")
        .doesNotContain(
            blindIndex.compute(TenantId.of("org-b"), "SplitNote", "email", "victim@example.test"));
  }

  /**
   * Change 8's other half: the same application shape declared correctly - the subject expression
   * and {@code subjectColumn} naming one value - is fully usable, and one erasure request for that
   * subject reaches the key, the ciphertext and the index.
   */
  @Test
  void probe_the_declared_shape_erases_key_ciphertext_and_index_together() throws Exception {
    String rowOwner = "aligned-" + System.nanoTime();
    String subject = "customer-" + System.nanoTime();
    alignedNotes.saveAndFlush(new AlignedNote(rowOwner, subject, "org-b", "victim@example.test"));

    assertThat(indexBytes("aligned_note", rowOwner)).hasSize(1);
    assertThat(indexBytes("aligned_note", rowOwner).get(0))
        .isEqualTo(
            blindIndex.compute(
                TenantId.of("org-b"), "AlignedNote", "email", "victim@example.test"));

    var result =
        erasures.erase(
            new ErasureRequest(TenantId.of("org-b"), SubjectId.of(subject), "dpo", "art 17"));

    assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
    assertThat(indexBytes("aligned_note", rowOwner))
        .describedAs("no index bytes left under any subject value the row ever carried")
        .isEmpty();
  }

  /** Change 3 on the subject axis: an index derived under null matches no {@code WHERE}. */
  @Test
  void probe_a_null_subject_column_value_is_refused_at_the_write() {
    String owner = "loose-null-" + System.nanoTime();

    ShreddingException refusal =
        refusalOf(
            () ->
                looseNotes.saveAndFlush(
                    new LooseSubjectNote(owner, null, "org-b", "victim@example.test")));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.UNVERIFIED_WRITE);
    assertThat(refusal.getMessage()).contains("customer_ref").contains("null");
  }

  /** Change 3, the blank half: a subject column of spaces is no more matchable than a null one. */
  @Test
  void probe_a_blank_subject_column_value_is_refused_at_the_write() {
    String owner = "loose-blank-" + System.nanoTime();

    ShreddingException refusal =
        refusalOf(
            () ->
                looseNotes.saveAndFlush(
                    new LooseSubjectNote(owner, "   ", "org-b", "victim@example.test")));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.UNVERIFIED_WRITE);
    assertThat(refusal.getMessage()).contains("customer_ref").contains("blank");
  }

  /**
   * Change 2 on the subject axis: one object carries the column the erasure's {@code WHERE} matches
   * and the property the write path reads, resolved from that column once, at startup.
   */
  @Test
  void probe_one_object_carries_the_subject_column_and_the_property_the_write_reads() {
    var column =
        model.blindIndexFields().stream()
            .filter(f -> f.entityName().equals("AlignedNote"))
            .findFirst()
            .orElseThrow()
            .column();

    assertThat(column.subjectColumn()).isEqualTo("customer_ref");
    assertThat(column.subjectProperty()).contains("customerRef");
    assertThat(model.blindIndexColumns()).contains(column);
  }

  private static ShreddingException refusalOf(Runnable write) {
    try {
      write.run();
    } catch (RuntimeException thrown) {
      for (Throwable t = thrown; t != null; t = t.getCause()) {
        if (t instanceof ShreddingException s) {
          return s;
        }
      }
      throw new AssertionError("the write failed, but not with a ShreddingException", thrown);
    }
    throw new AssertionError("the write was not refused");
  }

  private List<byte[]> indexBytes(String table, String owner) throws Exception {
    var found = new ArrayList<byte[]>();
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement(
                "select email_idx from "
                    + table
                    + " where owner_id = ? and email_idx is not null")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        while (rs.next()) {
          found.add(rs.getBytes(1));
        }
      }
    }
    return found;
  }

  private List<byte[]> allIndexBytes(String table) throws Exception {
    var found = new ArrayList<byte[]>();
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement("select email_idx from " + table + " where email_idx is not null");
        var rs = ps.executeQuery()) {
      while (rs.next()) {
        found.add(rs.getBytes(1));
      }
    }
    return found;
  }
}
