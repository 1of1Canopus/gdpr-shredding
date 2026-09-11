package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexambient.LooseNote;
import com.housedevinci.shredding.autoconfigure.blindindexambient.LooseNoteRepository;
import com.housedevinci.shredding.autoconfigure.blindindexambient.Note;
import com.housedevinci.shredding.autoconfigure.blindindexambient.NoteRepository;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository;
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
 * The eighth pass (fa6f477). S-13 / S-7b - the general case of S-7 - and the shape design addendum
 * 3 replaces it with.
 *
 * <p><b>The property (addendum 3).</b> <em>Every blind index value that exists is reachable and
 * destroyed by the erasure of the subject it was derived for.</em> the security review's original
 * repro on this file was RED: {@code Note} declares no tenant anywhere, so the index was derived
 * under the ambient {@code TenantSupplier} ({@code org-a}) while the erasure matched the row's own
 * {@code tenant_id} ({@code org-b}); the erasure destroyed the key, killed the ciphertext, reported
 * success and left {@code HMAC(secret, org-a | Note | email | victim@example.test)} in the table.
 *
 * <p><b>What the fix is, and why this file's first probe asserts a refusal rather than a clearing
 * (change 4, applied §3.4).</b> Deriving under {@code state[tenantColumn]} alone does not close the
 * finding: the ciphertext of {@code Note.email} is encrypted under the data key for {@code (org-a,
 * subject)}, so an erasure for {@code org-a} still matches no row and an erasure for {@code org-b}
 * clears an index while destroying a key the ciphertext was never under. The invariant is that the
 * tenant the data key was derived under, the tenant the index was derived under and the value in
 * the tenant column are one value - and {@code Note}'s shape can be made erasable by no keying this
 * module could choose. It is refused at the write, loudly, naming both values. {@code OwnedNote} is
 * the same application shape declared correctly ({@code @Shredded(tenant = "#{tenantId}")}, the
 * owning organisation the tenant column holds) and it is erasable: key, ciphertext and index
 * together, under any tenant value the row ever carried.
 */
@SpringBootTest(classes = CipherProbeBlindIndexAmbientTenantTest.NoteApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeBlindIndexAmbientTenantTest {

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
  @EntityScan(basePackageClasses = Note.class)
  @EnableJpaRepositories(basePackageClasses = NoteRepository.class)
  static class NoteApp {
    /** The acting organisation. The row's own tenant column holds the owning one. */
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @Autowired NoteRepository notes;
  @Autowired OwnedNoteRepository ownedNotes;
  @Autowired LooseNoteRepository looseNotes;
  @Autowired ErasureService erasures;
  @Autowired DataSource dataSource;
  @Autowired BlindIndex blindIndex;
  @Autowired ShreddedModel model;

  /**
   * Change 4. The shape the security review's repro used - the index would be derived under a
   * tenant the erasure cannot match, and the ciphertext under a third one - never reaches the table
   * at all. The message names both tenants, the field and the column, because the application's fix
   * is to choose which of the two is the owning organisation.
   */
  @Test
  void probe_a_write_whose_field_tenant_and_tenant_column_disagree_is_refused() throws Exception {
    String owner = "note-" + System.nanoTime();

    ShreddingException refusal =
        refusalOf(() -> notes.saveAndFlush(new Note(owner, "org-b", "victim@example.test")));
    assertThat(refusal.code()).isEqualTo(ErrorCodes.UNVERIFIED_WRITE);
    assertThat(refusal.getMessage())
        .contains("org-a")
        .contains("org-b")
        .contains("tenant_id")
        .contains("email");

    assertThat(indexBytes("ambient_note", owner))
        .describedAs("nothing was written, so there is no HMAC of the erased plaintext to survive")
        .isEmpty();
  }

  /**
   * Change 4, the other half: the same application shape, declared as change 4 requires, is fully
   * usable - and erasable. The index is derived under the row's tenant column value, and one
   * erasure request for that tenant reaches the key, the ciphertext and the index.
   */
  @Test
  void probe_the_declared_shape_erases_key_ciphertext_and_index_together() throws Exception {
    String owner = "owned-" + System.nanoTime();
    ownedNotes.saveAndFlush(new OwnedNote(owner, "org-b", "victim@example.test"));

    assertThat(indexBytes("owned_note", owner)).hasSize(1);
    assertThat(indexBytes("owned_note", owner).get(0))
        .describedAs("derived under the row's tenant column value, not under the ambient tenant")
        .isEqualTo(
            blindIndex.compute(TenantId.of("org-b"), "OwnedNote", "email", "victim@example.test"))
        .isNotEqualTo(
            blindIndex.compute(TenantId.of("org-a"), "OwnedNote", "email", "victim@example.test"));

    var result =
        erasures.erase(
            new ErasureRequest(TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17"));

    assertThat(result.blindIndexColumnsCleared())
        .describedAs("the proof's cleared-index count is non-zero wherever an index existed")
        .isEqualTo(1);
    assertThat(anyIndexBytes("owned_note", owner))
        .describedAs("no index bytes under any tenant value the row ever carried")
        .isEmpty();
  }

  /**
   * Change 3, the null half. An index derived under nothing is an index no {@code WHERE tenant_id =
   * ?} can match, so the write is refused rather than performed.
   */
  @Test
  void probe_a_null_tenant_column_value_is_refused_at_the_write() {
    String owner = "loose-null-" + System.nanoTime();

    ShreddingException refusal =
        refusalOf(() -> looseNotes.saveAndFlush(new LooseNote(owner, null, "victim@example.test")));
    assertThat(refusal.code()).isEqualTo(ErrorCodes.UNVERIFIED_WRITE);
    assertThat(refusal.getMessage()).contains("tenant_id").contains("null");
  }

  /** Change 3, the blank half: a tenant column of spaces is no more matchable than a null one. */
  @Test
  void probe_a_blank_tenant_column_value_is_refused_at_the_write() {
    String owner = "loose-blank-" + System.nanoTime();

    ShreddingException refusal =
        refusalOf(
            () -> looseNotes.saveAndFlush(new LooseNote(owner, "   ", "victim@example.test")));
    assertThat(refusal.code()).isEqualTo(ErrorCodes.UNVERIFIED_WRITE);
    assertThat(refusal.getMessage()).contains("tenant_id").contains("blank");
  }

  /**
   * Change 2. S-7 and S-13 both exist because the tenant the write derived under and the tenant the
   * erasure matched on were computed in two places from two different inputs. One object now
   * carries both: the column the erasure's {@code WHERE} names and the property the write path
   * reads out of the state array, resolved from that column once, at startup. The erasure store is
   * constructed from exactly these objects ({@code model.blindIndexColumns()}).
   */
  @Test
  void probe_one_object_carries_the_column_the_erasure_matches_and_the_property_the_write_reads() {
    var column =
        model.blindIndexFields().stream()
            .filter(f -> f.entityName().equals("OwnedNote"))
            .findFirst()
            .orElseThrow()
            .column();

    assertThat(column.tenantColumn())
        .isEqualTo(com.housedevinci.shredding.domain.ColumnRef.unquoted("tenant_id"));
    assertThat(column.tenantProperty()).contains("tenantId");
    assertThat(model.blindIndexColumns()).contains(column);
  }

  /**
   * Change 7's residual, seen from the write side. A row cannot be moved between tenants
   * <em>through Hibernate</em> at all: the tenant is bound into every stored value's header, and
   * {@code refuseIfSubjectMoved} refuses the update rather than re-encrypting the row into another
   * erasure scope. So the only way a row's tenant column can change under a live index is a bulk
   * update outside Hibernate, which fires no listener - the residual change 7 states in {@code
   * SECURITY-NOTES.md} and change 5's WARN surfaces at erasure time. Asserted here so that "the
   * index follows the row" is a checked property of this module and not an assumption.
   */
  @Test
  void probe_a_row_cannot_be_moved_between_tenants_through_hibernate() throws Exception {
    String owner = "moved-" + System.nanoTime();
    OwnedNote saved = ownedNotes.saveAndFlush(new OwnedNote(owner, "org-b", "victim@example.test"));
    byte[] before = indexBytes("owned_note", owner).get(0);

    saved.setTenantId("org-c");
    ShreddingException refusal = refusalOf(() -> ownedNotes.saveAndFlush(saved));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.SUBJECT_IMMUTABLE);
    assertThat(indexBytes("owned_note", owner).get(0))
        .describedAs("the refused move left the index exactly as it was, under org-b")
        .isEqualTo(before);
  }

  /**
   * The refusal a write threw, wherever in the cause chain Hibernate and Spring wrapped it: what
   * matters is that the transaction died with this module's own typed error, not what layer of
   * persistence exception it arrived in.
   */
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

  /** The index bytes for this subject under the tenant the erasure was asked for. */
  private List<byte[]> indexBytes(String table, String owner) throws Exception {
    return query(
        "select "
            + table
            + ".email_idx from "
            + table
            + " where owner_id = ? and email_idx is not null",
        owner);
  }

  /** The index bytes for this subject under any tenant value at all. */
  private List<byte[]> anyIndexBytes(String table, String owner) throws Exception {
    return query("select email_idx from " + table + " where owner_id = ?", owner);
  }

  private List<byte[]> query(String sql, String owner) throws Exception {
    var found = new ArrayList<byte[]>();
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement(sql)) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        while (rs.next()) {
          byte[] bytes = rs.getBytes(1);
          if (bytes != null) {
            found.add(bytes);
          }
        }
      }
    }
    return found;
  }
}
