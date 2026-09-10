package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.Placeholders;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
 * Cipher sixth pass. Design item 2's whole reason for a non-null placeholder is that the write-back
 * check turns "an entity whose install never ran, flushed anyway" into {@code
 * SHRED-PLACEHOLDER-001} instead of a live ciphertext overwritten with a marker. Item 3 then made
 * the comparison reference identity, and {@code
 * FrameworkMatrixTest.a_placeholder_is_never_re_encrypted} asserts that an equal-but-distinct
 * instance is deliberately <em>not</em> recognised.
 *
 * <p>That is the hole. A refused load leaves the entity holding the marker and detaches it; the
 * ordinary things an application then does to a detached entity - serialise it to a DTO and back,
 * {@code new String(...)}, {@code trim()}, a defensive {@code clone()} of a {@code byte[]}, a
 * property-access setter that normalises - all produce a value-equal, reference-distinct copy.
 * Neither {@code ShreddedConverter.convertToDatabaseColumn} nor {@code refusePlaceholdersInState}
 * recognises the copy, so the marker is encrypted straight over the live ciphertext and the real
 * value is gone, silently and irreversibly.
 *
 * <p>Value equality does not reopen item 3: the threat there is an attacker with {@code UPDATE} on
 * the table, and to make a read return the marker they would have to produce a ciphertext of it
 * under the subject's data key, which no amount of {@code UPDATE} gives them. The erased-value
 * marker in the same converter is already compared with {@code equals} for exactly this reason.
 */
@SpringBootTest(classes = CipherProbePlaceholderCopyTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbePlaceholderCopyTest {

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
  @EntityScan(basePackageClasses = Widget.class)
  @EnableJpaRepositories(basePackageClasses = WidgetRepository.class)
  static class TestApp {}

  @Autowired WidgetRepository widgets;
  @Autowired EntityManager entityManager;
  @Autowired org.springframework.transaction.support.TransactionTemplate transactions;

  /**
   * A value-equal copy of the marker must be refused with {@code SHRED-PLACEHOLDER-001}, exactly as
   * the marker instance itself is. Today it is encrypted, and the row's real value is destroyed.
   */
  @Test
  void probe_a_value_equal_copy_of_the_placeholder_is_refused_on_write_back() {
    String owner = "copy-" + System.nanoTime();
    Long id = transactions.execute(s -> widgets.save(new Widget(owner, "COPY-ORIGINAL")).getId());

    // What Jackson, a DTO round trip, trim() or a normalising setter all produce out of an entity
    // that was left holding the marker by a refused load.
    String copy = new String(Placeholders.STRING);

    String outcome;
    try {
      transactions.executeWithoutResult(
          s -> {
            Widget managed = widgets.findById(id).orElseThrow();
            setName(managed, copy);
            entityManager.flush();
          });
      outcome = "WRITTEN";
    } catch (RuntimeException e) {
      outcome = "REFUSED " + codeOf(e);
    }

    String nowStored =
        transactions.execute(
            s -> {
              entityManager.clear();
              try {
                return widgets.findById(id).orElseThrow().getName();
              } catch (RuntimeException e) {
                return "UNREADABLE " + codeOf(e);
              }
            });
    System.out.println("PLACEHOLDER COPY -> " + outcome + "; the row now reads as " + nowStored);

    assertThat(outcome).startsWith("REFUSED " + ErrorCodes.PLACEHOLDER);
    assertThat(nowStored).isEqualTo("COPY-ORIGINAL");
  }

  private static void setName(Widget widget, String value) {
    try {
      var field = Widget.class.getDeclaredField("name");
      field.setAccessible(true);
      field.set(widget, value);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String codeOf(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    return thrown.getClass().getSimpleName();
  }
}
