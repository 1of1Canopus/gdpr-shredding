package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.propseq.PropSeqWidget;
import com.housedevinci.shredding.autoconfigure.propseq.PropSeqWidgetRepository;
import java.nio.charset.StandardCharsets;
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
 * Cipher sixth pass, design item 14's insert half. {@code onPostInsert} reads the row back with its
 * own {@code SELECT} and refuses any stored header that is not bound to the scope the row was
 * written under - the last line of defence, and the one that does not depend on any of the module's
 * own bookkeeping being right.
 *
 * <p>{@code readStoredShreddedColumns} returns {@code null} when the {@code SELECT} finds no row,
 * and {@code refuseIfStoredHeadersDisagree} then returns without checking anything. With {@code
 * hibernate.jdbc.batch_size} set and an id strategy that permits insert batching (a sequence), the
 * {@code INSERT} is still sitting in the JDBC batch when the post-insert event fires, so the
 * {@code SELECT} finds nothing and the check silently does not happen - for every row of every
 * batch, on an ordinary performance setting no warning mentions.
 *
 * <p>Demonstrated with the mapping the check is currently the only thing that catches: an
 * {@code @Access(AccessType.PROPERTY)} shredded field, whose column Hibernate writes in the clear
 * because a field-level {@code @Convert} does not apply under property access. Without batching the
 * flush aborts with {@code SHRED-FORMAT-001} and nothing is committed. With batching the plaintext
 * is committed.
 */
@SpringBootTest(classes = CipherProbeBatchedInsertCheckTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeBatchedInsertCheckTest {

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
    registry.add("spring.jpa.properties.hibernate.jdbc.batch_size", () -> "10");
    registry.add("spring.jpa.properties.hibernate.order_inserts", () -> "true");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = PropSeqWidget.class)
  @EnableJpaRepositories(basePackageClasses = PropSeqWidgetRepository.class)
  static class TestApp {}

  @Autowired PropSeqWidgetRepository widgets;
  @Autowired DataSource dataSource;
  @Autowired org.springframework.transaction.support.TransactionTemplate transactions;

  @Test
  void probe_the_post_hoc_header_check_still_runs_when_inserts_are_batched() throws Exception {
    String owner = "batched-" + System.nanoTime();
    String outcome;
    try {
      transactions.executeWithoutResult(
          s ->
              widgets.saveAll(
                  List.of(
                      new PropSeqWidget(owner, "BATCHED-SECRET-1"),
                      new PropSeqWidget(owner, "BATCHED-SECRET-2"),
                      new PropSeqWidget(owner, "BATCHED-SECRET-3"))));
      outcome = "COMMITTED";
    } catch (RuntimeException e) {
      outcome = "REFUSED " + e.getClass().getSimpleName();
    }

    String stored;
    try (var connection = dataSource.getConnection();
        var ps =
            connection.prepareStatement(
                "select string_agg(cast(name as text), '|') from prop_seq_widget where owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        stored = rs.next() ? String.valueOf(rs.getObject(1)) : "NO ROW";
      }
    }
    System.out.println("BATCHED INSERT -> " + outcome + "; stored " + stored);
    assertThat(stored).doesNotContain("BATCHED-SECRET");
  }
}
