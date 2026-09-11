package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.autoconfigure.fixture.Doc;
import com.housedevinci.shredding.autoconfigure.fixture.DocRepository;
import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.ShreddingContext;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Service;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** The third pass: em.find/getReference, @Async, and a second EntityManagerFactory. */
@SpringBootTest(classes = CipherProbeMatrix2Test.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeMatrix2Test {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry r) {
    r.add("shredding.master-key", () -> b64("starter-integration-master-key32"));
    r.add("shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    r.add("shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    r.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    r.add(
        "spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EnableAsync
  @EntityScan(basePackageClasses = Widget.class)
  @EnableJpaRepositories(basePackageClasses = WidgetRepository.class)
  static class TestApp {
    @Bean
    AsyncReader asyncReader(DocRepository docs) {
      return new AsyncReader(docs);
    }
  }

  @Service
  static class AsyncReader {
    private final DocRepository docs;

    AsyncReader(DocRepository docs) {
      this.docs = docs;
    }

    @Async
    public Future<String> titleOf(String owner) {
      return java.util.concurrent.CompletableFuture.completedFuture(
          docs.findByOwnerId(owner).get(0).getTitle());
    }
  }

  @Autowired DocRepository docs;
  @Autowired AsyncReader asyncReader;
  @Autowired EntityManager entityManager;
  @Autowired org.springframework.transaction.support.TransactionTemplate tx;
  @Autowired javax.sql.DataSource dataSource;

  private static void report(String what, Runnable body) {
    try {
      body.run();
      System.out.println("MATRIX2 " + what + " -> DECRYPTED (no refusal)");
    } catch (Throwable t) {
      String code = null;
      for (Throwable c = t; c != null; c = c.getCause()) {
        if (c instanceof ShreddingException s) {
          code = s.code();
          break;
        }
      }
      System.out.println(
          "MATRIX2 " + what + " -> " + (code != null ? "REFUSED " + code : "THREW " + t));
    }
  }

  @Test
  void the_second_half_of_the_matrix() throws Exception {
    String owner = "m2-" + System.nanoTime();
    Long id = tx.execute(s -> docs.save(new Doc(owner, "TITLE-M2", "BODY-M2")).getId());

    report(
        "em.find (id known in advance, no repo call)",
        () ->
            tx.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  entityManager.find(Doc.class, id).getTitle();
                }));
    report(
        "em.getReference + field access",
        () ->
            tx.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  entityManager.getReference(Doc.class, id).getTitle();
                }));
    report(
        "em.find inside withReadBracket",
        () ->
            tx.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  ShreddingContext.withReadBracket(
                      () -> entityManager.find(Doc.class, id).getTitle());
                }));
    report(
        "@Async repository call",
        () -> {
          try {
            System.out.println("   async title=" + asyncReader.titleOf(owner).get());
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
        });
    System.out.println("MATRIX2 asyncReader class=" + asyncReader.getClass().getName());
    assertThat(id).isNotNull();
  }

  /**
   * A second EntityManagerFactory: no ShreddingIntegrator, so no listener, so no verification.
   *
   * <p>Before the fix, {@code withReadBracket}'s permission-shaped bracket let this decrypt through
   * with nothing behind it and the moved ciphertext came back to the caller. After the fix, the
   * decode is recorded into the bracket's frame same as any other; no {@code onPostLoad} exists on
   * this uninstrumented factory to drain it (there is no {@code ShreddingIntegrator} registered
   * against it at all), and the frame closes with the entry still in it - {@code withReadBracket}
   * itself throws, before {@code leaked} is ever assigned. This is the runtime path the security
   * review's repro used, and the frame accounting alone already closes it; per C-20, the separate,
   * coarser startup-time defence ({@code ShreddingReadBracketCustomizer} refusing outright when
   * more than one {@code EntityManagerFactory} bean exists) ships without its own dedicated
   * integration probe.
   */
  @Test
  void probe_a_second_entity_manager_factory_decrypts_a_moved_ciphertext() throws Exception {
    String alice = "a-emf2-alice-" + System.nanoTime();
    String bob = "b-emf2-bob-" + System.nanoTime();
    tx.executeWithoutResult(
        s -> {
          docs.save(new Doc(alice, "ALICE-EMF2-SECRET", "alice body"));
          docs.save(new Doc(bob, "bob title", "bob body"));
        });
    Long bobId = tx.execute(s -> docs.findByOwnerId(bob).get(0).getId());
    moveColumn("doc", "title", alice, bob);

    var emfBean = new LocalContainerEntityManagerFactoryBean();
    emfBean.setDataSource(dataSource);
    emfBean.setPackagesToScan(Doc.class.getPackageName());
    emfBean.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
    emfBean.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "none"));
    emfBean.afterPropertiesSet();
    var emf = emfBean.getObject();
    try {
      assertThatThrownBy(
              () -> {
                try (var em = emf.createEntityManager()) {
                  // The same relaxation any Spring Data repository bound to this factory would get.
                  ShreddingContext.withReadBracket(() -> em.find(Doc.class, bobId).getTitle());
                }
              })
          .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNVERIFIED));
    } finally {
      emfBean.destroy();
    }
  }

  private void moveColumn(String table, String column, String fromOwner, String toOwner)
      throws Exception {
    byte[] value;
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement("SELECT " + column + " FROM " + table + " WHERE owner_id = ?")) {
      ps.setString(1, fromOwner);
      try (var rs = ps.executeQuery()) {
        rs.next();
        value = rs.getBytes(1);
      }
    }
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement("UPDATE " + table + " SET " + column + " = ? WHERE owner_id = ?")) {
      ps.setBytes(1, value);
      ps.setString(2, toOwner);
      ps.executeUpdate();
    }
  }

  private static String shreddingCode(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    throw new AssertionError("no ShreddingException in the chain", thrown);
  }
}
