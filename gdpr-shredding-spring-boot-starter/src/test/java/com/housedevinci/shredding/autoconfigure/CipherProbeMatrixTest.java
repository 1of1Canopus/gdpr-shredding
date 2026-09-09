package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.fixture.Blob;
import com.housedevinci.shredding.autoconfigure.fixture.BlobRepository;
import com.housedevinci.shredding.autoconfigure.fixture.Dao;
import com.housedevinci.shredding.autoconfigure.fixture.Doc;
import com.housedevinci.shredding.autoconfigure.fixture.DocMatrixRepository;
import com.housedevinci.shredding.autoconfigure.fixture.DocRepository;
import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.domain.ShreddingException;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** Cipher third pass: the read-path matrix. Each case prints REFUSE / VERIFY / LEAK. */
@SpringBootTest(classes = CipherProbeMatrixTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeMatrixTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry r) {
    r.add("shredding.master-key", () -> b64("starter-integration-master-key32"));
    r.add("shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    r.add("shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    r.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Widget.class)
  @EnableJpaRepositories(basePackageClasses = WidgetRepository.class)
  @ComponentScan(basePackageClasses = Dao.class)
  static class TestApp {}

  @Autowired DocRepository docs;
  @Autowired DocMatrixRepository matrix;
  @Autowired BlobRepository blobs;
  @Autowired Dao dao;
  @Autowired EntityManager entityManager;
  @Autowired org.springframework.transaction.support.TransactionTemplate tx;
  @Autowired javax.sql.DataSource dataSource;

  private String seed(String tag) {
    String owner = tag + "-" + System.nanoTime();
    tx.executeWithoutResult(s -> docs.save(new Doc(owner, "TITLE-" + tag, "BODY-" + tag)));
    return owner;
  }

  private static void report(String what, Runnable body) {
    try {
      body.run();
      System.out.println("MATRIX " + what + " -> DECRYPTED (no refusal)");
    } catch (Throwable t) {
      String code = null;
      for (Throwable c = t; c != null; c = c.getCause()) {
        if (c instanceof ShreddingException s) {
          code = s.code();
          break;
        }
      }
      System.out.println(
          "MATRIX " + what + " -> " + (code != null ? "REFUSED " + code : "THREW " + t));
    }
  }

  @Test
  void the_read_path_matrix() {
    String o = seed("matrix");
    report(
        "repo.findById",
        () -> tx.executeWithoutResult(s -> docs.findById(idOf(o)).get().getTitle()));
    report(
        "repo.derived",
        () -> tx.executeWithoutResult(s -> docs.findByOwnerId(o).get(0).getTitle()));
    report(
        "repo.Page",
        () ->
            tx.executeWithoutResult(
                s ->
                    matrix
                        .findPageByOwnerId(o, PageRequest.of(0, 10))
                        .getContent()
                        .get(0)
                        .getTitle()));
    report(
        "repo.Slice",
        () ->
            tx.executeWithoutResult(
                s ->
                    matrix
                        .findSliceByOwnerId(o, PageRequest.of(0, 10))
                        .getContent()
                        .get(0)
                        .getTitle()));
    report(
        "repo.Streamable",
        () ->
            tx.executeWithoutResult(
                s -> matrix.findStreamableByOwnerId(o).toList().get(0).getTitle()));
    report(
        "repo.Specification",
        () ->
            tx.executeWithoutResult(
                s ->
                    matrix
                        .findAll((root, q, cb) -> cb.equal(root.get("ownerId"), o))
                        .get(0)
                        .getTitle()));
    report(
        "repo.nativeQuery.rawBytes",
        () ->
            tx.executeWithoutResult(
                s -> {
                  var raw = matrix.rawTitles(o);
                  System.out.println("   raw bytes=" + raw.get(0).length);
                }));
    report(
        "em.find",
        () ->
            tx.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  Doc d = entityManager.find(Doc.class, idOf(o));
                  d.getTitle();
                }));
    report(
        "em.getReference+access",
        () ->
            tx.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  Doc d = entityManager.getReference(Doc.class, idOf(o));
                  d.getTitle();
                }));
    report(
        "em.createQuery(entity)",
        () ->
            tx.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  entityManager
                      .createQuery("select d from Doc d where d.ownerId = :i", Doc.class)
                      .setParameter("i", o)
                      .getSingleResult()
                      .getTitle();
                }));
    report(
        "criteria(entity)",
        () ->
            tx.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  var cb = entityManager.getCriteriaBuilder();
                  var q = cb.createQuery(Doc.class);
                  var root = q.from(Doc.class);
                  q.select(root).where(cb.equal(root.get("ownerId"), o));
                  entityManager.createQuery(q).getSingleResult().getTitle();
                }));
    report(
        "criteria(scalar projection)",
        () ->
            tx.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  var cb = entityManager.getCriteriaBuilder();
                  var q = cb.createQuery(String.class);
                  var root = q.from(Doc.class);
                  q.select(root.get("title")).where(cb.equal(root.get("ownerId"), o));
                  entityManager.createQuery(q).getSingleResult();
                }));
    report(
        "hand-written @Repository DAO (unproxied)",
        () ->
            tx.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  dao.findByOwner(o).get(0).getTitle();
                }));
    report(
        "repo call, entity read after the tx/bracket closes",
        () -> {
          Doc detached =
              tx.execute(
                  s -> {
                    entityManager.clear();
                    return docs.findByOwnerId(o).get(0);
                  });
          detached.getTitle();
        });
    report(
        "repo call on another thread (async shape)",
        () -> {
          try (var ex = Executors.newVirtualThreadPerTaskExecutor()) {
            ex.submit(() -> tx.execute(s -> docs.findByOwnerId(o).get(0).getTitle())).get();
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
        });
    System.out.println(
        "MATRIX repo proxy class = "
            + docs.getClass().getName()
            + " isJdkProxy="
            + java.lang.reflect.Proxy.isProxyClass(docs.getClass()));
    assertThat(o).isNotNull();
  }

  /**
   * C-21: {@code @Immutable} on {@code byte[]} is what stops {@code
   * AttributeConverterMutabilityPlan} deep-copying the converted value to build Hibernate's
   * dirty-checking snapshot (that deep copy, happening a second time outside the write bracket, was
   * CIPHER-16's original bug). Losing that copy is not a bug to fix, it is the direct, permanent
   * cost of the annotation the module requires: with no snapshot copy, an in-place mutation of the
   * array a {@code @Shredded byte[]} field holds is compared against itself and is never seen as
   * dirty. No exception, no log line, no {@code UPDATE} - this probe demonstrates exactly that,
   * confirming the documentation this pass corrects (README.md, docs/index.md, and the startup
   * message in {@code ShreddedModel}) tells the truth. See QUESTIONS.md C-21: making this probe
   * assert the opposite would mean deep-copying the array again, which reopens CIPHER-16.
   */
  @Test
  /**
   * C-31 (fourth pass): renamed from {@code
   * probe_an_in_place_mutation_of_an_immutable_byte_array_is_persisted}. The old name promised the
   * opposite of what the body asserts: the assertion ({@code reloaded[0] == 1}, i.e. the mutation
   * is lost) is correct and was correct before this rename too - it is what C-21's corrected
   * documentation says happens, and Cipher's own third-pass fix text for C-21 rules out making the
   * mutation actually persist (that would reintroduce CIPHER-16's IDENTITY-insert failure). Only
   * the name was wrong; QUESTIONS.md #18 records the ruling.
   */
  void probe_an_in_place_mutation_of_an_immutable_byte_array_is_silently_discarded() {
    String owner = "blob-mut-" + System.nanoTime();
    byte[] payload = {1, 2, 3, 4};
    tx.executeWithoutResult(s -> blobs.save(new Blob(owner, payload)));

    tx.executeWithoutResult(
        s -> {
          entityManager.clear();
          Blob b = blobs.findByOwnerId(owner).get(0);
          b.getPayload()[0] = 99; // in-place, the only way to change a byte[] with no setter
        });

    byte[] reloaded =
        tx.execute(
            s -> {
              entityManager.clear();
              return blobs.findByOwnerId(owner).get(0).getPayload();
            });
    System.out.println("MATRIX @Immutable in-place mutation -> stored[0]=" + reloaded[0]);
    assertThat(reloaded[0]).isEqualTo((byte) 1);
  }

  private Long idOf(String owner) {
    return tx.execute(s -> docs.findByOwnerId(owner).get(0).getId());
  }
}
