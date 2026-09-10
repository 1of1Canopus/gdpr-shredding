package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingContext;
import jakarta.persistence.EntityManager;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.persister.entity.EntityPersister;
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
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Cipher, ninth pass, S-21b. {@code refuseIfSubjectMoved} is the write path's subject-immutability
 * check: before every {@code UPDATE} of a {@code @Shredded} row, it re-reads that row's own stored
 * shredded columns by id and compares the header against the scope the write is happening under.
 * {@code readStoredShreddedColumns} returns {@code null} when its {@code SELECT ... WHERE id = ?}
 * finds no row, and the caller did {@code if (stored == null) { return; }} - silently skipping the
 * check rather than refusing.
 *
 * <p>{@code refuseIfSubjectMoved} is called from {@code onPreUpdate} only: Hibernate is issuing an
 * {@code UPDATE} for a row it believes exists. This probe reproduces "the read-back finds no row"
 * deterministically, without racing a concurrent delete (which Hibernate's own row-count check
 * would catch a moment later anyway, masking the finding): it calls the check directly with an id
 * that addresses no row in the table at all - the same shape as a wrongly-addressed {@code SELECT}
 * - and asserts refusal rather than a silent pass.
 */
@SpringBootTest(classes = CipherProbeSubjectMovedNotFoundTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeSubjectMovedNotFoundTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add("shredding.master-key", () -> b64("s21b-integration-master-key-32b!"));
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("s21b-integration-chain-secret-!!"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("s21b-integration-index-secret-!!"));
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
  @Autowired TransactionTemplate transactions;
  @Autowired ShreddingEventListener listener;

  /**
   * An id that addresses no row of {@code widget} at all - deterministically the same condition
   * {@code readStoredShreddedColumns} hits when the write path's {@code SELECT} is wrongly
   * addressed (S-21): "row not found" while Hibernate is mid-{@code UPDATE} of a row it believes
   * exists. The only legitimate "not found" for a {@code @Shredded} entity is a brand-new row on
   * insert, and that is a different path ({@code onPreInsert}/{@code onPostInsert}) which never
   * calls {@code refuseIfSubjectMoved} at all.
   */
  @Test
  void probe_the_subject_immutability_check_refuses_when_the_read_back_finds_no_row()
      throws Exception {
    String owner = "s21b-" + System.nanoTime();
    Long id = transactions.execute(s -> widgets.save(new Widget(owner, "before-erasure")).getId());
    long noSuchId = id + 1_000_000L;

    Method refuseIfSubjectMoved =
        ShreddingEventListener.class.getDeclaredMethod(
            "refuseIfSubjectMoved",
            SharedSessionContractImplementor.class,
            EntityPersister.class,
            Object.class,
            List.class,
            ShreddingContext.Scope.class);
    refuseIfSubjectMoved.setAccessible(true);

    Method modelMethod = ShreddingEventListener.class.getDeclaredMethod("model");
    modelMethod.setAccessible(true);

    ShreddingException refusal =
        transactions.execute(
            s -> {
              Widget managed = widgets.findById(id).orElseThrow();
              SharedSessionContractImplementor session =
                  entityManager.unwrap(SharedSessionContractImplementor.class);
              EntityPersister persister = session.getEntityPersister(null, managed);
              ShreddedModel model;
              try {
                model = (ShreddedModel) modelMethod.invoke(listener);
              } catch (ReflectiveOperationException e) {
                throw new IllegalStateException(e);
              }
              var fields = model.byEntityName().get("Widget");
              assertThat(fields)
                  .describedAs("Widget must be a mapped @Shredded entity")
                  .isNotEmpty();
              var scope =
                  new ShreddingContext.Scope(
                      TenantId.of("default"),
                      SubjectId.of(owner),
                      "Widget",
                      RowId.ofIdentifier(noSuchId));
              try {
                refuseIfSubjectMoved.invoke(listener, session, persister, noSuchId, fields, scope);
              } catch (java.lang.reflect.InvocationTargetException e) {
                if (e.getCause() instanceof ShreddingException se) {
                  return se;
                }
                throw new IllegalStateException(e.getCause());
              } catch (ReflectiveOperationException e) {
                throw new IllegalStateException(e);
              }
              return null;
            });

    assertThat(refusal)
        .describedAs(
            "S-21b: a SELECT that found no row for an id Hibernate believes exists must refuse, not"
                + " return silently and let the write proceed unverified")
        .isNotNull();
    assertThat(refusal.code()).isEqualTo(ErrorCodes.UNVERIFIED_WRITE);
  }
}
