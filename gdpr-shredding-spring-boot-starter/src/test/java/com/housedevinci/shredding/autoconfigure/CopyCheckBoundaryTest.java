package com.housedevinci.shredding.autoconfigure;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TableRef;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Optional;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.junit.jupiter.api.Test;

/**
 * Audit-table coverage, rows 13, 14 and 44: who may read Envers and Hibernate's incubating audit
 * API, and what an unreadable metamodel means.
 */
class CopyCheckBoundaryTest {

  private static final com.tngtech.archunit.core.domain.JavaClasses STARTER =
      new ClassFileImporter()
          .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
          .importPackages("com.housedevinci.shredding");

  /** E13 / row 14: an application without Envers loads no class that imports it. */
  @Test
  void e13_only_envers_copy_check_imports_envers() {
    noClasses()
        .that()
        .doNotHaveSimpleName("EnversCopyCheck")
        .should()
        .dependOnClassesThat()
        .resideInAPackage("org.hibernate.envers..")
        .check(STARTER);
  }

  /** Row 14 widened with C1: the incubating audit and history API is read in one place. */
  @Test
  void only_hibernate_copy_check_reads_the_audit_and_history_api() {
    noClasses()
        .that()
        .doNotHaveSimpleName("HibernateCopyCheck")
        .should()
        .dependOnClassesThat()
        .haveFullyQualifiedName("org.hibernate.metamodel.mapping.AuditMapping")
        .orShould()
        .dependOnClassesThat()
        .haveFullyQualifiedName("org.hibernate.metamodel.mapping.TemporalMapping")
        .orShould()
        .dependOnClassesThat()
        .resideInAnyPackage("org.hibernate.audit..", "org.hibernate.temporal..")
        .check(STARTER);
  }

  /** E12 / N8: a metamodel that throws is unverifiable, never a pass. */
  @Test
  void e12_n8_an_unreadable_metamodel_is_unverifiable() {
    var factory =
        (SessionFactoryImplementor)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {SessionFactoryImplementor.class},
                (proxy, method, args) -> {
                  throw new IllegalStateException("probe: the metamodel API moved");
                });
    var field =
        new ShreddedModel.BlindIndexField(
            Object.class,
            "Note",
            "emailIndex",
            "email",
            null,
            "owner_id",
            "tenant_id",
            Optional.of(
                new BlindIndexColumn(
                    TableRef.parse("public.note"),
                    ColumnRef.unquoted("email_idx"),
                    ColumnRef.unquoted("owner_id"),
                    ColumnRef.unquoted("tenant_id"),
                    Optional.of("tenantId"),
                    Optional.of("ownerId"))));

    Throwable thrown = catchThrowable(() -> HibernateCopyCheck.check(factory, List.of(field)));

    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    assertThat(thrown).hasMessageContaining("Unverifiable is not clean");
  }
}
