package com.housedevinci.shredding.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.housedevinci.shredding.adapter.jdbc.VerifiedSchema;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaConstructorCall;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

/**
 * The domain boundary: no framework, no JPA, no JDBC, nothing but the JDK.
 *
 * <p>Module B's carve-out is kept: {@code javax.crypto} (java.base since JDK 9) is the one
 * permitted package under {@code javax..}, and it is the whole of this module's cryptography
 * (control 18: no BouncyCastle, no crypto dependency at all in core).
 */
@AnalyzeClasses(
    packages = "com.housedevinci.shredding",
    importOptions = ImportOption.DoNotIncludeTests.class)
class HexagonalArchitectureTest {

  /**
   * L1: an allowlist, not a denylist. The house rule and control 18 both say {@code domain} is JDK
   * only; a denylist of framework packages holds only for as long as somebody keeps adding to it,
   * and today one added compile dependency to {@code gdpr-shredding-core/pom.xml} would make Guava,
   * Netty or commons-lang legal in {@code domain} without this rule ever failing. An allowlist
   * fails the moment anything not {@code java..}, {@code javax.crypto..} or the domain package
   * itself is imported, which is what "JDK only" actually means.
   */
  @ArchTest
  static final ArchRule domain_has_no_framework_imports =
      classes()
          .that()
          .resideInAPackage("..domain..")
          .should()
          .onlyDependOnClassesThat()
          .resideInAnyPackage("java..", "javax.crypto..", "com.housedevinci.shredding.domain..");

  /**
   * Design addendum 4, change 13. {@code ColumnRef} is the type S-22's fix hangs on and the one
   * most likely to be "just given" an {@code Identifier} or a {@code Dialect} field by a later
   * change, which would drag Hibernate into the domain. Named on its own so the failure says so.
   */
  @ArchTest
  static final ArchRule column_ref_imports_nothing_outside_the_jdk =
      classes()
          .that()
          .haveFullyQualifiedName("com.housedevinci.shredding.domain.ColumnRef")
          .should()
          .onlyDependOnClassesThat()
          .resideInAnyPackage("java..", "com.housedevinci.shredding.domain..");

  @ArchTest
  static final ArchRule domain_imports_no_crypto_library =
      noClasses()
          .that()
          .resideInAPackage("..domain..")
          .should()
          .dependOnClassesThat()
          .resideInAnyPackage("org.bouncycastle..", "com.google.crypto..", "org.conscrypt..");

  @ArchTest
  static final ArchRule application_depends_only_on_domain_and_jdk =
      noClasses()
          .that()
          .resideInAPackage("..application..")
          .should()
          .dependOnClassesThat()
          .resideInAnyPackage(
              "org.springframework..",
              "jakarta..",
              "javax.crypto..",
              "java.sql..",
              "org.hibernate..",
              "..adapter..");

  @ArchTest
  static final ArchRule api_is_annotations_only_and_framework_free =
      noClasses()
          .that()
          .resideInAPackage("..api..")
          .should()
          .dependOnClassesThat()
          .resideInAnyPackage("org.springframework..", "org.hibernate..", "..adapter..");

  /**
   * C-PR-1, path P11. {@code VerifiedSchema} stands for "this schema, verified on this DataSource",
   * so the only production code that may construct one is {@code SchemaVerification} (its nested
   * {@code Session} included), which does so after the catalogue checks on a connection of that
   * DataSource. Package-private access alone would let any later class in the package mint one.
   */
  /** Package-private, so named rather than referenced. */
  private static final String SCHEMA_VERIFICATION =
      "com.housedevinci.shredding.adapter.jdbc.SchemaVerification";

  @ArchTest
  static final ArchRule only_SchemaVerification_constructs_VerifiedSchema =
      noClasses()
          .that(
              DescribedPredicate.describe(
                  "are not SchemaVerification or nested in it",
                  (JavaClass c) ->
                      !c.getName().equals(SCHEMA_VERIFICATION)
                          && !c.getName().startsWith(SCHEMA_VERIFICATION + "$")))
          .should()
          .callConstructorWhere(
              DescribedPredicate.describe(
                  "a constructor of VerifiedSchema",
                  (JavaConstructorCall call) ->
                      call.getTargetOwner().isEquivalentTo(VerifiedSchema.class)));
}
