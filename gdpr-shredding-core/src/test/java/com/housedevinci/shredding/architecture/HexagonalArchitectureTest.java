package com.housedevinci.shredding.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

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
}
