package com.housedevinci.shredding.architecture;

import static com.tngtech.archunit.base.DescribedPredicate.not;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.resideInAnyPackage;
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

  @ArchTest
  static final ArchRule domain_has_no_framework_imports =
      noClasses()
          .that()
          .resideInAPackage("..domain..")
          .should()
          .dependOnClassesThat(
              resideInAnyPackage("javax..")
                  .and(not(resideInAnyPackage("javax.crypto..")))
                  .or(
                      resideInAnyPackage(
                          "org.springframework..",
                          "jakarta..",
                          "java.sql..",
                          "org.slf4j..",
                          "com.fasterxml..",
                          "tools.jackson..",
                          "org.hibernate..",
                          "..application..",
                          "..adapter..")));

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
