package com.housedevinci.shredding.autoconfigure;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.housedevinci.shredding.adapter.jdbc.VerifiedSchema;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaAccess;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaConstructor;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.net.URISyntaxException;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * C-PR38-3. The starter is the module most likely to grow a helper beside the stores. The core's
 * architecture rules import the core's classes only, so they cannot see the starter. These two
 * rules import the starter's own {@code main} classes (and nothing from the core jar), and refuse:
 *
 * <ol>
 *   <li>a starter class that resides in a core package (a split package with the core), and
 *   <li>any access to a constructor of {@code VerifiedSchema}, by call or by reference.
 * </ol>
 */
class StarterArchitectureTest {

  private static JavaClasses starterMain;

  @BeforeAll
  static void importStarterMainOnly() throws URISyntaxException {
    Path starterClasses =
        Path.of(
            ShreddingAutoConfiguration.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .toURI());
    starterMain =
        new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPath(starterClasses);
  }

  @Test
  void no_starter_class_resides_in_a_core_package() {
    noClasses()
        .should()
        .resideInAnyPackage(
            "com.housedevinci.shredding.adapter..",
            "com.housedevinci.shredding.domain..",
            "com.housedevinci.shredding.application..",
            "com.housedevinci.shredding.api..")
        .because("a starter class in a core package is a split package with the sealed core jar")
        .check(starterMain);
  }

  @Test
  void no_starter_class_touches_a_constructor_of_VerifiedSchema() {
    noClasses()
        .should()
        .accessTargetWhere(
            DescribedPredicate.describe(
                "a constructor of VerifiedSchema, by call or by reference",
                (JavaAccess<?> access) ->
                    access.getTargetOwner().isEquivalentTo(VerifiedSchema.class)
                        && access.getTarget().getName().equals(JavaConstructor.CONSTRUCTOR_NAME)))
        .check(starterMain);
  }
}
