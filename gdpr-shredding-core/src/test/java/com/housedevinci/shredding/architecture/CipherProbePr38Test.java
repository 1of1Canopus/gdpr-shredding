package com.housedevinci.shredding.architecture;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.adapter.jdbc.CipherProbePr38MintFixtures;
import com.housedevinci.shredding.adapter.jdbc.SchemaVerdict;
import com.housedevinci.shredding.adapter.jdbc.VerifiedSchema;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import java.io.Serializable;
import org.junit.jupiter.api.Test;

/**
 * Security review, PR 38 (C-PR-1) pass 1, 2026-10-16. Two files: this one in {@code
 * gdpr-shredding-core/src/test/java/com/housedevinci/shredding/architecture/} and {@code
 * CipherProbePr38MintFixtures.java} in {@code .../adapter/jdbc/} of the same test tree.
 *
 * <p>The rule {@code only_SchemaVerification_constructs_VerifiedSchema} is the P11 control for the
 * module's own {@code main}. It matches {@code callConstructorWhere}, so it sees {@code new
 * VerifiedSchema(...)} and misses a constructor reference ({@code VerifiedSchema::new}), which
 * ArchUnit models as a {@code JavaConstructorReference}, not a call. Measured by mutation M7: a
 * {@code BiFunction} field holding {@code VerifiedSchema::new} added to {@code JdbcSupport} keeps
 * the whole core suite green.
 */
class CipherProbePr38Test {

  private static JavaClasses fixtures() {
    return new ClassFileImporter()
        .importClasses(
            CipherProbePr38MintFixtures.ByCall.class,
            CipherProbePr38MintFixtures.ByReference.class,
            VerifiedSchema.class);
  }

  /** Control: the harness works, a direct call is a violation today. */
  @Test
  void control_a_constructor_call_outside_SchemaVerification_is_a_violation() {
    var classes =
        new ClassFileImporter()
            .importClasses(CipherProbePr38MintFixtures.ByCall.class, VerifiedSchema.class);
    assertThat(
            HexagonalArchitectureTest.only_SchemaVerification_constructs_VerifiedSchema
                .evaluate(classes)
                .hasViolation())
        .isTrue();
  }

  /** RED on c09f9b4. */
  @Test
  void probe_a_constructor_reference_outside_SchemaVerification_passes_the_rule() {
    var classes =
        new ClassFileImporter()
            .importClasses(CipherProbePr38MintFixtures.ByReference.class, VerifiedSchema.class);
    assertThat(
            HexagonalArchitectureTest.only_SchemaVerification_constructs_VerifiedSchema
                .evaluate(classes)
                .hasViolation())
        .describedAs("VerifiedSchema::new outside SchemaVerification must be a violation")
        .isTrue();
  }

  /** Characterisation, green: the capability cannot be copied by serialization or clone. */
  @Test
  void verified_schema_and_verdict_cannot_be_copied_by_serialization_or_clone() {
    assertThat(Serializable.class.isAssignableFrom(VerifiedSchema.class)).isFalse();
    assertThat(Cloneable.class.isAssignableFrom(VerifiedSchema.class)).isFalse();
    assertThat(Serializable.class.isAssignableFrom(SchemaVerdict.class)).isFalse();
    assertThat(fixtures().contain(VerifiedSchema.class)).isTrue();
  }
}
