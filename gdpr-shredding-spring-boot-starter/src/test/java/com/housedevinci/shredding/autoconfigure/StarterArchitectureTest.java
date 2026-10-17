package com.housedevinci.shredding.autoconfigure;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.housedevinci.shredding.adapter.jdbc.VerifiedSchema;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaAccess;
import com.tngtech.archunit.core.domain.JavaClass;
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

  /**
   * C-PR-1b, round 2, item 9 and C-PR42-1: the starter takes no connection itself. Its reads go
   * through {@code JdbcSupport.readVerified}, which checks the database before the work; any other
   * way to open a connection would skip that check. The predicate is {@link
   * ConnectionAccess#TAKES_A_CONNECTION}, the twin of the core's, with its own probe.
   */
  @Test
  void getConnection_is_called_only_inside_JdbcSupport() {
    noClasses().should().accessTargetWhere(ConnectionAccess.TAKES_A_CONNECTION).check(starterMain);
  }

  /**
   * The twin of the core's {@code HexagonalArchitectureTest.ConnectionAccess}: this test cannot see
   * core test classes. Keep the two equal. It refuses, by call or by method reference: {@code
   * getConnection} on any {@code DataSource}, {@code DriverManager} or {@code PooledConnection};
   * {@code Driver.connect}; {@code createConnectionBuilder} and {@code ConnectionBuilder.build};
   * {@code getPooledConnection}; {@code getXAConnection}; Spring's {@code DataSourceUtils}; and any
   * class in {@code org.springframework.jdbc.core} (templates, {@code JdbcClient}, {@code
   * SimpleJdbcInsert}, {@code SimpleJdbcCall}).
   */
  static final class ConnectionAccess {
    private ConnectionAccess() {}

    static final DescribedPredicate<JavaAccess<?>> TAKES_A_CONNECTION =
        DescribedPredicate.describe(
            "a JDBC connection taken outside JdbcSupport (DataSource, Driver, pooled or XA"
                + " connection, ConnectionBuilder, Spring DataSourceUtils or JDBC template)",
            (JavaAccess<?> access) -> {
              JavaClass owner = access.getTargetOwner();
              String name = access.getTarget().getName();
              boolean directConnection =
                  name.equals("getConnection")
                      && (owner.isAssignableTo(javax.sql.DataSource.class)
                          || owner.isAssignableTo(javax.sql.PooledConnection.class)
                          || owner.isEquivalentTo(java.sql.DriverManager.class));
              boolean driver =
                  name.equals("connect") && owner.isAssignableTo(java.sql.Driver.class);
              boolean builder =
                  (name.equals("createConnectionBuilder")
                          && owner.isAssignableTo(javax.sql.DataSource.class))
                      || (name.equals("build")
                          && owner.isAssignableTo(java.sql.ConnectionBuilder.class));
              boolean pooledOrXa =
                  (name.equals("getPooledConnection")
                          && owner.isAssignableTo(javax.sql.ConnectionPoolDataSource.class))
                      || (name.equals("getXAConnection")
                          && owner.isAssignableTo(javax.sql.XADataSource.class));
              boolean spring =
                  owner.getName().equals("org.springframework.jdbc.datasource.DataSourceUtils")
                      || owner.getPackageName().equals("org.springframework.jdbc.core")
                      || owner.getPackageName().startsWith("org.springframework.jdbc.core.");
              return directConnection || driver || builder || pooledOrXa || spring;
            });
  }
}
