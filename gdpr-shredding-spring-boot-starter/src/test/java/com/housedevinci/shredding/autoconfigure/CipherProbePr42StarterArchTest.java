package com.housedevinci.shredding.autoconfigure;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.assertj.core.api.Assertions.assertThat;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import javax.sql.ConnectionPoolDataSource;
import javax.sql.DataSource;
import javax.sql.XADataSource;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;

/**
 * Security review of PR 42 (C-PR-1b), pass 1. Finding C-PR42-1.
 *
 * <p>The design's item 9 and SECURITY-NOTES say: "{@code JdbcSupport} is the only class that takes
 * a connection, in core and in the starter". The rule that is meant to hold this ({@code
 * getConnection_is_called_only_inside_JdbcSupport}, a copy in each module) matches three method
 * names on three owner types. The JDK and Spring offer other ways to open a connection from the
 * same {@code DataSource} object, and the starter has spring-jdbc on its compile class path through
 * spring-boot-starter-data-jpa. Each class below opens a connection that skips the fingerprint
 * check, and the rule reports none of them.
 *
 * <p>Starter twin of the core probe: the starter keeps its own copy of the predicate. This probe
 * evaluates the rule's own predicate on those classes. It fails while the predicate misses any of
 * them.
 */
class CipherProbePr42StarterArchTest {

  /** JDBC 4.3: {@code DataSource.createConnectionBuilder().build()}. */
  static final class ByConnectionBuilder {
    static Connection open(DataSource ds) throws SQLException {
      return ds.createConnectionBuilder().build();
    }
  }

  /** Spring: the helper every Spring JDBC component uses. */
  static final class BySpringUtils {
    static Connection open(DataSource ds) {
      return DataSourceUtils.getConnection(ds);
    }
  }

  /** Spring: a template opens and closes its own connection inside {@code query}. */
  static final class ByJdbcTemplate {
    static Integer open(DataSource ds) {
      return new JdbcTemplate(ds).queryForObject("SELECT 1", Integer.class);
    }
  }

  /** JDBC: a pooled or XA data source hands out a connection through another type. */
  static final class ByPooledConnection {
    static Connection open(ConnectionPoolDataSource ds) throws SQLException {
      return ds.getPooledConnection().getConnection();
    }

    static Connection open(XADataSource ds) throws SQLException {
      return ds.getXAConnection().getConnection();
    }
  }

  /** Control: a method reference to getConnection, which the rule claims to cover. */
  static final class ByMethodReference {
    static Supplier<Object> open(DataSource ds) {
      return () -> {
        try {
          JdbcCall call = ds::getConnection;
          return call.get();
        } catch (SQLException e) {
          throw new IllegalStateException(e);
        }
      };
    }

    interface JdbcCall {
      Connection get() throws SQLException;
    }
  }

  @Test
  void probe_connection_rule_misses_builder_pooled_and_spring_paths() {
    List<String> missed = new ArrayList<>();
    for (Class<?> planted :
        List.of(
            ByConnectionBuilder.class,
            BySpringUtils.class,
            ByJdbcTemplate.class,
            ByPooledConnection.class,
            ByMethodReference.class)) {
      JavaClasses classes = new ClassFileImporter().importClasses(planted);
      ArchRule rule =
          noClasses()
              .should()
              .accessTargetWhere(StarterArchitectureTest.ConnectionAccess.TAKES_A_CONNECTION)
              .allowEmptyShould(true);
      if (!rule.evaluate(classes).hasViolation()) {
        missed.add(planted.getSimpleName());
      }
    }
    assertThat(missed)
        .describedAs(
            "classes that open a connection from the verified DataSource without JdbcSupport,"
                + " and that the getConnection rule does not report")
        .isEmpty();
  }
}
