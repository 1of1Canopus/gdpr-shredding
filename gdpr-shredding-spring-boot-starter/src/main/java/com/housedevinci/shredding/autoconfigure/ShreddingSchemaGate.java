package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.adapter.jdbc.SchemaVerdict;
import com.housedevinci.shredding.adapter.jdbc.VerifiedSchema;
import java.util.Objects;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decides, once and before anything else touches the database, whether the schema this application
 * is pointed at is one whose guards are load-bearing against this application - and hands on the
 * exact {@code DataSource} and schema name it verified.
 *
 * <p>Design §3 of {@code no-ddl-at-runtime-design.md}. Three properties of this bean are the
 * mechanism, and each of them was a hole before:
 *
 * <ol>
 *   <li><b>The work is in the constructor.</b> A failure here is a context that refuses to start,
 *       which is what fail-closed means at boot. There is no "verified" flag anyone can ignore.
 *   <li><b>It is unconditional and eager.</b> Not {@code @ConditionalOnMissingBean}, and not
 *       dependent on either adapter existing - both adapters are {@code @ConditionalOnMissingBean},
 *       so an application that supplies its own {@code KeyProvider} would otherwise remove the only
 *       edge that pulls this in. A {@code LazyInitializationExcludeFilter} registered beside it
 *       (see {@code ShreddingAutoConfiguration}) keeps {@code spring.main.lazy-initialization=true}
 *       from deferring verification to the first erasure. Version 1 of the design treated "the
 *       adapters take the gate as a parameter" as sufficient; that is an ordering edge, not an
 *       eagerness one.
 *   <li><b>It owns the verified {@code DataSource}.</b> Everything downstream takes {@code
 *       gate.dataSource()} rather than injecting by type, so "the DataSource that was verified" and
 *       "the DataSource that is written to" are the same object by construction. With two {@code
 *       DataSource} beans in a context, injection by type can otherwise verify one database and
 *       write to another.
 * </ol>
 *
 * <p>It is also the only place in the starter that may call {@link JdbcSupport#initializeSchema},
 * which an ArchUnit rule asserts.
 */
public final class ShreddingSchemaGate {

  private static final Logger log = LoggerFactory.getLogger(ShreddingSchemaGate.class);

  private final DataSource dataSource;
  private final SchemaVerdict verdict;

  public ShreddingSchemaGate(DataSource dataSource, ShreddingProperties properties) {
    this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    var jdbc = Objects.requireNonNull(properties, "properties").getJdbc();
    this.verdict =
        jdbc.isInitializeSchema()
            ? JdbcSupport.initializeAndVerifySchema(dataSource, true)
            : JdbcSupport.verifySchema(dataSource, jdbc.isAllowPrivilegedRuntimeRole());
    warn(jdbc);
    verdict
        .indexWarnings()
        .forEach(
            index ->
                log.warn(
                    "shredding: the index {} is missing from schema {}. Not a control - the"
                        + " erasure log's guards do not depend on it - but every subject lookup on"
                        + " that table is a sequential scan until it is created. Re-apply"
                        + " schema-postgresql.sql as the owner role.",
                    index,
                    verdict.schema()));
    // Printed in both modes. summary() drops the clause about the role when a leg fired, so the
    // line claims only what was actually established (C-D2-4): an INFO line an auditor reads is a
    // claim, by the same argument a refusal is.
    log.info("shredding: {}", verdict.summary());
  }

  /**
   * Both WARNs fire at <em>every</em> startup, never once. An operator who reads one boot log a
   * month has to see it in that log, and a weaker mode that announces itself only the first time is
   * a weaker mode nobody knows is on.
   */
  private void warn(ShreddingProperties.JdbcProperties jdbc) {
    if (jdbc.isInitializeSchema()) {
      log.warn(
          "shredding: shredding.jdbc.initialize-schema=true. This application is issuing DDL with"
              + " its own database credentials, which means its role owns the erasure tables and"
              + " the guard functions. An owner can ALTER TABLE ... DISABLE TRIGGER, or CREATE OR"
              + " REPLACE the guard functions with a body that allows everything, and then delete"
              + " from shredding_erasure - so the append-only erasure log (control 8) and the"
              + " erasure tombstone (control 11) are not enforced against this application. For"
              + " production: apply schema-postgresql.sql once with an owner role, grant the"
              + " runtime role the statements in SECURITY-NOTES.md \"Database roles\", and leave"
              + " shredding.jdbc.initialize-schema=false. See docs/upgrading-0.2.0.md.");
    }
    if (!verdict.runtimeRoleIsUnprivileged()) {
      log.warn(
          "shredding: {} and the runtime role {} is"
              + " privileged over the shredding objects in schema {}: {}. The append-only controls"
              + " are advisory in this configuration: nothing stops this application from disabling"
              + " or replacing its own guards. Record this in your processing documentation, or"
              + " follow docs/upgrading-0.2.0.md to move the application to a non-privileged role.",
          jdbc.isAllowPrivilegedRuntimeRole()
              ? "shredding.jdbc.allow-privileged-runtime-role=true"
              : "shredding.jdbc.initialize-schema=true implies a role that can run DDL here",
          verdict.role(),
          verdict.schema(),
          String.join("; ", verdict.privilegeLegs()));
    }
  }

  /**
   * The {@code DataSource} this gate verified. Adapters take this, never a {@code DataSource} by
   * type.
   */
  public DataSource dataSource() {
    return dataSource;
  }

  /**
   * The schema {@code current_schema()} resolved to, which every module statement is qualified
   * with.
   */
  public VerifiedSchema schema() {
    return verdict.schema();
  }

  /** What was established, for the health indicator to report rather than re-derive. */
  public SchemaVerdict verdict() {
    return verdict;
  }
}
