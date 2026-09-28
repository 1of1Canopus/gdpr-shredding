package com.housedevinci.shredding.adapter.jdbc;

import java.util.List;
import java.util.Objects;

/**
 * What {@link JdbcSupport#verifySchema(javax.sql.DataSource, boolean)} established.
 *
 * <p>Design §4.8, amended for C-D2-4. A refusal is a claim and so is the success line: "role not
 * privileged" is a global statement over a check that is a list of legs, and an INFO line an
 * auditor reads must claim only the legs that actually ran. {@link #summary()} therefore enumerates
 * what was compared, and the clause about the role is only printed when {@link #privilegeLegs()} is
 * empty - when it is not, the caller prints the weaker-mode WARN instead, naming the legs.
 *
 * @param privilegeLegs the {@code SHRED-SCHEMA-004} legs that fired and were suppressed by {@code
 *     shredding.jdbc.allow-privileged-runtime-role=true}. Empty on the hardened path.
 * @param indexWarnings the non-control indexes that are missing. Performance, never a refusal.
 */
public record SchemaVerdict(
    VerifiedSchema schema,
    String role,
    String database,
    List<String> privilegeLegs,
    List<String> indexWarnings) {

  public SchemaVerdict {
    Objects.requireNonNull(schema, "schema");
    Objects.requireNonNull(role, "role");
    Objects.requireNonNull(database, "database");
    privilegeLegs = List.copyOf(privilegeLegs);
    indexWarnings = List.copyOf(indexWarnings);
  }

  /** True when no {@code 004} leg fired, so the role clause of {@link #summary()} is earned. */
  public boolean runtimeRoleIsUnprivileged() {
    return privilegeLegs.isEmpty();
  }

  /** The one INFO line. Every clause names something that was actually compared. */
  public String summary() {
    return "schema verified in schema "
        + schema.name()
        + " of database "
        + database
        + " as role "
        + role
        + " ("
        + SchemaExpectations.TABLES.size()
        + " tables, "
        + SchemaExpectations.COLUMN_COUNT
        + " columns, "
        + SchemaExpectations.CONSTRAINTS.size()
        + " constraints, 1 sequence, "
        + SchemaExpectations.GUARD_FUNCTIONS.size()
        + " guard functions with the bundled bodies, "
        + SchemaExpectations.TRIGGERS.size()
        + " triggers ENABLE ALWAYS, no rules, no RLS, no policies"
        + (runtimeRoleIsUnprivileged()
            ? "; the role owns none of the 9 objects, holds no privilege on them beyond the"
                + " documented grant set, and holds no CREATE or TEMPORARY in this database"
            : "")
        + "; every statement this module issues is qualified to schema "
        + schema.name()
        + ")";
  }
}
