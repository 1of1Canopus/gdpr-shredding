package com.housedevinci.shredding.adapter.jdbc;

import java.util.List;
import java.util.Map;

/**
 * What the bundled {@code schema-postgresql.sql} produces, as a constant.
 *
 * <p>Design §4.2 and §14.1. The security review asked for the expectation to be derived from the
 * script's own {@code CREATE TABLE} bodies at run time; that was refused with reasons and the
 * refusal was accepted. Parsing DDL inside a security control means shipping a small DDL parser,
 * and a parser that mishandles one type modifier or one inline {@code CHECK} under-specifies the
 * expectation - it fails <em>open</em>, silently weakening every leg built on it. A build-time test
 * prevents the same drift with no parser in the product: {@code SchemaVerificationTest} applies the
 * bundled script to a real PostgreSQL and asserts the catalogue equals this constant, so an edit to
 * the script that is not reflected here fails the build.
 *
 * <p>The guard function <em>bodies</em> are the one thing that is not a constant: they are
 * extracted from the same classpath resource at run time ({@link GuardBodies}), because a
 * hard-coded digest and the shipped script can drift apart, and because the bodies are delimited by
 * {@code $$ ... $$}, so reading them is a scan rather than a parse.
 */
final class SchemaExpectations {

  private SchemaExpectations() {}

  static final String DATA_KEY = "shredding_data_key";
  static final String ERASED_SUBJECT = "shredding_erased_subject";
  static final String ERASURE = "shredding_erasure";
  static final String ANCHOR = "shredding_erasure_anchor";
  static final String SEQUENCE = "shredding_erasure_seq_seq";

  static final List<String> TABLES = List.of(DATA_KEY, ERASED_SUBJECT, ERASURE, ANCHOR);

  /** Performance, not a control. A missing one is a WARN; owning one is a refusal (§4.6.2). */
  static final List<String> INDEXES =
      List.of("shredding_data_key_subject", "shredding_erasure_subject");

  /**
   * The exact {@code pg_proc.proconfig} the schema step gives all three guards, compared element by
   * element in Java and never as a SQL predicate.
   *
   * <p>Design {@code name-resolution-design.md} §2.4 and §2.6, finding C-13-14. A guard function is
   * not {@code SECURITY DEFINER}, so without a {@code SET search_path} clause its body resolves its
   * operator, function and type names in the session of whoever writes to the table - and the role
   * that writes is the role the guard exists to constrain. Version 1 of this expectation required
   * the opposite ({@code proconfig IS NULL}), on the reasoning that a {@code proconfig} is also how
   * a guard gets redirected; the leg is inverted rather than dropped, so the column is still
   * verified material, with exactly one accepted value instead of exactly one refused shape.
   *
   * <p>Three things make the exact comparison necessary rather than fussy. {@code CREATE OR REPLACE
   * FUNCTION} with no {@code SET} clause clears the column with <b>no error</b>, so re-applying an
   * older copy of the script disarms the clause silently and only an equality check sees it. A
   * second setting (say {@code statement_timeout}) makes the array two elements long, and the
   * expectation is about the whole array. And a SQL-side comparison of a NULL {@code proconfig}
   * evaluates to NULL rather than to false, which drops the row and reports the guard as absent
   * instead of unguarded - so the array is read into Java and compared here.
   *
   * <p>{@code pg_temp} is named for a measured reason: the implicit {@code pg_temp} precedes the
   * path for <em>relation</em> references, and naming it explicitly is the only way to demote it.
   * The three bodies name no relation today; the clause costs about a microsecond per invocation
   * and removes the question for whatever a body names next.
   *
   * <p>Three spellings of the clause store this identical text ({@code = pg_catalog, pg_temp},
   * {@code = pg_catalog,pg_temp} and {@code = "pg_catalog", pg_temp}). {@code SET search_path TO
   * 'pg_catalog, pg_temp'} stores {@code search_path="pg_catalog, pg_temp"}, which means the same
   * to the server and is refused here: a hand-edited schema is a schema this module cannot compare,
   * and unverifiable is not clean. The one supported producer is the bundled script, which {@code
   * SchemaVerificationTest} asserts produces exactly this.
   */
  static final List<String> GUARD_PROCONFIG = List.of("search_path=pg_catalog, pg_temp");

  static final List<String> GUARD_FUNCTIONS =
      List.of(
          "shredding_erasure_append_only",
          "shredding_erasure_anchor_monotonic",
          "shredding_erasure_anchor_append_only");

  /** name, {@code attnotnull}, {@code format_type}. Ordinal is the position in the list. */
  record Column(String name, boolean notNull, String type) {}

  static final Map<String, List<Column>> COLUMNS =
      Map.of(
          DATA_KEY,
              List.of(
                  new Column("tenant", true, "character varying(255)"),
                  new Column("subject", true, "character varying(255)"),
                  new Column("version", true, "integer"),
                  new Column("wrapped_key", true, "bytea"),
                  new Column("state", true, "character varying(16)"),
                  new Column("encryption_count", true, "bigint"),
                  new Column("created_at", true, "timestamp with time zone")),
          ERASED_SUBJECT,
              List.of(
                  new Column("tenant", true, "character varying(255)"),
                  new Column("subject", true, "character varying(255)"),
                  new Column("erased_at", true, "timestamp with time zone")),
          ERASURE,
              List.of(
                  new Column("seq", true, "bigint"),
                  new Column("ts", true, "timestamp with time zone"),
                  new Column("tenant", true, "character varying(255)"),
                  new Column("subject_pseudonym", true, "character(64)"),
                  new Column("requested_by", true, "character varying(1000)"),
                  new Column("reason", true, "character varying(1000)"),
                  new Column("keys_destroyed", true, "integer"),
                  new Column("entity_count", true, "integer"),
                  new Column("field_count", true, "integer"),
                  new Column("blind_index_cleared", true, "integer"),
                  new Column("outcome", true, "character varying(16)"),
                  new Column("hook_outcomes", true, "text"),
                  new Column("backup_clear_at", true, "timestamp with time zone"),
                  new Column("chain_version", true, "character varying(8)"),
                  new Column("key_id", true, "character varying(64)"),
                  new Column("prev_hash", true, "character(64)"),
                  new Column("hash", true, "character(64)")),
          ANCHOR,
              List.of(
                  new Column("id", true, "smallint"),
                  new Column("head_hash", true, "character(64)"),
                  new Column("row_count", true, "bigint"),
                  new Column("updated_at", true, "timestamp with time zone"),
                  new Column("keyed", true, "boolean")));

  static final int COLUMN_COUNT = COLUMNS.values().stream().mapToInt(List::size).sum();

  /**
   * Compared on {@code contype} and {@code pg_get_constraintdef}, never on the name alone: a {@code
   * UNIQUE} moved to another column keeps its name.
   */
  record Constraint(String table, String name, String type, String definition) {}

  static final List<Constraint> CONSTRAINTS =
      List.of(
          new Constraint(
              DATA_KEY, "shredding_data_key_pkey", "p", "PRIMARY KEY (tenant, subject, version)"),
          new Constraint(
              ERASED_SUBJECT,
              "shredding_erased_subject_pkey",
              "p",
              "PRIMARY KEY (tenant, subject)"),
          new Constraint(ERASURE, "shredding_erasure_pkey", "p", "PRIMARY KEY (seq)"),
          new Constraint(ERASURE, "shredding_erasure_hash_key", "u", "UNIQUE (hash)"),
          new Constraint(ANCHOR, "shredding_erasure_anchor_pkey", "p", "PRIMARY KEY (id)"),
          new Constraint(ANCHOR, "shredding_erasure_anchor_id_check", "c", "CHECK ((id = 1))"));

  /**
   * Exhaustive, not existential (§4.4). An eighth trigger is a refusal: a {@code BEFORE INSERT ...
   * RETURN NULL} makes every append vanish with no error, and version 1's "are my seven there"
   * check called that clean. Internal triggers ({@code tgisinternal}) are deliberately outside this
   * set - a foreign key onto the erasure log adds two of them and the append-only trigger still
   * fires on a cascaded delete - while a user {@code CREATE CONSTRAINT TRIGGER} lands inside it.
   *
   * <p>{@code tgtype}: 27 = ROW|BEFORE|DELETE|UPDATE, 34 = statement BEFORE TRUNCATE, 19 =
   * ROW|BEFORE|UPDATE, 11 = ROW|BEFORE|DELETE.
   */
  record Trigger(String name, String table, String function, int type) {}

  static final List<Trigger> TRIGGERS =
      List.of(
          new Trigger(
              "shredding_erasure_append_only", ERASURE, "shredding_erasure_append_only", 27),
          new Trigger(
              "shredding_erasure_no_truncate", ERASURE, "shredding_erasure_append_only", 34),
          new Trigger(
              "shredding_erased_subject_append_only",
              ERASED_SUBJECT,
              "shredding_erasure_append_only",
              27),
          new Trigger(
              "shredding_erased_subject_no_truncate",
              ERASED_SUBJECT,
              "shredding_erasure_append_only",
              34),
          new Trigger(
              "shredding_erasure_anchor_monotonic",
              ANCHOR,
              "shredding_erasure_anchor_monotonic",
              19),
          new Trigger(
              "shredding_erasure_anchor_no_delete",
              ANCHOR,
              "shredding_erasure_anchor_append_only",
              11),
          new Trigger(
              "shredding_erasure_anchor_no_truncate",
              ANCHOR,
              "shredding_erasure_anchor_append_only",
              34));

  /**
   * The per-table privilege matrix of §4.6.6, measured against the corrected grant block. "No
   * DELETE or TRUNCATE anywhere" was both too wide and too narrow: {@code UPDATE} on the erasure
   * log, {@code TRIGGER} and {@code REFERENCES} all passed it, and {@code TRIGGER} on a table is
   * enough for a non-owner to add a trigger of their own to the erasure log.
   *
   * @param required table-level privileges the adapters cannot work without ({@code 007} if
   *     missing)
   * @param refused table-level privileges nothing on the path needs ({@code 004} if held)
   * @param updatableColumn the one column the module updates, or {@code null} for none
   */
  record TablePrivileges(
      String table, List<String> required, List<String> refused, String updatableColumn) {}

  static final List<TablePrivileges> PRIVILEGES =
      List.of(
          new TablePrivileges(
              DATA_KEY,
              List.of("SELECT", "INSERT", "DELETE"),
              List.of("UPDATE", "TRUNCATE", "TRIGGER", "REFERENCES"),
              "encryption_count"),
          new TablePrivileges(
              ERASED_SUBJECT,
              List.of("SELECT", "INSERT"),
              List.of("UPDATE", "DELETE", "TRUNCATE", "TRIGGER", "REFERENCES"),
              "erased_at"),
          new TablePrivileges(
              ERASURE,
              List.of("SELECT", "INSERT"),
              List.of("UPDATE", "DELETE", "TRUNCATE", "TRIGGER", "REFERENCES"),
              null),
          new TablePrivileges(
              ANCHOR,
              List.of("SELECT", "INSERT", "UPDATE"),
              List.of("DELETE", "TRUNCATE", "TRIGGER", "REFERENCES"),
              null));
}
