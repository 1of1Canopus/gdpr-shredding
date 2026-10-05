package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Admitted;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Copied;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Use;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Verdict;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TableRef;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Planner statistics on a blind-index column are a copy of it (audit-table coverage design, section
 * 3b, rows 30, 37, 47 and 48, C13 and the confirmation's item 5): one test per path by which
 * statistics can exist for the column - its own target and stored rows, an expression index, an
 * extended-statistics object, a partial index, partitions and inheritance children, and a stored
 * generated column computed from it - each on PostgreSQL 16 and 17, whose default targets differ
 * ({@code -1} and {@code NULL}).
 *
 * <p>Fixture: the superuser; {@code shred_owner}, owner of schema {@code app}, of every table in it
 * and of the module's own schema; the runtime role {@code shred_app}, {@code NOSUPERUSER}, holding
 * {@code SELECT, UPDATE} on each table, which is the role every verdict below is read as. Rows are
 * written and {@code ANALYZE} run by the owner, as autovacuum would.
 *
 * <p>Deliberately not given the test-only event trigger the other Testcontainers fixtures install
 * (it turns statistics off on every new column, which is what these tests must see undone).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class PlannerStatisticsPostgresTest {

  private static final String OWNER = "shred_owner";
  private static final String APP = "shred_app";
  private static final byte[] SECRET =
      "planner-statistics-chain-secret-32".getBytes(StandardCharsets.UTF_8);
  private static final TenantId T1 = TenantId.of("T1");
  private static final String LABEL = "@BlindIndex Note.emailIndex";

  private final PostgreSQLContainer<?> postgres;
  private final String defaultTargetFact;
  private final List<HikariDataSource> pools = new ArrayList<>();
  private HikariDataSource su;
  private HikariDataSource owner;
  private HikariDataSource app;
  private VerifiedSchema schema;

  PlannerStatisticsPostgresTest(String image, String defaultTargetFact) {
    this.postgres =
        new PostgreSQLContainer<>(
                DockerImageName.parse(image).asCompatibleSubstituteFor("postgres"))
            .withStartupTimeout(Duration.ofMinutes(2));
    this.defaultTargetFact = defaultTargetFact;
  }

  @BeforeAll
  void start() {
    postgres.start();
    su = pool(postgres.getUsername(), postgres.getPassword());
    exec(
        su,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "CREATE ROLE shred_byp LOGIN PASSWORD 'pw' NOSUPERUSER BYPASSRLS",
        "CREATE ROLE shred_reader LOGIN PASSWORD 'pw' NOSUPERUSER",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA app AUTHORIZATION " + OWNER,
        "GRANT USAGE ON SCHEMA app TO " + APP + ", shred_byp, shred_reader");
    owner = pool(OWNER, "pw");
    JdbcSupport.initializeSchema(owner);
    exec(
        owner,
        "GRANT USAGE ON SCHEMA public TO " + APP,
        "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO " + APP,
        "GRANT UPDATE (encryption_count) ON shredding_data_key TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erased_subject TO " + APP,
        "GRANT UPDATE (erased_at) ON shredding_erased_subject TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erasure TO " + APP,
        "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO " + APP,
        "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO " + APP);
    app = pool(APP, "pw");
    schema = JdbcSupport.verifySchema(app, true).schema();
  }

  @AfterAll
  void stop() {
    pools.forEach(HikariDataSource::close);
    postgres.stop();
  }

  // ------------------------------------------------------------------- row 30: the column

  @Test
  void s1_default_statistics_target_on_index_is_refused_with_the_exact_message() {
    table("app.s1", "");

    Verdict verdict = verdict("app.s1");

    assertThat(verdict).isInstanceOf(Copied.class);
    assertThat(((Copied) verdict).message())
        .isEqualTo(
            "shredding: PostgreSQL keeps, or will keep, planner statistics on the blind-index"
                + " column app.s1.email_idx (@BlindIndex Note.emailIndex): "
                + defaultTargetFact
                + ". Statistics store sampled values of the column (most common values, histogram"
                + " bounds); any role with SELECT on the table reads them from pg_stats, and an"
                + " erasure does not remove them. As the table owner run: SET search_path ="
                + " pg_catalog, pg_temp; SET lock_timeout = '5s'; ALTER TABLE app.s1 ALTER COLUMN email_idx SET STATISTICS 0; ALTER TABLE"
                + " app.s1 ALTER COLUMN email_idx TYPE character varying(64) USING email_idx; The"
                + " TYPE statement deletes the statistics already stored; it does not rewrite"
                + " the table but takes an ACCESS EXCLUSIVE lock briefly. See"
                + " docs/upgrading-0.2.0.md, step 3a.");
  }

  @Test
  void s1b_a_raised_target_is_named_with_its_value() {
    table("app.s1b", "");
    exec(owner, "ALTER TABLE app.s1b ALTER COLUMN email_idx SET STATISTICS 250");

    assertThat(copied("app.s1b"))
        .contains("its statistics target is 250, so the next ANALYZE samples it");
  }

  @Test
  void s2_stale_statistics_row_is_refused_after_set_statistics_0() {
    table("app.s2", "");
    analyze("app.s2");
    exec(owner, "ALTER TABLE app.s2 ALTER COLUMN email_idx SET STATISTICS 0");
    assertThat(text(app, statsRows("s2", "email_idx")))
        .describedAs("the runtime role reads the stale row: the copy this check exists for")
        .isEqualTo("1");

    String message = copied("app.s2");

    assertThat(message)
        .contains("app.s2.email_idx (@BlindIndex Note.emailIndex): pg_stats holds sampled values")
        .doesNotContain("statistics target is");
  }

  @Test
  void s3_documented_remedy_admits_and_survives_analyze() {
    table("app.s3", "");
    analyze("app.s3");

    exec(owner, remedy(copied("app.s3")));
    assertThat(verdict("app.s3")).isInstanceOf(Admitted.class);

    analyze("app.s3");
    exec(owner, "VACUUM ANALYZE app.s3");
    assertThat(verdict("app.s3")).isInstanceOf(Admitted.class);
    assertThat(text(app, statsRows("s3", "email_idx"))).isEqualTo("0");
    assertThat(text(app, statsRows("s3", "subject")))
        .describedAs("only the blind-index column is constrained; the others keep statistics")
        .isEqualTo("1");
  }

  // --------------------------------------------------- row 37: indexes and extended statistics

  @Test
  void s4_expression_index_on_index_column_is_refused_naming_the_drop() {
    table("app.s4", "");
    zero("app.s4");
    exec(owner, "CREATE INDEX s4_prefix ON app.s4 (substring(email_idx from 1 for 8))");

    assertThat(copied("app.s4"))
        .contains(
            "app.s4.email_idx (@BlindIndex Note.emailIndex): expression index app.s4_prefix"
                + " computes over it (drop it: DROP INDEX app.s4_prefix). ")
        .contains("Drop the objects named above as the table owner.");
  }

  @Test
  void s4b_whole_row_expression_index_is_refused() {
    table("app.s4b", "");
    zero("app.s4b");
    exec(owner, "CREATE INDEX s4b_whole ON app.s4b ((s4b IS NULL))");

    assertThat(copied("app.s4b"))
        .contains(
            "expression index app.s4b_whole computes over it (drop it: DROP INDEX app.s4b_whole)");
  }

  /** C-24-4: a function outside pg_catalog is opaque, whatever columns the tree names. */
  @Test
  void s14_index_extended_statistics_or_generated_column_calling_a_user_function_is_unverifiable() {
    exec(
        owner,
        "CREATE FUNCTION app.s14_peek(i bigint) RETURNS varchar LANGUAGE sql IMMUTABLE"
            + " AS 'SELECT md5(i::text)'");
    table("app.s14a", "");
    zero("app.s14a");
    exec(owner, "CREATE INDEX s14a_peek ON app.s14a (app.s14_peek(id))");
    table("app.s14b", "");
    zero("app.s14b");
    exec(owner, "CREATE STATISTICS app.s14b_st ON (app.s14_peek(id)), tenant FROM app.s14b");
    table("app.s14c", ", peek varchar GENERATED ALWAYS AS (app.s14_peek(id)) STORED");
    zero("app.s14c");
    exec(owner, "ALTER TABLE app.s14c ALTER COLUMN peek SET STATISTICS 0");

    for (String[] c :
        new String[][] {
          {"app.s14a", "expression index app.s14a_peek"},
          {"app.s14b", "extended statistics app.s14b_st"},
          {"app.s14c", "stored generated column app.s14c.peek"}
        }) {
      Throwable thrown = catchThrowable(() -> verdict(c[0]));
      assertThat(code(thrown)).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
      assertThat(thrown)
          .hasMessageStartingWith(
              "shredding: "
                  + c[1]
                  + " on a blind-indexed table calls app.s14_peek, which is outside pg_catalog.");
    }
  }

  /** C-24-3: a view under default privileges is named, never re-created with wider grants. */
  @Test
  void s11c_view_under_default_privileges_is_named_not_recreated() {
    table("app.s11c", "");
    exec(
        owner,
        "CREATE VIEW app.s11c_v AS SELECT id, email_idx FROM app.s11c",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT ON TABLES TO shred_reader");
    try {
      assertThat(copied("app.s11c"))
          .contains("view app.s11c_v (default privileges would change its grants)")
          .doesNotContain("CREATE VIEW");
    } finally {
      exec(
          owner,
          "ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE SELECT ON TABLES FROM shred_reader");
    }
  }

  @Test
  void s7_extended_statistics_on_index_column_are_refused_by_key_and_by_expression() {
    table("app.s7", "");
    zero("app.s7");
    exec(
        owner,
        "CREATE STATISTICS app.s7_keys (mcv) ON tenant, email_idx FROM app.s7",
        "CREATE STATISTICS app.s7_expr ON (length(email_idx)), subject FROM app.s7",
        "CREATE STATISTICS app.s7_other (ndistinct) ON tenant, subject FROM app.s7");
    analyze("app.s7");

    String message = copied("app.s7");

    assertThat(message)
        .contains(
            "extended statistics app.s7_expr cover it (drop them: DROP STATISTICS app.s7_expr)")
        .contains(
            "extended statistics app.s7_keys cover it (drop them: DROP STATISTICS app.s7_keys)")
        .doesNotContain("s7_other");
  }

  @Test
  void s8_partial_index_predicate_on_index_column_is_admitted() {
    table("app.s8", "");
    zero("app.s8");
    exec(
        owner,
        "CREATE INDEX s8_pred ON app.s8 (id) WHERE email_idx IS NOT NULL",
        "CREATE INDEX s8_mixed ON app.s8 (lower(subject)) WHERE email_idx IS NOT NULL",
        "CREATE INDEX s8_plain_and_expr ON app.s8 (email_idx, lower(subject))",
        "CREATE INDEX s8_lookup ON app.s8 (email_idx)");
    analyze("app.s8");
    assertThat(
            text(
                su,
                "SELECT count(*) FROM pg_statistic s JOIN pg_index i ON i.indexrelid = s.starelid"
                    + " WHERE i.indrelid = 'app.s8'::regclass AND s.staattnum IN"
                    + " (SELECT a.attnum FROM pg_attribute a WHERE a.attrelid = s.starelid"
                    + " AND a.atttypid = 'varchar'::regtype)"))
        .describedAs("measured: no index stores statistics of the index column itself")
        .isEqualTo("0");

    assertThat(verdict("app.s8")).isInstanceOf(Admitted.class);
  }

  // ---------------------------------------------------------- rows 30 and 48: descendants

  @Test
  void s5_descendant_statistics_invisible_to_the_role_is_unverifiable() {
    exec(
        owner,
        "CREATE TABLE app.s5 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) PARTITION BY RANGE (id)",
        "CREATE TABLE app.s5_1 PARTITION OF app.s5 FOR VALUES FROM (0) TO (1000000)",
        "GRANT SELECT, UPDATE ON app.s5 TO " + APP);
    zero("app.s5");

    Throwable thrown = catchThrowable(() -> verdict("app.s5"));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    assertThat(thrown)
        .hasMessage(
            "shredding: the runtime role has no SELECT on app.s5_1.email_idx, so it cannot see"
                + " whether statistics are stored for it. Grant SELECT on the partition, or run"
                + " the check as a role that has it.");
  }

  @Test
  void s5b_row_level_security_on_a_partition_hides_its_statistics_and_is_unverifiable() {
    exec(
        owner,
        "CREATE TABLE app.s5b (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) PARTITION BY RANGE (id)",
        "CREATE TABLE app.s5b_1 PARTITION OF app.s5b FOR VALUES FROM (0) TO (1000000)",
        "GRANT SELECT, UPDATE ON app.s5b, app.s5b_1 TO " + APP,
        "ALTER TABLE app.s5b_1 ENABLE ROW LEVEL SECURITY");
    zero("app.s5b");

    Throwable thrown = catchThrowable(() -> verdict("app.s5b"));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    assertThat(thrown)
        .hasMessageContaining("row level security on app.s5b_1 applies to the runtime role");
  }

  @Test
  void s10_partitioned_remedy_on_parent_clears_every_partition() {
    exec(
        owner,
        "CREATE TABLE app.s10 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) PARTITION BY RANGE (id)",
        "CREATE TABLE app.s10_1 PARTITION OF app.s10 FOR VALUES FROM (0) TO (200)",
        "CREATE TABLE app.s10_2 PARTITION OF app.s10 FOR VALUES FROM (200) TO (1000000)",
        "GRANT SELECT, UPDATE ON app.s10, app.s10_1, app.s10_2 TO " + APP);
    rows("app.s10");
    analyze("app.s10");

    String message = copied("app.s10");
    assertThat(message)
        .contains("pg_stats holds sampled values for it on partition app.s10_1")
        .contains("pg_stats holds sampled values for it on partition app.s10_2")
        .contains("ALTER TABLE app.s10 ALTER COLUMN email_idx SET STATISTICS 0;");

    exec(owner, remedy(message));
    analyze("app.s10");
    assertThat(verdict("app.s10")).isInstanceOf(Admitted.class);
  }

  @Test
  void s10b_inheritance_child_left_at_its_default_is_named() {
    table("app.s10b", "");
    exec(
        owner,
        "CREATE TABLE app.s10b_child () INHERITS (app.s10b)",
        "GRANT SELECT, UPDATE ON app.s10b_child TO " + APP,
        "ALTER TABLE ONLY app.s10b ALTER COLUMN email_idx SET STATISTICS 0");

    String message = copied("app.s10b");

    assertThat(message)
        .contains(
            defaultTargetFact.replace(
                "its statistics target is",
                "its statistics target on inheritance child app.s10b_child is"));
    exec(owner, remedy(message));
    assertThat(verdict("app.s10b")).isInstanceOf(Admitted.class);
  }

  // ----------------------------------------------------- item 5 and C13: generated, dependents

  @Test
  void s13_generated_column_over_index_column_statistics_are_refused() {
    table("app.s13", ", email_low text GENERATED ALWAYS AS (lower(email_idx))" + " STORED");
    zero("app.s13");
    analyze("app.s13");
    assertThat(text(app, statsRows("s13", "email_low")))
        .describedAs("measured (item 5): the generated column's own pg_stats row, derived values")
        .isEqualTo("1");

    String message = copied("app.s13");

    assertThat(message)
        .contains(
            "stored generated column app.s13.email_low is computed from it, and pg_stats holds"
                + " sampled values for it")
        .contains(
            "Objects that depend on the column and are not re-created by a generated statement:"
                + " stored generated column app.s13.email_low.")
        .contains(
            "As the table owner run: SET search_path = pg_catalog, pg_temp; ALTER TABLE app.s13"
                + " ALTER COLUMN email_idx SET STATISTICS 0; ALTER TABLE app.s13 ALTER COLUMN"
                + " email_low SET STATISTICS 0; The rows already stored for app.s13.email_idx,"
                + " app.s13.email_low then need");
  }

  @Test
  void s13b_expression_index_over_the_generated_column_is_refused() {
    table("app.s13b", ", email_low text GENERATED ALWAYS AS (lower(email_idx))" + " STORED");
    zero("app.s13b");
    exec(
        owner,
        "ALTER TABLE app.s13b ALTER COLUMN email_low SET STATISTICS 0",
        "CREATE INDEX s13b_low ON app.s13b (upper(email_low))");

    assertThat(copied("app.s13b"))
        .contains(
            "expression index app.s13b_low computes over it through stored generated column"
                + " app.s13b.email_low (drop it: DROP INDEX app.s13b_low)");
  }

  @Test
  void s11_remedy_with_dependent_view_and_policy_runs_in_one_transaction_and_admits() {
    table("app.s11", "");
    analyze("app.s11");
    exec(
        owner,
        "CREATE VIEW app.s11_v WITH (security_barrier) AS SELECT id, tenant, email_idx"
            + " FROM app.s11",
        "COMMENT ON VIEW app.s11_v IS 'lookup view'",
        "GRANT SELECT ON app.s11_v TO shred_reader",
        "GRANT SELECT ON app.s11 TO shred_reader",
        "ALTER TABLE app.s11 ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY s11_tenant ON app.s11 AS PERMISSIVE FOR SELECT TO shred_reader"
            + " USING (email_idx IS NOT NULL AND id < 10)");
    long readerBefore = Long.parseLong(text(reader(), "SELECT count(*) FROM app.s11"));
    assertThat(readerBefore).describedAs("the policy filters the reader").isEqualTo(9);

    String message = copied(byp(), "app.s11");
    assertThat(message)
        .contains(
            "Objects that depend on the column and must be dropped and re-created with it: view"
                + " app.s11_v; policy s11_tenant on app.s11.")
        .contains(
            "BEGIN; SET LOCAL search_path = pg_catalog, pg_temp; SET LOCAL lock_timeout = '5s';"
                + " DROP VIEW app.s11_v;")
        .contains("COMMIT;");

    exec(owner, remedy(message));

    assertThat(copiedOrAdmitted(byp(), "app.s11")).isInstanceOf(Admitted.class);
    assertThat(text(reader(), "SELECT count(*) FROM app.s11"))
        .describedAs("the re-created policy still filters")
        .isEqualTo("9");
    assertThat(text(reader(), "SELECT count(*) FROM app.s11_v"))
        .describedAs("the re-created view is readable by its grantee")
        .isEqualTo("300");
    assertThat(text(su, "SELECT obj_description('app.s11_v'::regclass, 'pg_class')"))
        .isEqualTo("lookup view");
    assertThat(text(su, "SELECT reloptions::text FROM pg_class WHERE oid = 'app.s11_v'::regclass"))
        .isEqualTo("{security_barrier=true}");
  }

  @Test
  void s11b_generated_column_cleared_with_the_documented_superuser_template_admits() {
    table("app.s11b", ", email_low text GENERATED ALWAYS AS (lower(email_idx))" + " STORED");
    analyze("app.s11b");
    copied("app.s11b");

    // docs/upgrading-0.2.0.md, step 3a, the 16/17 template: SET STATISTICS 0 first, then the
    // rows of exactly these columns, in one transaction that checks the count before commit.
    exec(
        owner,
        "ALTER TABLE app.s11b ALTER COLUMN email_idx SET STATISTICS 0",
        "ALTER TABLE app.s11b ALTER COLUMN email_low SET STATISTICS 0");
    String index = attnum("app.s11b", "email_idx");
    String derived = attnum("app.s11b", "email_low");
    String scope =
        "(starelid = 'app.s11b'::regclass AND staattnum = "
            + index
            + ") OR (starelid = 'app.s11b'::regclass AND staattnum = "
            + derived
            + ")";
    assertThat(text(su, "SELECT pg_catalog.count(*) FROM pg_catalog.pg_statistic WHERE " + scope))
        .isEqualTo("2");
    exec(
        su,
        "BEGIN; DO $$ DECLARE n bigint; BEGIN DELETE FROM pg_catalog.pg_statistic WHERE "
            + scope
            + "; GET DIAGNOSTICS n = ROW_COUNT; IF n <> 2 THEN RAISE EXCEPTION 'expected 2"
            + " pg_statistic rows, deleted %', n; END IF; END $$; COMMIT;");

    analyze("app.s11b");
    assertThat(verdict("app.s11b")).isInstanceOf(Admitted.class);
  }

  @Test
  void s12_dependents_are_listed_and_tree_or_generated_column_is_not_generated() {
    table("app.s12", ", email_low text GENERATED ALWAYS AS (lower(email_idx))" + " STORED");
    exec(
        owner,
        "ALTER TABLE app.s12 ALTER COLUMN email_low SET STATISTICS 0",
        "CREATE VIEW app.s12_v1 AS SELECT id, email_idx FROM app.s12",
        "CREATE VIEW app.s12_v2 AS SELECT id FROM app.s12_v1");

    assertThat(copied("app.s12"))
        .isEqualTo(
            "shredding: PostgreSQL keeps, or will keep, planner statistics on the blind-index"
                + " column app.s12.email_idx (@BlindIndex Note.emailIndex): "
                + defaultTargetFact
                + ". Statistics store sampled values of the column (most common values, histogram"
                + " bounds); any role with SELECT on the table reads them from pg_stats, and an"
                + " erasure does not remove them. Objects that depend on the column and are not"
                + " re-created by a generated statement: stored generated column"
                + " app.s12.email_low; view app.s12_v1 (other views depend on it). Clear the"
                + " statistics without retyping. As the table owner run: SET search_path ="
                + " pg_catalog, pg_temp; ALTER TABLE app.s12 ALTER COLUMN email_idx SET STATISTICS"
                + " 0; ALTER TABLE app.s12 ALTER COLUMN email_low SET STATISTICS 0; The rows"
                + " already stored for app.s12.email_idx, app.s12.email_low then need a statement"
                + " this module does not generate: on PostgreSQL 18 or later, as the table owner,"
                + " pg_catalog.pg_clear_attribute_stats for each column; on 16 or 17, a superuser"
                + " deletes their pg_statistic rows. See docs/upgrading-0.2.0.md, step 3a.");
  }

  // --------------------------------------------------------- row 47: after boot, at erasure

  @Test
  void s9_statistics_target_raised_after_boot_refuses_erasure_and_records_nothing() {
    table("app.s9", "");
    zero("app.s9");
    JdbcErasureStore store = store("app.s9");
    exec(owner, "ALTER TABLE app.s9 ALTER COLUMN email_idx SET STATISTICS 100");
    long before = Long.parseLong(text(su, "SELECT count(*) FROM public.shredding_erasure"));

    Throwable thrown = catchThrowable(() -> erase(store, "s-1"));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(thrown)
        .hasMessageContaining("its statistics target is 100")
        .hasMessageContaining("This erasure is refused before its first statement");
    assertThat(Long.parseLong(text(su, "SELECT count(*) FROM public.shredding_erasure")))
        .isEqualTo(before);
    assertThat(text(su, "SELECT count(*) FROM app.s9 WHERE subject = 's-1' AND email_idx IS NULL"))
        .describedAs("nothing was cleared")
        .isEqualTo("0");

    exec(owner, "ALTER TABLE app.s9 ALTER COLUMN email_idx SET STATISTICS 0");
    assertThat(erase(store, "s-1").blindIndexColumnsCleared()).isEqualTo(1);
  }

  @Test
  void s6_drop_column_removes_its_statistics() {
    table("app.s6", "");
    analyze("app.s6");
    String attnum =
        text(
            su,
            "SELECT attnum FROM pg_attribute WHERE attrelid = 'app.s6'::regclass"
                + " AND attname = 'email_idx'");
    assertThat(stored("app.s6", attnum)).isEqualTo("1");

    exec(owner, "ALTER TABLE app.s6 DROP COLUMN email_idx");

    assertThat(stored("app.s6", attnum)).isEqualTo("0");
  }

  // ------------------------------------------------------------------------------ helpers

  private void table(String table, String extra) {
    exec(
        owner,
        "CREATE TABLE "
            + table
            + " (id bigint, tenant varchar(64), subject varchar(64), email_idx varchar(64)"
            + extra
            + ")",
        "GRANT SELECT, UPDATE ON " + table + " TO " + APP + ", shred_byp");
    rows(table);
  }

  private void rows(String table) {
    exec(
        owner,
        "INSERT INTO "
            + table
            + " (id, tenant, subject, email_idx) SELECT g, 'T1', 's-' || g, md5(g::text)"
            + " FROM generate_series(1, 300) g");
  }

  private void analyze(String table) {
    exec(owner, "ANALYZE " + table);
  }

  private void zero(String table) {
    exec(owner, "ALTER TABLE " + table + " ALTER COLUMN email_idx SET STATISTICS 0");
  }

  private String attnum(String table, String column) {
    return text(
        su,
        "SELECT attnum FROM pg_attribute WHERE attrelid = '"
            + table
            + "'::regclass AND attname = '"
            + column
            + "'");
  }

  private String stored(String table, String attnum) {
    return text(
        su,
        "SELECT count(*) FROM pg_statistic WHERE starelid = '"
            + table
            + "'::regclass AND staattnum = "
            + attnum);
  }

  private static String statsRows(String table, String column) {
    return "SELECT count(*) FROM pg_stats WHERE schemaname = 'app' AND tablename = '"
        + table
        + "' AND attname = '"
        + column
        + "'";
  }

  /** The statements a refusal prints after "As the table owner run:", exactly as printed. */
  private static String remedy(String message) {
    int start = message.indexOf("As the table owner run: ");
    assertThat(start).describedAs("the message prints a remedy").isGreaterThanOrEqualTo(0);
    String rest = message.substring(start + "As the table owner run: ".length());
    int end = rest.startsWith("BEGIN;") ? rest.indexOf("COMMIT;") + 7 : rest.indexOf(" The ");
    return rest.substring(0, end);
  }

  private static List<Column> cols() {
    return List.of(
        new Column(ColumnRef.unquoted("tenant"), Use.COMPARED, MappingAdmission.TENANT),
        new Column(ColumnRef.unquoted("subject"), Use.COMPARED, MappingAdmission.SUBJECT),
        new Column(ColumnRef.unquoted("id"), Use.COMPARED, MappingAdmission.IDENTIFIER),
        new Column(
            ColumnRef.unquoted("email_idx"),
            Use.ASSIGNED,
            MappingAdmission.BLIND_INDEX,
            Optional.of(LABEL)));
  }

  private Verdict verdict(String table) {
    return copiedOrAdmitted(app, table);
  }

  private static Verdict copiedOrAdmitted(DataSource ds, String table) {
    try (Connection c = ds.getConnection()) {
      return MappingAdmission.verdict(
          c, new Target(Optional.of("Note"), TableRef.parse(table), cols()));
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private String copied(String table) {
    return copied(app, table);
  }

  private static String copied(DataSource ds, String table) {
    Verdict verdict = copiedOrAdmitted(ds, table);
    assertThat(verdict).isInstanceOf(Copied.class);
    return ((Copied) verdict).message();
  }

  private DataSource byp() {
    return pool("shred_byp", "pw");
  }

  private DataSource reader() {
    return pool("shred_reader", "pw");
  }

  private JdbcErasureStore store(String table) {
    return new JdbcErasureStore(
        app,
        schema,
        ErasureChain.keyed(SECRET, "k1"),
        List.of(
            new BlindIndexColumn(
                TableRef.parse(table),
                ColumnRef.unquoted("email_idx"),
                ColumnRef.unquoted("subject"),
                ColumnRef.unquoted("tenant"),
                Optional.of("tenant"),
                Optional.of("subject"))),
        (c, col, tenant, subject) -> 0L);
  }

  private static com.housedevinci.shredding.application.ErasureStore.Outcome erase(
      JdbcErasureStore store, String subjectId) {
    SubjectId subject = SubjectId.of(subjectId);
    return store.erase(
        T1,
        subject,
        (destroyed, cleared) ->
            ErasureRecord.of(
                Instant.now(),
                T1,
                new Pseudonymiser(SECRET).pseudonym(T1, subject),
                "dpo",
                "art 17",
                destroyed,
                1,
                1,
                cleared,
                ErasureOutcome.COMPLETE,
                List.of(),
                Instant.now().plus(Duration.ofDays(30))));
  }

  private static String code(Throwable thrown) {
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    return ((ShreddingException) thrown).code();
  }

  private HikariDataSource pool(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(postgres.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(2);
    var ds = new HikariDataSource(config);
    pools.add(ds);
    return ds;
  }

  private static void exec(DataSource ds, String... sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }

  private static String text(DataSource ds, String sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getString(1) : null;
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }
}
