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
import java.lang.reflect.Proxy;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Leg K of the audit-table coverage design (section 3, rows 10, 15-25, 27b, 32, 45): every
 * catalogue object through which a copy of a blind-index column can exist outside the admitted
 * table is refused with {@code SHRED-SCHEMA-010}, at startup and at every erasure, and again after
 * the erasure's {@code UPDATE} (C5). One test per path, named as in the design's table.
 *
 * <p>Fixture: PostgreSQL 16 with {@code wal_level=logical} (slots need it); {@code shred_owner}
 * owns schema {@code app} and every table in it; {@code shred_app}, {@code NOSUPERUSER}, holds
 * {@code SELECT, UPDATE} on each table and is the role every verdict is read as. The test-only
 * statistics-off event trigger is installed, so planner statistics (PR 2) never decide a verdict
 * here.
 */
class CopyCataloguePostgresTest {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withCommand("postgres", "-c", "wal_level=logical", "-c", "fsync=off")
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(Duration.ofMinutes(2));

  private static final String OWNER = "shred_owner";
  private static final String APP = "shred_app";
  private static final byte[] SECRET =
      "copy-catalogue-chain-secret-32-by".getBytes(StandardCharsets.UTF_8);
  private static final TenantId T1 = TenantId.of("T1");
  private static final String LABEL = "@BlindIndex Note.emailIndex";

  private static final List<HikariDataSource> pools = new ArrayList<>();
  private static HikariDataSource su;
  private static HikariDataSource owner;
  private static HikariDataSource app;
  private static VerifiedSchema schema;

  @BeforeAll
  static void start() {
    POSTGRES.start();
    su = pool(POSTGRES.getUsername(), POSTGRES.getPassword(), null);
    exec(
        su,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA app AUTHORIZATION " + OWNER,
        "CREATE SCHEMA audit AUTHORIZATION " + OWNER,
        "CREATE SCHEMA decoy AUTHORIZATION " + APP,
        "GRANT USAGE ON SCHEMA app TO " + APP);
    owner = pool(OWNER, "pw", null);
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
    app = pool(APP, "pw", null);
    schema = JdbcSupport.verifySchema(app, true).schema();
  }

  @AfterAll
  static void stop() {
    pools.forEach(HikariDataSource::close);
    POSTGRES.stop();
  }

  // ------------------------------------------------------------------- rows 15-20: triggers

  @Test
  void t1_after_update_history_trigger_is_refused_at_startup() {
    table("app.t1");
    exec(
        owner,
        "CREATE TABLE app.t1_history (LIKE app.t1)",
        "CREATE FUNCTION app.t1_copy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN"
            + " INSERT INTO app.t1_history SELECT OLD.*; RETURN NULL; END $$",
        "CREATE TRIGGER t1_audit AFTER UPDATE ON app.t1 FOR EACH ROW"
            + " EXECUTE FUNCTION app.t1_copy()");

    assertThat(copied("app.t1"))
        .isEqualTo(
            "shredding: app.t1 holds the blind-index column email_idx (@BlindIndex"
                + " Note.emailIndex) and has trigger t1_audit (AFTER UPDATE, FOR EACH ROW,"
                + " function app.t1_copy). This module cannot see where a trigger writes; one"
                + " that copies the row keeps the erased subject's index after every erasure, and"
                + " the erasure's own UPDATE fires it. Drop or disable the trigger: ALTER TABLE"
                + " app.t1 DISABLE TRIGGER t1_audit.");
  }

  static Stream<String[]> triggerShapes() {
    return Stream.of(
        new String[] {"before_row", "BEFORE UPDATE ON %s FOR EACH ROW", "BEFORE UPDATE"},
        new String[] {"after_insert", "AFTER INSERT ON %s FOR EACH ROW", "AFTER INSERT"},
        new String[] {"after_delete", "AFTER DELETE ON %s FOR EACH ROW", "AFTER DELETE"},
        new String[] {
          "update_of_other", "AFTER UPDATE OF note ON %s FOR EACH ROW", "AFTER UPDATE OF note"
        },
        new String[] {"statement", "AFTER UPDATE ON %s FOR EACH STATEMENT", "FOR EACH STATEMENT"},
        new String[] {
          "transition",
          "AFTER UPDATE ON %s REFERENCING NEW TABLE AS n FOR EACH STATEMENT",
          "FOR EACH STATEMENT"
        },
        new String[] {"truncate", "BEFORE TRUNCATE ON %s FOR EACH STATEMENT", "BEFORE TRUNCATE"},
        new String[] {"constraint", "AFTER UPDATE ON %s FOR EACH ROW", "constraint trigger"},
        new String[] {"replica", "AFTER UPDATE ON %s FOR EACH ROW", "ENABLE REPLICA"},
        new String[] {"always", "AFTER UPDATE ON %s FOR EACH ROW", "ENABLE ALWAYS"});
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("triggerShapes")
  void t3_every_trigger_shape_is_refused(String name, String shape, String fact) {
    String table = "app.t3_" + name;
    table(table);
    exec(owner, "CREATE FUNCTION app.t3_" + name + "_f() RETURNS trigger LANGUAGE plpgsql AS"
        + " $$ BEGIN RETURN NULL; END $$");
    String create =
        ("constraint".equals(name) ? "CREATE CONSTRAINT TRIGGER " : "CREATE TRIGGER ")
            + "tr_"
            + name
            + " "
            + String.format(shape, table)
            + " EXECUTE FUNCTION app.t3_"
            + name
            + "_f()";
    exec(owner, create);
    if ("replica".equals(name)) {
      exec(owner, "ALTER TABLE " + table + " ENABLE REPLICA TRIGGER tr_replica");
    }
    if ("always".equals(name)) {
      exec(owner, "ALTER TABLE " + table + " ENABLE ALWAYS TRIGGER tr_always");
    }

    String message = copied(table);

    assertThat(message).contains("has trigger tr_" + name + " (").contains(fact);
  }

  @Test
  void t4_disabled_trigger_admitted_enabled_later_refuses_erasure() {
    table("app.t4");
    exec(
        owner,
        "CREATE FUNCTION app.t4_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$",
        "CREATE TRIGGER t4_tr AFTER UPDATE ON app.t4 FOR EACH ROW EXECUTE FUNCTION app.t4_f()",
        "ALTER TABLE app.t4 DISABLE TRIGGER t4_tr");
    assertThat(verdict("app.t4")).isInstanceOf(Admitted.class);
    JdbcErasureStore store = store("app.t4");

    exec(owner, "ALTER TABLE app.t4 ENABLE TRIGGER t4_tr");
    long records = records();
    Throwable thrown = catchThrowable(() -> erase(store, "app.t4-s-1"));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(thrown)
        .hasMessageContaining("has trigger t4_tr (AFTER UPDATE, FOR EACH ROW, function app.t4_f)")
        .hasMessageEndingWith(
            "This erasure is refused before its first statement: no key is destroyed, no blind"
                + " index is touched and no record is appended.");
    assertThat(records()).isEqualTo(records);
    assertThat(indexed("app.t4", "app.t4-s-1")).isEqualTo(1);
  }

  @Test
  void t5_descendant_and_cloned_triggers_reported_once() {
    exec(
        owner,
        "CREATE TABLE app.t5 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64), note text) PARTITION BY LIST (tenant)",
        "CREATE TABLE app.t5_a PARTITION OF app.t5 FOR VALUES IN ('T1')",
        "CREATE TABLE app.t5_b PARTITION OF app.t5 FOR VALUES IN ('T2')",
        "GRANT SELECT, UPDATE ON app.t5, app.t5_a, app.t5_b TO " + APP,
        "CREATE FUNCTION app.t5_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$",
        "CREATE TRIGGER t5_parent AFTER UPDATE ON app.t5 FOR EACH ROW EXECUTE FUNCTION"
            + " app.t5_f()",
        "CREATE TRIGGER t5_own AFTER INSERT ON app.t5_b FOR EACH ROW EXECUTE FUNCTION"
            + " app.t5_f()");
    // Measured first: the clones on both partitions are not internal and carry their parent.
    assertThat(
            text(
                su,
                "SELECT count(*) FROM pg_trigger WHERE tgname = 't5_parent'"
                    + " AND NOT tgisinternal AND tgparentid <> 0"))
        .isEqualTo("2");

    String message = copied("app.t5");

    assertThat(occurrences(message, "has trigger t5_parent (")).isEqualTo(1);
    assertThat(message)
        .contains(
            "has trigger t5_parent (AFTER UPDATE, FOR EACH ROW, function app.t5_f), cloned to 2"
                + " partitions")
        .contains("has trigger t5_own on partition app.t5_b (AFTER INSERT, FOR EACH ROW,");
  }

  @Test
  void t6_trigger_after_boot_refuses_erasure() {
    table("app.t6");
    JdbcErasureStore store = store("app.t6");
    assertThat(verdict("app.t6")).isInstanceOf(Admitted.class);
    exec(
        owner,
        "CREATE FUNCTION app.t6_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$",
        "CREATE TRIGGER t6_tr BEFORE UPDATE ON app.t6 FOR EACH ROW EXECUTE FUNCTION app.t6_f()");
    long records = records();

    Throwable thrown = catchThrowable(() -> erase(store, "app.t6-s-1"));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(thrown).hasMessageContaining("has trigger t6_tr (BEFORE UPDATE");
    assertThat(records()).isEqualTo(records);
  }

  @Test
  void t7_create_trigger_waits_for_the_erasure_lock() throws Exception {
    table("app.t7");
    exec(
        owner,
        "CREATE FUNCTION app.t7_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$");
    var during = new BlockingReadBack();
    JdbcErasureStore store = store("app.t7", during);
    CompletableFuture<?> erasure = CompletableFuture.runAsync(() -> erase(store, "app.t7-s-1"));
    during.awaitInside();
    Throwable blocked;
    try {
      blocked =
          catchThrowable(
              () ->
                  exec(
                      owner,
                      "SET lock_timeout = '500ms'",
                      "CREATE TRIGGER t7_tr AFTER UPDATE ON app.t7 FOR EACH ROW"
                          + " EXECUTE FUNCTION app.t7_f()"));
    } finally {
      during.release();
    }
    erasure.get(30, TimeUnit.SECONDS);

    assertThat(blocked).hasMessageContaining("lock timeout");
    assertThat(text(su, "SELECT count(*) FROM pg_trigger WHERE tgname = 't7_tr'")).isEqualTo("0");
  }

  @Test
  void t8_internal_ri_triggers_not_reported() {
    table("app.t8");
    exec(
        owner,
        "ALTER TABLE app.t8 ADD PRIMARY KEY (id)",
        "CREATE TABLE app.t8_child (id bigint, parent bigint REFERENCES app.t8 (id))");
    assertThat(text(su, "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'app.t8'::regclass"))
        .isNotEqualTo("0");

    assertThat(verdict("app.t8")).isInstanceOf(Admitted.class);
  }

  // ------------------------------------------------------------------------- row 21: rules

  @Test
  void r1_rule_on_table_or_descendant_is_refused() {
    table("app.r1");
    exec(
        owner,
        "CREATE TABLE app.r1_log (LIKE app.r1)",
        "CREATE RULE r1_copy AS ON UPDATE TO app.r1 DO ALSO INSERT INTO app.r1_log SELECT OLD.*");
    assertThat(copied("app.r1"))
        .contains(
            "shredding: app.r1 holds the blind-index column email_idx (@BlindIndex"
                + " Note.emailIndex) and has rule r1_copy (ON UPDATE DO ALSO). A rule rewrites"
                + " the statements on the table, the erasure's own UPDATE included, and this"
                + " module cannot see where it writes. Drop it: DROP RULE r1_copy ON app.r1.");

    table("app.r1p");
    exec(
        owner,
        "CREATE TABLE app.r1p_child () INHERITS (app.r1p)",
        "GRANT SELECT, UPDATE ON app.r1p_child TO " + APP,
        "CREATE TABLE app.r1p_log (LIKE app.r1p)",
        "CREATE RULE r1p_copy AS ON DELETE TO app.r1p_child DO ALSO"
            + " INSERT INTO app.r1p_log SELECT OLD.*");
    assertThat(copied("app.r1p"))
        .contains("has rule r1p_copy on inheritance child app.r1p_child (ON DELETE DO ALSO)");
  }

  // ---------------------------------------------------------------- row 22: generated column

  @Test
  void g1_generated_column_over_index_is_cleared_by_the_erasure() {
    exec(
        owner,
        "CREATE TABLE app.g1 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64), email_up text GENERATED ALWAYS AS (upper(email_idx))"
            + " STORED)",
        "GRANT SELECT, UPDATE ON app.g1 TO " + APP);
    rows("app.g1");
    assertThat(verdict("app.g1")).isInstanceOf(Admitted.class);

    erase(store("app.g1"), "app.g1-s-1");

    assertThat(
            text(
                su,
                "SELECT count(*) FROM app.g1 WHERE subject = 'app.g1-s-1' AND email_up IS NOT NULL"))
        .isEqualTo("0");
  }

  // -------------------------------------------------------------- row 23: materialized views

  @Test
  void m1_matview_over_index_refused() {
    table("app.m1");
    exec(owner, "CREATE MATERIALIZED VIEW app.m1_direct AS SELECT id, email_idx FROM app.m1");
    assertThat(copied("app.m1"))
        .contains(
            "shredding: materialized view app.m1_direct reads the blind-index column"
                + " app.m1.email_idx (@BlindIndex Note.emailIndex). It holds every index value as"
                + " of its last refresh, and no erasure reaches it. Leave the column out of the"
                + " view, or drop it: DROP MATERIALIZED VIEW app.m1_direct.");

    table("app.m1w");
    exec(owner, "CREATE MATERIALIZED VIEW app.m1w_row AS SELECT r FROM app.m1w r");
    assertThat(copied("app.m1w")).contains("materialized view app.m1w_row reads the whole row");

    table("app.m1v");
    exec(
        owner,
        "CREATE VIEW app.m1v_v AS SELECT id, email_idx FROM app.m1v",
        "CREATE VIEW app.m1v_vv AS SELECT * FROM app.m1v_v",
        "CREATE MATERIALIZED VIEW app.m1v_mv AS SELECT * FROM app.m1v_vv");
    assertThat(copied("app.m1v"))
        .contains("materialized view app.m1v_mv reads the blind-index column app.m1v.email_idx")
        .contains("through view app.m1v_vv");
  }

  @Test
  void m2_matview_over_other_columns_admitted() {
    table("app.m2");
    exec(owner, "CREATE MATERIALIZED VIEW app.m2_mv AS SELECT id, subject FROM app.m2");

    assertThat(verdict("app.m2")).isInstanceOf(Admitted.class);
  }

  @Test
  void k4_matview_created_during_erasure_refuses_that_erasure() throws Exception {
    table("app.k4");
    var during = new BlockingReadBack();
    JdbcErasureStore store = store("app.k4", during);
    long records = records();
    CompletableFuture<Throwable> erasure =
        CompletableFuture.supplyAsync(() -> catchThrowable(() -> erase(store, "app.k4-s-1")));
    during.awaitInside();
    long created;
    try {
      // Not blocked by the erasure's locks (measured by the security review): it copies the
      // index values the erasure is about to clear, from the last committed snapshot.
      exec(owner, "CREATE MATERIALIZED VIEW app.k4_mv AS SELECT email_idx FROM app.k4");
      created = System.nanoTime();
    } finally {
      during.release();
    }
    Throwable thrown = erasure.get(30, TimeUnit.SECONDS);
    long window = Duration.ofNanos(System.nanoTime() - created).toMillis();

    assertThat(code(thrown)).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(thrown)
        .hasMessageContaining("materialized view app.k4_mv reads the blind-index column")
        .hasMessageEndingWith(
            "Found after this erasure's UPDATE: the erasure is refused and rolled back, no key is"
                + " destroyed, no blind index is cleared and no record is appended.");
    assertThat(records()).isEqualTo(records);
    assertThat(indexed("app.k4", "app.k4-s-1")).isEqualTo(1);
    System.out.println("K4 release-to-refusal ms: " + window);
  }

  // ------------------------------------------------------------------- row 24: foreign keys

  @Test
  void f1_foreign_key_on_index_column_refused_both_sides() {
    table("app.f1");
    exec(
        owner,
        "ALTER TABLE app.f1 ADD CONSTRAINT f1_idx_unique UNIQUE (email_idx)",
        "CREATE TABLE app.f1_child (id bigint, customer_email_idx varchar(64)"
            + " CONSTRAINT f1_child_ref REFERENCES app.f1 (email_idx))");
    assertThat(copied("app.f1"))
        .contains(
            "shredding: foreign key f1_child_ref on app.f1_child references the blind-index"
                + " column app.f1.email_idx (@BlindIndex Note.emailIndex), so app.f1_child holds"
                + " index values and no erasure reaches it. Reference the table by its"
                + " identifier instead, then drop the constraint and the column:"
                + " ALTER TABLE app.f1_child DROP CONSTRAINT f1_child_ref.");

    table("app.f1p");
    exec(
        owner,
        "CREATE TABLE app.f1p_parent (code varchar(64) PRIMARY KEY)",
        "ALTER TABLE app.f1p ADD CONSTRAINT f1p_ref FOREIGN KEY (email_idx)"
            + " REFERENCES app.f1p_parent (code) NOT VALID");
    assertThat(copied("app.f1p"))
        .contains(
            "shredding: foreign key f1p_ref on app.f1p makes the blind-index column email_idx"
                + " (@BlindIndex Note.emailIndex) reference app.f1p_parent, so app.f1p_parent"
                + " holds the same index values and no erasure reaches it.");
  }

  // ------------------------------------------------------------------- row 25: publications

  @Test
  void p1_publication_without_update_refused() {
    table("app.p1");
    exec(owner, "CREATE PUBLICATION p1_pub FOR TABLE app.p1 WITH (publish = 'insert')");
    try {
      assertThat(copied("app.p1"))
          .contains(
              "shredding: publication p1_pub publishes the blind-index column app.p1.email_idx"
                  + " (@BlindIndex Note.emailIndex) and does not publish UPDATE: a subscriber"
                  + " keeps every index value it received after every erasure. Publish the table"
                  + " with a column list that leaves out email_idx, or remove it from the"
                  + " publication.");
    } finally {
      exec(su, "DROP PUBLICATION p1_pub");
    }
  }

  @Test
  void p2_publication_with_update_is_refused_in_three_forms() {
    table("app.p2");
    exec(
        owner,
        "CREATE TABLE app.p2_root (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64), note text) PARTITION BY LIST (tenant)",
        "CREATE TABLE app.p2_root_a PARTITION OF app.p2_root FOR VALUES IN ('T1')",
        "GRANT SELECT, UPDATE ON app.p2_root, app.p2_root_a TO " + APP);
    for (String form :
        List.of(
            "FOR TABLE app.p2",
            "FOR TABLES IN SCHEMA app",
            "FOR ALL TABLES",
            "FOR TABLE app.p2_root WITH (publish_via_partition_root = true)")) {
      exec(su, "CREATE PUBLICATION p2_pub " + form);
      try {
        String table = form.contains("p2_root") ? "app.p2_root" : "app.p2";
        assertThat(copied(table))
            .describedAs(form)
            .contains(
                "shredding: publication p2_pub publishes the blind-index column "
                    + table
                    + ".email_idx (@BlindIndex Note.emailIndex). A subscriber receives the"
                    + " erasure's UPDATE, but what it keeps is out of this module's sight."
                    + " Publish the table with a column list that leaves out email_idx, or remove"
                    + " it from the publication.");
      } finally {
        exec(su, "DROP PUBLICATION p2_pub");
      }
    }
  }

  @Test
  void p3_column_list_excluding_index_admitted() {
    table("app.p3");
    exec(owner, "CREATE PUBLICATION p3_pub FOR TABLE app.p3 (id, tenant, subject)");
    try {
      assertThat(verdict("app.p3")).isInstanceOf(Admitted.class);
    } finally {
      exec(su, "DROP PUBLICATION p3_pub");
    }
  }

  @Test
  void k5_publication_for_all_tables_created_during_erasure_refuses_that_erasure()
      throws Exception {
    table("app.k5");
    var during = new BlockingReadBack();
    JdbcErasureStore store = store("app.k5", during);
    long records = records();
    CompletableFuture<Throwable> erasure =
        CompletableFuture.supplyAsync(() -> catchThrowable(() -> erase(store, "app.k5-s-1")));
    during.awaitInside();
    try {
      exec(su, "CREATE PUBLICATION k5_pub FOR ALL TABLES");
    } finally {
      during.release();
    }
    try {
      Throwable thrown = erasure.get(30, TimeUnit.SECONDS);

      assertThat(code(thrown)).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
      assertThat(thrown)
          .hasMessageContaining("publication k5_pub publishes the blind-index column")
          .hasMessageContaining("Found after this erasure's UPDATE");
      assertThat(records()).isEqualTo(records);
      assertThat(indexed("app.k5", "app.k5-s-1")).isEqualTo(1);
    } finally {
      exec(su, "DROP PUBLICATION k5_pub");
    }
  }

  // ------------------------------------------------------------ row 27b: logical slots

  @Test
  void l1_non_pgoutput_logical_slot_refused() {
    table("app.l1");
    exec(su, "SELECT pg_create_logical_replication_slot('l1_cdc', 'test_decoding')");
    try {
      assertThat(copied("app.l1"))
          .contains(
              "shredding: logical replication slot l1_cdc (plugin test_decoding) decodes every"
                  + " table of this database, including app.l1 with blind-index column email_idx"
                  + " (@BlindIndex Note.emailIndex). Every index value written since the slot was"
                  + " created has already been sent to its consumer, and this module cannot see or"
                  + " clear what the consumer keeps. Drop the slot, or publish through pgoutput"
                  + " with a column list that excludes the index.");
    } finally {
      exec(su, "SELECT pg_drop_replication_slot('l1_cdc')");
    }
  }

  @Test
  void l2_inactive_slot_still_refused() {
    table("app.l2");
    exec(su, "SELECT pg_create_logical_replication_slot('l2_cdc', 'test_decoding')");
    try {
      assertThat(text(su, "SELECT active FROM pg_replication_slots WHERE slot_name = 'l2_cdc'"))
          .isEqualTo("f");
      assertThat(copied("app.l2")).contains("logical replication slot l2_cdc");
    } finally {
      exec(su, "SELECT pg_drop_replication_slot('l2_cdc')");
    }
  }

  @Test
  void l3_pgoutput_slot_left_to_publication_leg() {
    table("app.l3");
    exec(su, "SELECT pg_create_logical_replication_slot('l3_sub', 'pgoutput')");
    try {
      assertThat(verdict("app.l3")).isInstanceOf(Admitted.class);
    } finally {
      exec(su, "SELECT pg_drop_replication_slot('l3_sub')");
    }
  }

  @Test
  void l4_slot_in_other_database_not_reported() {
    table("app.l4");
    exec(su, "CREATE DATABASE l4_other");
    HikariDataSource other =
        pool(
            POSTGRES.getUsername(),
            POSTGRES.getPassword(),
            POSTGRES.getJdbcUrl().replace("/" + POSTGRES.getDatabaseName(), "/l4_other"));
    exec(other, "SELECT pg_create_logical_replication_slot('l4_cdc', 'test_decoding')");
    try {
      assertThat(verdict("app.l4")).isInstanceOf(Admitted.class);
    } finally {
      exec(other, "SELECT pg_drop_replication_slot('l4_cdc')");
    }
  }

  // ------------------------------------------------- rows 10, 11, 45: stale audit and history

  @Test
  void e9_envers_disabled_stale_audit_column_is_refused() {
    table("app.e9");
    exec(owner, "CREATE TABLE app.e9_aud (id bigint, rev integer, revtype smallint,"
        + " email_idx varchar(64))");

    assertThat(copied("app.e9"))
        .contains(
            "shredding: app.e9_aud has a column email_idx and is named as Hibernate Envers names"
                + " the audit table of app.e9. No erasure reaches it. Clear and drop the column:"
                + " UPDATE app.e9_aud SET email_idx = NULL; ALTER TABLE app.e9_aud DROP COLUMN"
                + " email_idx. If it is not an audit table, rename the column.");
  }

  @Test
  void e10_stale_audit_column_found_by_name_without_signature() {
    table("app.e10");
    exec(owner, "CREATE TABLE app.\"e10_AUD\" (id bigint, email_idx varchar(64))");

    assertThat(copied("app.e10")).contains("shredding: app.\"e10_AUD\" has a column email_idx");
  }

  @Test
  void e15_renamed_stale_audit_table_found_by_shape() {
    table("app.e15");
    exec(owner, "CREATE TABLE audit.old_customer_hist (id bigint, rev integer, revtype smallint,"
        + " email_idx varchar(64))");

    assertThat(copied("app.e15"))
        .contains(
            "shredding: audit.old_customer_hist has a column email_idx, the blind-index column"
                + " of app.e15, together with the columns rev and revtype that Hibernate Envers"
                + " writes in an audit table. No erasure reaches it. If it is an audit table from"
                + " an earlier configuration, clear and drop the column: UPDATE"
                + " audit.old_customer_hist SET email_idx = NULL; ALTER TABLE"
                + " audit.old_customer_hist DROP COLUMN email_idx. If it is not, rename the"
                + " column.");
  }

  @Test
  void e17_stale_temporal_history_table_found_by_shape() {
    table("app.e17");
    exec(owner, "CREATE TABLE audit.e17_versions (id bigint, effective timestamp,"
        + " superseded timestamp, email_idx varchar(64))");

    assertThat(copied("app.e17"))
        .contains(
            "audit.e17_versions has a column email_idx, the blind-index column of app.e17,"
                + " together with the columns effective and superseded that Hibernate writes in a"
                + " history table.");
  }

  @Test
  void e18_table_with_index_name_but_no_revision_signature_admitted() {
    table("app.e18");
    exec(
        owner,
        "CREATE TABLE audit.e18_other (id bigint, rev integer, email_idx varchar(64))",
        "CREATE TABLE audit.e18_more (id bigint, email_idx varchar(64))");

    assertThat(verdict("app.e18")).isInstanceOf(Admitted.class);
  }

  @Test
  void reported_copies_and_configured_signatures_are_refused() {
    table("app.e19");
    exec(
        owner,
        "CREATE TABLE audit.\"Note Archive\" (id bigint, email_idx varchar(64))",
        "CREATE TABLE audit.e19_rev (id bigint, \"REVISION\" integer, kind smallint,"
            + " email_idx varchar(64))");
    var signatures =
        new CopySignatures(
            List.of(
                new CopySignatures.NamedCopy(
                    TableRef.parse("app.e19"),
                    TableRef.parse("audit.\"Note Archive\""),
                    "Hibernate Envers",
                    "audit")),
            List.of(new CopySignatures.RevisionSignature("Hibernate Envers", "audit",
                "REVISION", "kind")));

    Verdict verdict = verdict(app, "app.e19", signatures);

    assertThat(verdict).isInstanceOf(Copied.class);
    assertThat(((Copied) verdict).message())
        .contains(
            "shredding: audit.\"Note Archive\" has a column email_idx and is the audit table"
                + " Hibernate Envers writes for app.e19.")
        .contains(
            "audit.e19_rev has a column email_idx, the blind-index column of app.e19, together"
                + " with the columns \"REVISION\" and kind that Hibernate Envers writes in an"
                + " audit table.");
    assertThat(verdict("app.e19")).isInstanceOf(Admitted.class);
  }

  @Test
  void one_message_lists_every_finding_of_a_table() {
    table("app.all");
    exec(
        owner,
        "CREATE FUNCTION app.all_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$",
        "CREATE TRIGGER all_tr AFTER UPDATE ON app.all FOR EACH ROW EXECUTE FUNCTION"
            + " app.all_f()",
        "CREATE MATERIALIZED VIEW app.all_mv AS SELECT email_idx FROM app.all",
        "CREATE TABLE app.all_aud (id bigint, rev integer, revtype smallint, email_idx text)");

    String message = copied("app.all");

    assertThat(message)
        .contains("has trigger all_tr")
        .contains("materialized view app.all_mv")
        .contains("app.all_aud has a column email_idx");
  }

  // --------------------------------------------------------- row 32: hostile path, failure, cost

  @Test
  void k1_copy_leg_identical_on_hostile_path() {
    table("app.k1");
    exec(
        owner,
        "CREATE FUNCTION app.k1_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$",
        "CREATE TRIGGER k1_tr AFTER UPDATE ON app.k1 FOR EACH ROW EXECUTE FUNCTION app.k1_f()",
        "CREATE RULE k1_rule AS ON DELETE TO app.k1 DO ALSO NOTHING",
        "CREATE MATERIALIZED VIEW app.k1_mv AS SELECT email_idx FROM app.k1",
        "CREATE TABLE app.k1_aud (id bigint, rev integer, revtype smallint, email_idx text)",
        "ALTER TABLE app.k1 ADD CONSTRAINT k1_u UNIQUE (email_idx)",
        "CREATE TABLE app.k1_child (r varchar(64) CONSTRAINT k1_ref REFERENCES app.k1"
            + " (email_idx))",
        "CREATE PUBLICATION k1_pub FOR TABLE app.k1");
    table("app.k1_clean");
    exec(
        app,
        "CREATE VIEW decoy.pg_trigger AS SELECT * FROM pg_catalog.pg_trigger WHERE false",
        "CREATE VIEW decoy.pg_rewrite AS SELECT * FROM pg_catalog.pg_rewrite WHERE false",
        "CREATE VIEW decoy.pg_depend AS SELECT * FROM pg_catalog.pg_depend WHERE false",
        "CREATE VIEW decoy.pg_constraint AS SELECT * FROM pg_catalog.pg_constraint WHERE false",
        "CREATE VIEW decoy.pg_publication AS SELECT * FROM pg_catalog.pg_publication"
            + " WHERE false",
        "CREATE VIEW decoy.pg_replication_slots AS SELECT * FROM"
            + " pg_catalog.pg_replication_slots WHERE false",
        "CREATE VIEW decoy.pg_attribute AS SELECT * FROM pg_catalog.pg_attribute WHERE false",
        "CREATE VIEW decoy.pg_class AS SELECT * FROM pg_catalog.pg_class WHERE false",
        "CREATE FUNCTION decoy.pg_get_publication_tables(VARIADIC text[], OUT pubid oid,"
            + " OUT relid oid, OUT attrs int2vector, OUT qual pg_node_tree) RETURNS SETOF record"
            + " LANGUAGE sql AS $$ SELECT NULL::oid, NULL::oid, NULL::int2vector,"
            + " NULL::pg_node_tree WHERE false $$",
        "CREATE FUNCTION decoy.f_oid(pg_catalog.oid, pg_catalog.oid) RETURNS boolean"
            + " LANGUAGE sql AS $$ SELECT false $$",
        "CREATE OPERATOR decoy.= (LEFTARG = pg_catalog.oid, RIGHTARG = pg_catalog.oid,"
            + " PROCEDURE = decoy.f_oid)",
        "CREATE FUNCTION decoy.f_name(pg_catalog.name, pg_catalog.name) RETURNS boolean"
            + " LANGUAGE sql AS $$ SELECT false $$",
        "CREATE OPERATOR decoy.= (LEFTARG = pg_catalog.name, RIGHTARG = pg_catalog.name,"
            + " PROCEDURE = decoy.f_name)",
        "CREATE OPERATOR decoy.<> (LEFTARG = pg_catalog.name, RIGHTARG = pg_catalog.name,"
            + " PROCEDURE = decoy.f_name)");
    try {
      HikariDataSource hostile =
          pool(APP, "pw", null, "SET search_path = decoy, app, public, pg_catalog");
      for (String table : List.of("app.k1", "app.k1_clean")) {
        assertThat(verdict(hostile, table, CopySignatures.defaults()))
            .describedAs(table)
            .isEqualTo(verdict(app, table, CopySignatures.defaults()));
      }
      assertThat(verdict("app.k1")).isInstanceOf(Copied.class);
    } finally {
      exec(su, "DROP PUBLICATION k1_pub");
    }
  }

  @Test
  void k2_copy_leg_failure_is_unverifiable() throws SQLException {
    table("app.k2");
    exec(owner, "CREATE TABLE app.k2_aud (id bigint, rev integer, revtype smallint)");
    assertThat(CopyCatalogue.STATEMENTS).hasSizeGreaterThanOrEqualTo(7);
    for (String failing : CopyCatalogue.STATEMENTS) {
      try (Connection c = app.getConnection()) {
        Connection broken = failingOn(c, failing);
        Throwable thrown =
            catchThrowable(
                () ->
                    MappingAdmission.verdict(
                        broken, target("app.k2"), CopySignatures.defaults()));

        assertThat(thrown).describedAs(failing).isInstanceOf(ShreddingException.class);
        assertThat(((ShreddingException) thrown).code())
            .describedAs(failing)
            .isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
      }
    }
  }

  @Test
  void k3_copy_leg_cost_per_erasure() throws SQLException {
    table("app.k3");
    var counted = new AtomicInteger();
    try (Connection c = app.getConnection()) {
      Connection counting = counting(c, counted);
      MappingAdmission.verdict(counting, target("app.k3"), CopySignatures.defaults());
      int statements = counted.get();
      exec(owner, "INSERT INTO app.k3 SELECT g, 'T1', 'app.k3-x-' || g, md5(g::text), 'n'"
          + " FROM generate_series(1, 20000) g");
      counted.set(0);
      MappingAdmission.verdict(counting, target("app.k3"), CopySignatures.defaults());

      assertThat(counted.get()).describedAs("statements do not grow with rows").isEqualTo(
          statements);
      long[] nanos = new long[21];
      for (int i = 0; i < nanos.length; i++) {
        long start = System.nanoTime();
        MappingAdmission.verdict(c, target("app.k3"), CopySignatures.defaults());
        nanos[i] = System.nanoTime() - start;
      }
      java.util.Arrays.sort(nanos);
      System.out.println(
          "K3 verdict statements="
              + statements
              + " median ms="
              + nanos[nanos.length / 2] / 1_000_000.0
              + " max ms="
              + nanos[nanos.length - 1] / 1_000_000.0);
    }
    JdbcErasureStore store = store("app.k3");
    long[] erasures = new long[11];
    for (int i = 0; i < erasures.length; i++) {
      long start = System.nanoTime();
      erase(store, "app.k3-x-" + (i + 1));
      erasures[i] = System.nanoTime() - start;
    }
    java.util.Arrays.sort(erasures);
    System.out.println(
        "K3 erasure (K twice) median ms=" + erasures[erasures.length / 2] / 1_000_000.0);
  }

  // ------------------------------------------------------------------------------ helpers

  /** Holds an erasure inside its read-back, after its UPDATE, until released. */
  private static final class BlockingReadBack implements BlindIndexResidual {
    private final CountDownLatch inside = new CountDownLatch(1);
    private final CountDownLatch release = new CountDownLatch(1);

    @Override
    public long count(Connection c, BlindIndexColumn column, TenantId tenant, SubjectId subject) {
      inside.countDown();
      try {
        release.await(30, TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      return 0L;
    }

    void awaitInside() throws InterruptedException {
      assertThat(inside.await(30, TimeUnit.SECONDS)).isTrue();
    }

    void release() {
      release.countDown();
    }
  }

  private static Connection failingOn(Connection c, String fragment) {
    return (Connection)
        Proxy.newProxyInstance(
            Connection.class.getClassLoader(),
            new Class<?>[] {Connection.class},
            (proxy, method, args) -> {
              if ("prepareStatement".equals(method.getName()) && fragment.equals(args[0])) {
                throw new SQLException("probe: refused a copy-leg statement", "XX000");
              }
              try {
                return method.invoke(c, args);
              } catch (java.lang.reflect.InvocationTargetException e) {
                throw e.getCause();
              }
            });
  }

  private static Connection counting(Connection c, AtomicInteger counter) {
    return (Connection)
        Proxy.newProxyInstance(
            Connection.class.getClassLoader(),
            new Class<?>[] {Connection.class},
            (proxy, method, args) -> {
              if ("prepareStatement".equals(method.getName())) {
                counter.incrementAndGet();
              }
              try {
                return method.invoke(c, args);
              } catch (java.lang.reflect.InvocationTargetException e) {
                throw e.getCause();
              }
            });
  }

  private static void table(String table) {
    exec(
        owner,
        "CREATE TABLE "
            + table
            + " (id bigint, tenant varchar(64), subject varchar(64), email_idx varchar(64),"
            + " note text)",
        "GRANT SELECT, UPDATE ON " + table + " TO " + APP);
    rows(table);
  }

  private static void rows(String table) {
    exec(
        owner,
        "INSERT INTO "
            + table
            + " (id, tenant, subject, email_idx) SELECT g, 'T1', '"
            + table
            + "-s-' || g, md5(g::text)"
            + " FROM generate_series(1, 5) g");
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

  private static Target target(String table) {
    return new Target(Optional.of("Note"), TableRef.parse(table), cols());
  }

  private static Verdict verdict(String table) {
    return verdict(app, table, CopySignatures.defaults());
  }

  private static Verdict verdict(DataSource ds, String table, CopySignatures signatures) {
    try (Connection c = ds.getConnection()) {
      return MappingAdmission.verdict(c, target(table), signatures);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String copied(String table) {
    Verdict verdict = verdict(table);
    assertThat(verdict).describedAs(table).isInstanceOf(Copied.class);
    return ((Copied) verdict).message();
  }

  private static JdbcErasureStore store(String table) {
    return store(table, (c, col, tenant, subject) -> 0L);
  }

  private static JdbcErasureStore store(String table, BlindIndexResidual residual) {
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
        residual,
        CopySignatures.defaults());
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

  private static long records() {
    return Long.parseLong(text(su, "SELECT count(*) FROM public.shredding_erasure"));
  }

  private static long indexed(String table, String subject) {
    return Long.parseLong(
        text(
            su,
            "SELECT count(*) FROM "
                + table
                + " WHERE subject = '"
                + subject
                + "' AND email_idx IS NOT NULL"));
  }

  private static int occurrences(String text, String needle) {
    int n = 0;
    for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) {
      n++;
    }
    return n;
  }

  private static String code(Throwable thrown) {
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    return ((ShreddingException) thrown).code();
  }

  private static HikariDataSource pool(String user, String password, String url) {
    return pool(user, password, url, null);
  }

  private static HikariDataSource pool(
      String user, String password, String url, String initSql) {
    var config = new HikariConfig();
    config.setJdbcUrl(url == null ? POSTGRES.getJdbcUrl() : url);
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(3);
    if (initSql != null) {
      config.setConnectionInitSql(initSql);
    }
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
