package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Acknowledged;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Admitted;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Copied;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Refused;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Use;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Verdict;
import com.housedevinci.shredding.application.AcknowledgedCopy;
import com.housedevinci.shredding.application.DataKeyCache;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureResult;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.application.ErasureStore;
import com.housedevinci.shredding.application.PostErasureHook;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.HookOutcome;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * The acknowledgement mechanism of the audit-table coverage design (section 3c, rows 15, 25, 27b,
 * 42, 49, 50) against PostgreSQL: an entry admits exactly the object it names and nothing else
 * (A1-A3, A12, P2, L1, T2), an entry that admits nothing refuses at the erasure as at startup (A7),
 * the store refuses an erasure whose record does not name what it admitted (C12, W1-W6), printed
 * identifiers are escaped while the record keeps them raw (W7), and every append answers the
 * subject's outstanding hooks (C11 store side, Y9, Y10).
 *
 * <p>Fixture as {@code CopyCataloguePostgresTest}: PostgreSQL 16 with {@code wal_level=logical},
 * {@code shred_owner} owns schema {@code app}, {@code shred_app} ({@code NOSUPERUSER}) holds {@code
 * SELECT, UPDATE} on each table and reads every verdict; the statistics-off event trigger is
 * installed so planner statistics never decide here.
 */
class AcknowledgedCopiesPostgresTest {

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
      "acknowledged-copies-secret-32-byt".getBytes(StandardCharsets.UTF_8);
  private static final Pseudonymiser PSEUDONYMS = new Pseudonymiser(SECRET);
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
    su = pool(POSTGRES.getUsername(), POSTGRES.getPassword());
    exec(
        su,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA app AUTHORIZATION " + OWNER,
        "GRANT USAGE ON SCHEMA app TO " + APP);
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
  static void stop() {
    pools.forEach(HikariDataSource::close);
    POSTGRES.stop();
  }

  // ------------------------------------------------------------- T2, A1, A2, A3: triggers

  @Test
  void t2_acknowledged_trigger_is_admitted_and_warns() {
    historyTrigger("app.t2", "t2_audit");
    var entry = AcknowledgedCopy.trigger("app", "t2", "t2_audit", "historyScrubber");

    Verdict verdict = verdict("app.t2", List.of(entry));

    assertThat(verdict).isInstanceOf(Admitted.class);
    assertThat(((Admitted) verdict).acknowledged())
        .singleElement()
        .satisfies(
            a -> {
              assertThat(a.entry()).isZero();
              assertThat(a.warning())
                  .isEqualTo(
                      "shredding: trigger \"app\".\"t2\".\"t2_audit\" on a table with blind-index"
                          + " column email_idx (@BlindIndex Note.emailIndex) is admitted by"
                          + " shredding.jdbc.acknowledged-copies[0] and cleared by hook"
                          + " historyScrubber. This module does not see what the trigger writes or"
                          + " what the hook clears; each erasure is recorded PARTIAL until that"
                          + " hook reports success, and its record names this trigger.");
            });
  }

  @Test
  void t1_unacknowledged_trigger_message_offers_the_acknowledgement() {
    historyTrigger("app.t1b", "t1b_audit");

    assertThat(((Copied) verdict("app.t1b", List.of())).message())
        .endsWith(
            "Drop or disable the trigger: ALTER TABLE app.t1b DISABLE TRIGGER t1b_audit. Or, if it"
                + " never stores the index or a hook clears what it stores, acknowledge it with"
                + " the hook that clears it: shredding.jdbc.acknowledged-copies[n] with"
                + " kind=trigger, schema=app, table=t1b, name=t1b_audit, cleared-by=<hook"
                + " name>.");
  }

  @Test
  void a1_dotted_quoted_trigger_name_matches_exactly() throws SQLException {
    // A mapped table name is [a-z_][a-z0-9_]* (TableRef), so the quoted, dotted, upper-case
    // identifier is the trigger's own name: the one an entry spells and the catalogue stores.
    table("app.a1");
    exec(
        owner,
        "CREATE FUNCTION app.a1_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$",
        "CREATE TRIGGER \"Audit.Copy\" AFTER UPDATE ON app.a1 FOR EACH ROW EXECUTE"
            + " FUNCTION app.a1_f()");

    var exact = AcknowledgedCopy.trigger("app", "a1", "Audit.Copy", "h");
    assertThat(verdict("app.a1", List.of(exact))).isInstanceOf(Admitted.class);

    for (AcknowledgedCopy near :
        List.of(
            AcknowledgedCopy.trigger("app", "a1", "audit.copy", "h"),
            AcknowledgedCopy.trigger("APP", "a1", "Audit.Copy", "h"),
            AcknowledgedCopy.trigger("app", "A1", "Audit.Copy", "h"),
            AcknowledgedCopy.trigger("app.a1", "Audit", "Copy", "h"),
            AcknowledgedCopy.trigger("app", "a1", "\"Audit.Copy\"", "h"))) {
      assertThat(verdict("app.a1", List.of(near)))
          .describedAs(near.object())
          .isInstanceOf(Copied.class);
      assertThat(unused(List.of(near)))
          .singleElement()
          .satisfies(
              m ->
                  assertThat(m)
                      .endsWith(
                          "which does not exist. Names are compared exactly"
                              + " as pg_catalog stores them (unquoted SQL names are stored in lower case). Remove"
                              + " the entry or correct it."));
    }
  }

  @Test
  void a2_wildcard_entry_refused() throws SQLException {
    historyTrigger("app.a2", "a2_audit");
    for (String pattern : List.of("*", "%", "a2_%", "a2_.*", ".*")) {
      var entry = AcknowledgedCopy.trigger("app", "a2", pattern, "h");
      assertThat(verdict("app.a2", List.of(entry))).describedAs(pattern).isInstanceOf(Copied.class);
      assertThat(unused(List.of(entry)))
          .singleElement()
          .satisfies(m -> assertThat(m).contains("does not exist"));
    }
    var schemaWildcard = AcknowledgedCopy.trigger("%", "a2", "a2_audit", "h");
    assertThat(verdict("app.a2", List.of(schemaWildcard))).isInstanceOf(Copied.class);
  }

  @Test
  void a3_entry_on_unrelated_table_refused() throws SQLException {
    table("app.a3");
    exec(
        owner,
        "CREATE TABLE app.a3_other (id bigint)",
        "CREATE FUNCTION app.a3_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$",
        "CREATE TRIGGER a3_audit AFTER UPDATE ON app.a3_other FOR EACH ROW EXECUTE FUNCTION"
            + " app.a3_f()");
    var entry = AcknowledgedCopy.trigger("app", "a3_other", "a3_audit", "h");

    assertThat(verdict("app.a3", List.of(entry))).isInstanceOf(Admitted.class);
    assertThat(((Admitted) verdict("app.a3", List.of(entry))).acknowledged()).isEmpty();
    assertThat(unused(List.of(entry)))
        .containsExactly(
            "shredding: shredding.jdbc.acknowledged-copies[0] names trigger"
                + " \"app\".\"a3_other\".\"a3_audit\", which is on app.a3_other, which is not a"
                + " table this module erases or a descendant of one. An entry that grants nothing"
                + " now would grant silently later; remove it.");
  }

  @Test
  void a3_disabled_trigger_entry_grants_nothing_and_refuses() throws SQLException {
    historyTrigger("app.a3d", "a3d_audit");
    exec(owner, "ALTER TABLE app.a3d DISABLE TRIGGER a3d_audit");
    var entry = AcknowledgedCopy.trigger("app", "a3d", "a3d_audit", "h");

    assertThat(verdict("app.a3d", List.of(entry))).isInstanceOf(Admitted.class);
    assertThat(unused(List.of(entry)))
        .singleElement()
        .satisfies(m -> assertThat(m).contains("is disabled"));
  }

  @Test
  void a3_two_entries_for_one_object_are_refused() {
    var one = AcknowledgedCopy.trigger("app", "x", "y", "h1");
    var two = AcknowledgedCopy.trigger("app", "x", "y", "h2");
    assertThat(catchThrowable(() -> AcknowledgedCopies.requireDistinct(List.of(one, two))))
        .isInstanceOf(ShreddingException.class)
        .hasMessage(
            "shredding: shredding.jdbc.acknowledged-copies[1] names trigger \"app\".\"x\".\"y\", as"
                + " shredding.jdbc.acknowledged-copies[0] does. Name each object once, with the"
                + " one hook that clears it.");
  }

  // ------------------------------------------------------------------ A12: ancestors (R-i)

  @Test
  void a12_acknowledgement_naming_an_ancestor_is_refused() throws SQLException {
    exec(
        owner,
        "CREATE TABLE app.a12 (id bigint, tenant varchar(64), subject varchar(64), email_idx"
            + " varchar(64), note text) PARTITION BY RANGE (id)",
        "CREATE TABLE app.a12_p1 PARTITION OF app.a12 FOR VALUES FROM (0) TO (1000)",
        "GRANT SELECT, UPDATE ON app.a12, app.a12_p1 TO " + APP,
        "CREATE FUNCTION app.a12_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$",
        "CREATE TRIGGER a12_audit AFTER UPDATE ON app.a12 FOR EACH ROW EXECUTE FUNCTION"
            + " app.a12_f()");
    var onParent = AcknowledgedCopy.trigger("app", "a12", "a12_audit", "h");
    var onClone = AcknowledgedCopy.trigger("app", "a12_p1", "a12_audit", "h");

    for (AcknowledgedCopy entry : List.of(onParent, onClone)) {
      Verdict verdict = verdict("app.a12_p1", List.of(entry));
      assertThat(verdict)
          .describedAs("the mapped partition has an ancestor: -009 decides before any entry")
          .isInstanceOf(Refused.class);
      Throwable thrown =
          catchThrowable(() -> erase(store("app.a12_p1", List.of(entry)), "a12-s", pending(entry)));
      assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    }
    assertThat(unused(List.of(onParent)))
        .singleElement()
        .satisfies(m -> assertThat(m).contains("which is not a table this module erases"));
    assertThat(unused(List.of(onClone)))
        .singleElement()
        .satisfies(m -> assertThat(m).contains("clone of a trigger on its parent table"));
  }

  // --------------------------------------------------------------- P2, L1: publications, slots

  @Test
  void p2_publication_with_update_is_admitted_when_acknowledged_and_without_update_never()
      throws SQLException {
    table("app.p2a");
    exec(
        su,
        "CREATE PUBLICATION p2a_pub FOR TABLE app.p2a",
        "CREATE PUBLICATION p2a_noupd FOR" + " TABLE app.p2a WITH (publish = 'insert, delete')");
    try {
      var ack = AcknowledgedCopy.publication("p2a_pub", "subscriberScrubber");
      var noUpdate = AcknowledgedCopy.publication("p2a_noupd", "subscriberScrubber");

      Verdict both = verdict("app.p2a", List.of(ack, noUpdate));
      assertThat(both).isInstanceOf(Copied.class);
      assertThat(((Copied) both).message())
          .contains("p2a_noupd")
          .doesNotContain("publication p2a_pub");
      assertThat(((Copied) both).acknowledged()).extracting(Acknowledged::entry).containsExactly(0);
      assertThat(unused(List.of(ack, noUpdate)))
          .containsExactly(
              "shredding: shredding.jdbc.acknowledged-copies[1] names publication \"p2a_noupd\","
                  + " which does not publish UPDATE, which cannot be acknowledged: a subscriber"
                  + " keeps every index value it received after every erasure. Publish UPDATE, or"
                  + " leave the index out of the publication's column list.");

      exec(su, "DROP PUBLICATION p2a_noupd");
      Verdict one = verdict("app.p2a", List.of(ack));
      assertThat(one).isInstanceOf(Admitted.class);
      assertThat(((Admitted) one).acknowledged().get(0).warning())
          .startsWith(
              "shredding: publication \"p2a_pub\" publishing the blind-index column app.p2a.email_idx"
                  + " (@BlindIndex Note.emailIndex) is admitted by"
                  + " shredding.jdbc.acknowledged-copies[0]")
          .contains("what a subscriber keeps");
      assertThat(((Copied) verdict("app.p2a", List.of())).message())
          .contains("kind=publication, name=p2a_pub, cleared-by=<hook name>.");
    } finally {
      exec(su, "DROP PUBLICATION IF EXISTS p2a_pub", "DROP PUBLICATION IF EXISTS p2a_noupd");
    }
  }

  @Test
  void l1_logical_slot_is_admitted_when_acknowledged_and_pgoutput_never() throws SQLException {
    table("app.l1a");
    exec(
        su,
        "SELECT pg_create_logical_replication_slot('l1a_cdc', 'test_decoding')",
        "SELECT pg_create_logical_replication_slot('l1a_sub', 'pgoutput')");
    try {
      var ack = AcknowledgedCopy.replicationSlot("l1a_cdc", "cdcScrubber");
      var pgoutput = AcknowledgedCopy.replicationSlot("l1a_sub", "cdcScrubber");

      assertThat(((Copied) verdict("app.l1a", List.of())).message())
          .contains("kind=replication-slot, name=l1a_cdc, cleared-by=<hook name>.");
      Verdict v = verdict("app.l1a", List.of(ack, pgoutput));
      assertThat(v).isInstanceOf(Admitted.class);
      assertThat(((Admitted) v).acknowledged().get(0).warning())
          .startsWith(
              "shredding: replication-slot \"l1a_cdc\" (plugin test_decoding) decoding a table"
                  + " with blind-index column email_idx");
      assertThat(unused(List.of(ack, pgoutput)))
          .containsExactly(
              "shredding: shredding.jdbc.acknowledged-copies[1] names replication-slot"
                  + " \"l1a_sub\", which uses pgoutput, which decodes only what a publication"
                  + " carries; acknowledge the publication instead.");
    } finally {
      exec(
          su,
          "SELECT pg_drop_replication_slot('l1a_cdc')",
          "SELECT pg_drop_replication_slot('l1a_sub')");
    }
  }

  // ----------------------------------------------------------------- A7: stale at an erasure

  @Test
  void a7_entry_object_dropped_after_boot_refuses_erasure_and_recreated_is_admitted() {
    historyTrigger("app.a7", "a7_audit");
    var entry = AcknowledgedCopy.trigger("app", "a7", "a7_audit", "h");
    JdbcErasureStore store = store("app.a7", List.of(entry));

    assertThat(erase(store, "app.a7-s-1", pending(entry)).record().outcome())
        .isEqualTo(ErasureOutcome.PARTIAL);

    exec(owner, "DROP TRIGGER a7_audit ON app.a7");
    long before = records();
    Throwable thrown = catchThrowable(() -> erase(store, "app.a7-s-2", pending(entry)));
    assertThat(code(thrown)).isEqualTo(ErrorCodes.CONFIG);
    assertThat(thrown.getMessage())
        .contains("names trigger \"app\".\"a7\".\"a7_audit\", which does not exist")
        .endsWith(
            "This erasure is refused before its first statement: no key is destroyed, no"
                + " blind index is touched and no record is appended.");
    assertThat(records()).isEqualTo(before);
    assertThat(indexed("app.a7", "app.a7-s-2")).isEqualTo(1);

    exec(
        owner,
        "CREATE TRIGGER a7_audit AFTER UPDATE ON app.a7 FOR EACH ROW EXECUTE FUNCTION"
            + " app.a7_audit_f()");
    assertThat(erase(store, "app.a7-s-2", pending(entry)).record().outcome())
        .isEqualTo(ErasureOutcome.PARTIAL);
  }

  // -------------------------------------------------------------------- W1 - W6: C12

  @Test
  void w1_decorator_hiding_acknowledged_copies_refuses_and_commits_nothing() {
    historyTrigger("app.w1", "w1_audit");
    var entry = AcknowledgedCopy.trigger("app", "w1", "w1_audit", "h");
    JdbcErasureStore store = store("app.w1", List.of(entry));
    insertKey("app.w1-s-1");
    ErasureStore hiding = decorator(store, false);
    String anchor = anchor();
    long rows = records();

    Throwable thrown =
        catchThrowable(
            () -> service(hiding, hook("h", true)).erase(request("app.w1-s-1", "app.w1-s-1")));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.CONFIG);
    assertThat(thrown.getMessage())
        .isEqualTo(
            "shredding: refused the erasure: acknowledged copy trigger \"app\".\"w1\".\"w1_audit\""
                + " is cleared by hook h, and the erasure record does not name that hook as"
                + " pending. ErasureService must be built on a store whose acknowledgedCopies()"
                + " returns this store's list; a wrapping ErasureStore must forward"
                + " acknowledgedCopies(). The transaction is rolled back: no key is destroyed, no"
                + " blind index is cleared and no record is appended.");
    assertThat(indexed("app.w1", "app.w1-s-1")).isEqualTo(1);
    assertThat(keyRows("app.w1-s-1")).isEqualTo(1);
    assertThat(
            text(su, "SELECT count(*) FROM shredding_erased_subject WHERE subject = 'app.w1-s-1'"))
        .isEqualTo("0");
    assertThat(records()).isEqualTo(rows);
    assertThat(anchor()).isEqualTo(anchor);
  }

  @Test
  void w2_forwarding_decorator_erases_partial_with_the_pending_name() {
    historyTrigger("app.w2", "w2_audit");
    var entry = AcknowledgedCopy.trigger("app", "w2", "w2_audit", "h");
    ErasureStore forwarding = decorator(store("app.w2", List.of(entry)), true);

    ErasureResult result =
        service(forwarding, hook("h", true)).erase(request("app.w2-s-1", "app.w2-s-1"));

    assertThat(result.records().get(0).outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(result.records().get(0).hookOutcomes())
        .containsExactly(new HookOutcome("h", false, "pending; clears " + entry.object()));
    assertThat(result.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
  }

  @Test
  void w3_record_complete_with_an_admitted_copy_is_refused() {
    historyTrigger("app.w3", "w3_audit");
    var entry = AcknowledgedCopy.trigger("app", "w3", "w3_audit", "h");
    long rows = records();

    Throwable thrown =
        catchThrowable(
            () ->
                erase(
                    store("app.w3", List.of(entry)),
                    "app.w3-s-1",
                    ErasureOutcome.COMPLETE,
                    pending(entry)));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.CONFIG);
    assertThat(thrown.getMessage()).contains("does not name that hook as pending");
    assertThat(records()).isEqualTo(rows);
    assertThat(indexed("app.w3", "app.w3-s-1")).isEqualTo(1);
  }

  @Test
  void w4_pending_outcome_naming_other_objects_is_refused() {
    historyTrigger("app.w4", "w4_audit");
    var entry = AcknowledgedCopy.trigger("app", "w4", "w4_audit", "h");
    var other = AcknowledgedCopy.trigger("app", "w4", "something_else", "h");

    for (HookOutcome wrong :
        List.of(
            new HookOutcome("h", false, "pending; clears " + other.object()),
            new HookOutcome("h", false, "pending"),
            new HookOutcome("other", false, "pending; clears " + entry.object()),
            new HookOutcome("h", true, "clears " + entry.object()))) {
      Throwable thrown =
          catchThrowable(() -> erase(store("app.w4", List.of(entry)), "app.w4-s-1", wrong));
      assertThat(code(thrown)).describedAs(wrong.toString()).isEqualTo(ErrorCodes.CONFIG);
    }
    assertThat(indexed("app.w4", "app.w4-s-1")).isEqualTo(1);
  }

  @Test
  void w5_no_acknowledged_copies_needs_no_pending_outcome() {
    table("app.w5");
    var outcome = erase(store("app.w5", List.of()), "app.w5-s-1", ErasureOutcome.COMPLETE);
    assertThat(outcome.record().outcome()).isEqualTo(ErasureOutcome.COMPLETE);
  }

  @Test
  void w6_two_copies_on_one_hook_in_any_config_order_match() {
    historyTrigger("app.w6", "w6_b_audit");
    exec(
        owner,
        "CREATE TRIGGER w6_a_audit AFTER UPDATE ON app.w6 FOR EACH ROW EXECUTE FUNCTION"
            + " app.w6_audit_f()");
    var a = AcknowledgedCopy.trigger("app", "w6", "w6_a_audit", "h");
    var b = AcknowledgedCopy.trigger("app", "w6", "w6_b_audit", "h");

    ErasureResult ab =
        service(store("app.w6", List.of(a, b)), hook("h", true))
            .erase(request("app.w6-s-1", "app.w6-s-1"));
    ErasureResult ba =
        service(store("app.w6", List.of(b, a)), hook("h", true))
            .erase(request("app.w6-s-2", "app.w6-s-2"));

    String expected =
        "pending; clears trigger \"app\".\"w6\".\"w6_a_audit\"; trigger \"app\".\"w6\".\"w6_b_audit\"";
    assertThat(ab.records().get(0).hookOutcomes())
        .containsExactly(new HookOutcome("h", false, expected));
    assertThat(ba.records().get(0).hookOutcomes())
        .containsExactly(new HookOutcome("h", false, expected));
  }

  // ----------------------------------------------------------------------------- W7

  @Test
  void w7_identifier_with_newline_is_escaped_in_the_log() throws SQLException {
    String odd = "w7\naudit x";
    historyTrigger("app.w7", "w7_plain");
    exec(owner, "ALTER TRIGGER w7_plain ON app.w7 RENAME TO \"" + odd + "\"");
    var entry = AcknowledgedCopy.trigger("app", "w7", odd, "h");

    Verdict verdict = verdict("app.w7", List.of(entry));
    String warning = ((Admitted) verdict).acknowledged().get(0).warning();
    assertThat(warning).doesNotContain("\n").doesNotContain(" ");
    assertThat(warning).contains("\"w7\\u000Aaudit\\u2028x\"");

    var missing = AcknowledgedCopy.trigger("app", "w7", odd + "\n2", "h");
    String refusal = unused(List.of(missing)).get(0);
    assertThat(refusal).doesNotContain("\n").contains("\\u000A2");

    ErasureResult result =
        service(store("app.w7", List.of(entry)), hook("h", true))
            .erase(request("app.w7-s-1", "app.w7-s-1"));
    assertThat(result.records().get(0).hookOutcomes().get(0).detail())
        .describedAs("the record keeps the raw identifier: it is hashed material")
        .isEqualTo("pending; clears trigger \"app\".\"w7\".\"" + odd + "\"");
  }

  // ------------------------------------------------------------------ Y9, Y10: store guard

  @Test
  void y9_jdbc_append_refuses_complete_leaving_an_outstanding_name() {
    table("app.y9");
    JdbcErasureStore store = store("app.y9", List.of());
    String subject = "app.y9-s-1";
    erase(store, subject, ErasureOutcome.PARTIAL, new HookOutcome("h1", false, "pending"));
    String anchor = anchor();
    long rows = records();

    Throwable thrown = catchThrowable(() -> store.append(record(subject, ErasureOutcome.COMPLETE)));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.CONFIG);
    assertThat(thrown.getMessage())
        .matches(
            "shredding: refused to append an erasure record for this subject: record [0-9]+ left"
                + " hook h1 pending or failed and the new record does not report it\\.");
    assertThat(records()).isEqualTo(rows);
    assertThat(anchor()).isEqualTo(anchor);
  }

  @Test
  void y10_jdbc_append_refuses_partial_that_drops_an_outstanding_name() {
    table("app.y10");
    JdbcErasureStore store = store("app.y10", List.of());
    String subject = "app.y10-s-1";
    erase(store, subject, ErasureOutcome.PARTIAL, new HookOutcome("h1", false, "pending"));
    String anchor = anchor();
    long rows = records();

    assertThat(
            code(
                catchThrowable(
                    () ->
                        store.append(
                            record(
                                subject, ErasureOutcome.PARTIAL, HookOutcome.failed("h2", "x"))))))
        .isEqualTo(ErrorCodes.CONFIG);
    assertThat(code(catchThrowable(() -> store.append(record(subject, ErasureOutcome.COMPLETE)))))
        .isEqualTo(ErrorCodes.CONFIG);
    Throwable twice =
        catchThrowable(
            () ->
                store.append(
                    record(
                        subject,
                        ErasureOutcome.COMPLETE,
                        HookOutcome.ok("h1"),
                        HookOutcome.ok("h1"))));
    assertThat(twice)
        .hasMessage(
            "shredding: refused to append an erasure record for this subject: it reports hook h1"
                + " more than once.");
    assertThat(records()).isEqualTo(rows);
    assertThat(anchor()).isEqualTo(anchor);

    // The answer the service would write is accepted.
    assertThat(
            store.append(record(subject, ErasureOutcome.COMPLETE, HookOutcome.ok("h1"))).outcome())
        .isEqualTo(ErasureOutcome.COMPLETE);
  }

  // ---------------------------------------------------------------------------- fixtures

  private static void table(String table) {
    exec(
        owner,
        "CREATE TABLE "
            + table
            + " (id bigint, tenant varchar(64), subject varchar(64), email_idx varchar(64),"
            + " note text)",
        "GRANT SELECT, UPDATE ON " + table + " TO " + APP,
        "INSERT INTO "
            + table
            + " (id, tenant, subject, email_idx) SELECT g, 'T1', '"
            + table.replace("'", "''")
            + "-s-' || g, md5(g::text) FROM generate_series(1, 3) g");
  }

  /** A table with an {@code AFTER UPDATE} trigger copying the row into a log table. */
  private static void historyTrigger(String table, String trigger) {
    table(table);
    String bare = table.substring(table.indexOf('.') + 1);
    exec(
        owner,
        "CREATE TABLE " + table + "_log (LIKE " + table + ")",
        "CREATE FUNCTION app."
            + bare
            + "_audit_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO "
            + table
            + "_log SELECT OLD.*; RETURN NULL; END $$",
        "GRANT INSERT ON " + table + "_log TO " + APP,
        "CREATE TRIGGER "
            + trigger
            + " AFTER UPDATE ON "
            + table
            + " FOR EACH ROW EXECUTE FUNCTION app."
            + bare
            + "_audit_f()");
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

  private static Verdict verdict(String table, List<AcknowledgedCopy> entries) {
    try (Connection c = app.getConnection()) {
      return MappingAdmission.verdict(
          c,
          new Target(Optional.of("Note"), TableRef.parse(table), cols()),
          CopySignatures.defaults(),
          entries);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static List<String> unused(List<AcknowledgedCopy> entries) throws SQLException {
    try (Connection c = app.getConnection()) {
      Set<Integer> used = new java.util.HashSet<>();
      // What the verdicts over every target used is decided by the caller; here, the unused
      // classification of entries no target admitted.
      for (int i = 0; i < entries.size(); i++) {
        if (entries.get(i).kind() == AcknowledgedCopy.Kind.PUBLICATION
            && "p2a_pub".equals(entries.get(i).name())) {
          used.add(i);
        }
        if (entries.get(i).kind() == AcknowledgedCopy.Kind.REPLICATION_SLOT
            && "l1a_cdc".equals(entries.get(i).name())) {
          used.add(i);
        }
      }
      return AcknowledgedCopies.unused(c, entries, used);
    }
  }

  private static JdbcErasureStore store(String table, List<AcknowledgedCopy> entries) {
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
        (c, col, tenant, subject) -> 0L,
        CopySignatures.defaults(),
        entries);
  }

  private static HookOutcome pending(AcknowledgedCopy entry) {
    return new HookOutcome(entry.clearedBy(), false, "pending; clears " + entry.object());
  }

  private static ErasureStore.Outcome erase(
      JdbcErasureStore store, String subjectId, HookOutcome... outcomes) {
    return erase(store, subjectId, ErasureOutcome.PARTIAL, outcomes);
  }

  private static ErasureStore.Outcome erase(
      JdbcErasureStore store, String subjectId, ErasureOutcome outcome, HookOutcome... outcomes) {
    return store.erase(
        T1, SubjectId.of(subjectId), (destroyed, cleared) -> record(subjectId, outcome, outcomes));
  }

  private static ErasureRecord record(
      String subjectId, ErasureOutcome outcome, HookOutcome... outcomes) {
    return ErasureRecord.of(
        Instant.now(),
        T1,
        PSEUDONYMS.pseudonym(T1, SubjectId.of(subjectId)),
        "dpo",
        "art 17",
        0,
        1,
        1,
        1,
        outcome,
        List.of(outcomes),
        Instant.now());
  }

  private static ErasureStore decorator(JdbcErasureStore store, boolean forwards) {
    return new ErasureStore() {
      @Override
      public Outcome erase(TenantId tenant, SubjectId subject, RecordFactory factory) {
        return store.erase(tenant, subject, factory);
      }

      @Override
      public List<AcknowledgedCopy> acknowledgedCopies() {
        return forwards ? store.acknowledgedCopies() : ErasureStore.super.acknowledgedCopies();
      }

      @Override
      public ErasureRecord append(ErasureRecord record) {
        return store.append(record);
      }

      @Override
      public Optional<ErasureRecord> latestForSubject(TenantId tenant, String pseudonym) {
        return store.latestForSubject(tenant, pseudonym);
      }
    };
  }

  private static PostErasureHook hook(String name, boolean succeeds) {
    return new PostErasureHook() {
      @Override
      public String name() {
        return name;
      }

      @Override
      public void afterErasure(TenantId tenant, SubjectId subject) {
        if (!succeeds) {
          throw new IllegalStateException("down");
        }
      }
    };
  }

  private static ErasureService service(ErasureStore store, PostErasureHook... hooks) {
    return new ErasureService(
        store,
        new DataKeyCache(Duration.ofSeconds(60), 10, Clock.systemUTC()),
        PSEUDONYMS,
        List.of(hooks),
        Duration.ZERO,
        Clock.systemUTC(),
        1,
        1);
  }

  private static ErasureRequest request(String rowSubject, String ignored) {
    return new ErasureRequest(T1, SubjectId.of(rowSubject), "dpo", "art 17");
  }

  /** A data-key row for {@code subject}, so the erasure has a key to destroy (or keep). */
  private static void insertKey(String subject) {
    exec(
        su,
        "INSERT INTO shredding_data_key (tenant, subject, version, wrapped_key, state, created_at,"
            + " encryption_count) SELECT 'T1', '"
            + subject
            + "', 1, '\\x00'::bytea, 'ACTIVE', now(), 0");
  }

  private static long keyRows(String subject) {
    return Long.parseLong(
        text(su, "SELECT count(*) FROM shredding_data_key WHERE subject = '" + subject + "'"));
  }

  private static long records() {
    return Long.parseLong(text(su, "SELECT count(*) FROM public.shredding_erasure"));
  }

  private static String anchor() {
    return text(su, "SELECT head_hash || '/' || row_count FROM public.shredding_erasure_anchor");
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

  private static String code(Throwable thrown) {
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    return ((ShreddingException) thrown).code();
  }

  private static HikariDataSource pool(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(3);
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
