package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Admitted;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Refused;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Use;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Verdict;
import com.housedevinci.shredding.application.ErasureStore;
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
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Mapping admission, one test per path (name-resolution design, addendum section A.10, rows N28 to
 * N50), on PostgreSQL in the two-role fixture of the section check: {@code citext}, {@code hstore}
 * and {@code postgres_fdw} installed into {@code public} by the superuser; the module's schema
 * installed by an owner role with the SECURITY-NOTES grant block; the runtime role {@code
 * shred_app} {@code NOSUPERUSER NOCREATEDB NOCREATEROLE}, owner of {@code app} and {@code decoy};
 * {@code app2} owned by the superuser for the RLS, {@code SELECT}-only and foreign-table cases.
 *
 * <p>Where a row's whole point is that the three legs of an erasure agree on a falsehood, the test
 * first measures that falsehood on the fixture with plain SQL, so a fixture that is not an attack
 * (the N-1 lesson: a {@code text} fixture proves nothing for {@code citext}) fails here rather than
 * passing a refusal nobody needed.
 */
class MappingAdmissionPostgresTest {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(Duration.ofMinutes(2));

  private static final String APP = "shred_app";
  private static final String OWNER = "shred_owner";
  private static final byte[] SECRET =
      "mapping-admission-chain-secret-32".getBytes(StandardCharsets.UTF_8);
  private static final TenantId T1 = TenantId.of("T1");

  private static HikariDataSource su;
  private static HikariDataSource app;
  private static VerifiedSchema schema;
  private static final List<HikariDataSource> pools = new ArrayList<>();

  @BeforeAll
  static void start() {
    POSTGRES.start();
    su = pool(POSTGRES.getUsername(), POSTGRES.getPassword(), 3, null);
    exec(
        su,
        "CREATE EXTENSION citext",
        "CREATE EXTENSION hstore",
        "CREATE EXTENSION postgres_fdw",
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "CREATE ROLE shred_byp LOGIN PASSWORD 'pw' NOSUPERUSER BYPASSRLS",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA app AUTHORIZATION " + APP,
        "CREATE SCHEMA decoy AUTHORIZATION " + APP,
        "CREATE SCHEMA app2",
        "GRANT USAGE ON SCHEMA app2 TO " + APP + ", shred_byp",
        "GRANT USAGE ON SCHEMA app TO shred_byp",
        "CREATE SERVER loop FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'localhost',"
            + " port '5432', dbname '"
            + POSTGRES.getDatabaseName()
            + "')",
        "GRANT USAGE ON FOREIGN SERVER loop TO " + APP,
        "CREATE USER MAPPING FOR PUBLIC SERVER loop OPTIONS (user '"
            + POSTGRES.getUsername()
            + "', password '"
            + POSTGRES.getPassword()
            + "')");
    HikariDataSource owner = pool(OWNER, "pw", 1, null);
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
    // The application's own path, with pg_catalog named late (rev 2.3 #6): the hostile shape.
    app = pool(APP, "pw", 3, "SET search_path = public, app, pg_catalog");
    // [advisory posture]: the role keeps TEMPORARY, which N36's temporary relation needs.
    schema = JdbcSupport.verifySchema(app, true).schema();
  }

  @AfterAll
  static void stop() {
    pools.forEach(HikariDataSource::close);
    POSTGRES.stop();
  }

  // ------------------------------------------------------------------------- N28 baseline

  @Test
  void n28_the_plain_varchar_mapping_is_admitted_and_erases() {
    plainTable("app.n28");
    Verdict verdict = verdict(app, target("app.n28"));
    assertThat(verdict).isInstanceOf(Admitted.class);
    assertThat(((Admitted) verdict).warnings()).isEmpty();

    var executions = new Counter();
    ErasureStore.Outcome outcome = erase(counting(app, executions), "app.n28");
    assertThat(outcome.blindIndexColumnsCleared()).isEqualTo(1);
    assertThat(text(su, "SELECT count(*) FROM app.n28 WHERE email_idx IS NOT NULL")).isEqualTo("0");
    assertThat(executions.of(MappingAdmission.RELATION_SQL))
        .describedAs("the verdict ran inside the erasure, once for its one table")
        .isEqualTo(1);
  }

  // -------------------------------------------------------------------------- R-a, R-b

  @Test
  void n29_a_table_text_with_no_schema_is_refused_by_the_catalogue_leg_too() {
    Verdict verdict = verdict(app, new Target(Optional.of("Note"), TableRef.of("n28"), cols()));
    assertThat(verdict).isInstanceOf(Refused.class);
    assertThat(((Refused) verdict).rule()).isEqualTo("R-a");
    assertThat(((Refused) verdict).message()).contains("names no schema");
  }

  @Test
  void n31_a_table_dropped_after_construction_refuses_the_erasure_and_records_nothing() {
    plainTable("app.n31");
    JdbcErasureStore store = store(app, "app.n31", honestResidual());
    exec(su, "DROP TABLE app.n31");
    long before = Long.parseLong(text(su, "SELECT count(*) FROM public.shredding_erasure"));

    Throwable thrown = catchThrowable(() -> eraseWith(store, "app.n31"));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(thrown).hasMessageContaining("app.n31").hasMessageContaining("does not exist");
    assertThat(Long.parseLong(text(su, "SELECT count(*) FROM public.shredding_erasure")))
        .describedAs("nothing is recorded")
        .isEqualTo(before);
  }

  /**
   * D16, and the reason the verdict is never cached (mutation 25): the table the store was built
   * for is renamed and replaced by a hiding view of the same name, which the runtime role may do.
   * The LOCK succeeds on a view (A26), so only the verdict read inside the erasure refuses it.
   */
  @Test
  void n31b_a_table_swapped_for_a_hiding_view_after_construction_is_refused_at_erasure() {
    plainTable("app.n31b");
    JdbcErasureStore store = store(app, "app.n31b", honestResidual());
    // A first erasure on the real table is admitted and completes, so a verdict remembered from
    // construction or from an earlier erasure would be "admitted" from here on.
    assertThat(eraseWith(store, "app.n31b").blindIndexColumnsCleared()).isEqualTo(1);
    exec(
        app(),
        "INSERT INTO app.n31b VALUES (2, 'T1', 's-second', 'HMAC-RESIDUE')",
        "ALTER TABLE app.n31b RENAME TO n31b_old",
        "CREATE VIEW app.n31b AS SELECT * FROM app.n31b_old WHERE (subject <> 's-second')");

    SubjectId second = SubjectId.of("s-second");
    Throwable thrown =
        catchThrowable(() -> store.erase(T1, second, (d, c) -> record(second, d, c)));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(thrown).hasMessageContaining("is a view");
    assertThat(text(su, "SELECT email_idx FROM app.n31b_old WHERE id = 2"))
        .isEqualTo("HMAC-RESIDUE");
  }

  @Test
  void n39b_an_absent_table_is_read_as_absent_and_never_as_an_absent_column() {
    Verdict verdict = verdict(app, target("app.never_created"));
    assertThat(verdict).isInstanceOf(MappingAdmission.Absent.class);
    assertThat(((MappingAdmission.Absent) verdict).message()).contains("does not exist");
  }

  // ------------------------------------------------------------------------------- R-c

  @Test
  void n32_a_hiding_view_is_refused_and_is_a_real_attack() {
    exec(
        app(),
        "CREATE TABLE app.n32_base (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "INSERT INTO app.n32_base VALUES (1, 'T1', 's1', 'HMAC-RESIDUE')",
        "CREATE VIEW app.n32 AS SELECT * FROM app.n32_base WHERE (subject <> 's1')");
    assertThat(sameTextUpdate("app.n32"))
        .describedAs("A6: the erasure's own UPDATE through the view clears nothing")
        .isZero();

    assertRefused(verdict(app, target("app.n32")), "R-c", "is a view");
    Throwable thrown = catchThrowable(() -> erase(app, "app.n32"));
    assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(text(su, "SELECT email_idx FROM app.n32_base")).isEqualTo("HMAC-RESIDUE");
  }

  @Test
  void n33_a_foreign_table_is_refused_by_the_verdict_and_independently_by_the_lock() {
    exec(
        su,
        "CREATE TABLE app2.n33_remote_base (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "INSERT INTO app2.n33_remote_base VALUES (1, 'T1', 's1', 'HMAC-RESIDUE')",
        "CREATE VIEW app2.n33_remote AS SELECT * FROM app2.n33_remote_base"
            + " WHERE (subject <> 's1')",
        "CREATE FOREIGN TABLE app2.n33 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) SERVER loop OPTIONS (schema_name 'app2',"
            + " table_name 'n33_remote')",
        "GRANT SELECT, UPDATE ON app2.n33 TO " + APP);
    assertRefused(verdict(app, target("app2.n33")), "R-c", "foreign table");

    Throwable thrown = catchThrowable(() -> erase(app, "app2.n33"));
    assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(thrown)
        .describedAs("A26: the LOCK refuses before the verdict is reached")
        .hasMessageContaining("42809");
  }

  // ------------------------------------------------------------------ R-d / R-e, partitions

  @Test
  void n34_partitioned_tables_with_ordinary_leaves_are_admitted_one_and_two_levels_deep() {
    exec(
        app(),
        "CREATE TABLE app.n34a (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) PARTITION BY LIST (tenant)",
        "CREATE TABLE app.n34a_t1 PARTITION OF app.n34a FOR VALUES IN ('T1')",
        "INSERT INTO app.n34a VALUES (1, 'T1', 's-app-n34a', 'HMAC-RESIDUE')",
        "CREATE TABLE app.n34b2 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) PARTITION BY LIST (tenant)",
        "CREATE TABLE app.n34b2_t1 PARTITION OF app.n34b2 FOR VALUES IN ('T1')"
            + " PARTITION BY LIST (subject)",
        "CREATE TABLE app.n34b2_t1s1 PARTITION OF app.n34b2_t1 FOR VALUES IN ('s-app-n34b2')",
        "INSERT INTO app.n34b2 VALUES (1, 'T1', 's-app-n34b2', 'HMAC-RESIDUE')");
    assertThat(verdict(app, target("app.n34a"))).isInstanceOf(Admitted.class);
    assertThat(verdict(app, target("app.n34b2")))
        .describedAs("S-3: a partitioned partition (descendant kinds pp,rp) is not a leaf")
        .isInstanceOf(Admitted.class);
    assertThat(erase(app, "app.n34a").blindIndexColumnsCleared()).isEqualTo(1);
    assertThat(erase(app, "app.n34b2").blindIndexColumnsCleared()).isEqualTo(1);
  }

  @Test
  void n34_a_partitioned_table_with_a_foreign_leaf_is_refused() {
    exec(
        su,
        "CREATE TABLE app2.n34f (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) PARTITION BY LIST (tenant)",
        "CREATE TABLE app2.n34f_t1 PARTITION OF app2.n34f FOR VALUES IN ('T1')",
        "CREATE TABLE app2.n34f_remote (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "CREATE FOREIGN TABLE app2.n34f_t2 PARTITION OF app2.n34f FOR VALUES IN ('T2')"
            + " SERVER loop OPTIONS (schema_name 'app2', table_name 'n34f_remote')",
        "GRANT SELECT, UPDATE ON app2.n34f TO " + APP);
    assertRefused(verdict(app, target("app2.n34f")), "R-d", "foreign table");
  }

  @Test
  void n34_a_partitioned_leaf_with_no_partitions_is_refused() {
    exec(
        app(),
        "CREATE TABLE app.n34e (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) PARTITION BY LIST (tenant)",
        "CREATE TABLE app.n34e_t1 PARTITION OF app.n34e FOR VALUES IN ('T1')"
            + " PARTITION BY LIST (subject)");
    assertRefused(verdict(app, target("app.n34e")), "R-d", "as a leaf");
  }

  /**
   * S-2, D13. An erasure holds its locks on a partitioned parent; a second session tries to change
   * the parent's descendant set. Both statements need SHARE UPDATE EXCLUSIVE on the parent, so step
   * 1b makes both wait until the erasure ends; with step 1b gone (mutation 30) both succeed while
   * the erasure's verdict still describes the old set.
   */
  @Test
  void n34b_attach_and_detach_concurrently_wait_for_the_erasure() {
    exec(
        app(),
        "CREATE TABLE app.n34b (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) PARTITION BY LIST (tenant)",
        "CREATE TABLE app.n34b_t1 PARTITION OF app.n34b FOR VALUES IN ('T1')",
        "CREATE TABLE app.n34b_t2 PARTITION OF app.n34b FOR VALUES IN ('T2')",
        "CREATE TABLE app.n34b_t9 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "INSERT INTO app.n34b VALUES (1, 'T1', 's-app-n34b', 'HMAC-RESIDUE')");
    var attempts = new ArrayList<String>();
    erase(
        app,
        "app.n34b",
        whileHeld(
            () -> {
              attempts.add(
                  concurrently(
                      "ALTER TABLE app.n34b ATTACH PARTITION app.n34b_t9 FOR VALUES IN ('T9')"));
              attempts.add(
                  concurrently("ALTER TABLE app.n34b DETACH PARTITION app.n34b_t2 CONCURRENTLY"));
            }));
    assertThat(attempts)
        .describedAs("both wait on the erasure's SHARE UPDATE EXCLUSIVE lock")
        .containsExactly("55P03", "55P03");
  }

  /**
   * S-2 for an ordinary table, measured during the build: {@code CREATE TABLE ... INHERITS} and
   * {@code ALTER TABLE ... INHERIT} take SHARE UPDATE EXCLUSIVE on the parent and do not conflict
   * with step 1's ROW EXCLUSIVE, so a table with no descendant at the verdict could gain one (a
   * foreign table over a hiding view) before the UPDATE routes to it. Step 1b is taken on every
   * table for this reason.
   */
  @Test
  void n34d_adding_an_inheritance_child_to_an_ordinary_table_waits_for_the_erasure() {
    plainTable("app.n34d");
    exec(
        app(),
        "CREATE TABLE app.n34d_x (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))");
    var attempts = new ArrayList<String>();
    erase(
        app,
        "app.n34d",
        whileHeld(
            () -> {
              attempts.add(concurrently("CREATE TABLE app.n34d_child () INHERITS (app.n34d)"));
              attempts.add(concurrently("ALTER TABLE app.n34d_x INHERIT app.n34d"));
            }));
    assertThat(attempts).containsExactly("55P03", "55P03");
  }

  @Test
  void n34c_an_unlogged_inheritance_child_is_admitted_with_a_warning() {
    plainTable("app.n34c");
    exec(app(), "CREATE UNLOGGED TABLE app.n34c_child () INHERITS (app.n34c)");
    Verdict verdict = verdict(app, target("app.n34c"));
    assertThat(verdict).isInstanceOf(Admitted.class);
    assertThat(((Admitted) verdict).warnings()).singleElement().asString().contains("UNLOGGED");
  }

  @Test
  void an_unlogged_table_is_admitted_with_a_warning() {
    exec(
        app(),
        "CREATE UNLOGGED TABLE app.n_unlogged (id bigint, tenant varchar(64),"
            + " subject varchar(64), email_idx varchar(64))");
    Verdict verdict = verdict(app, target("app.n_unlogged"));
    assertThat(verdict).isInstanceOf(Admitted.class);
    assertThat(((Admitted) verdict).warnings()).singleElement().asString().contains("UNLOGGED");
  }

  @Test
  void n35_an_inheritance_child_that_is_a_foreign_table_is_refused() {
    exec(
        su,
        "CREATE TABLE app2.n35 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "CREATE TABLE app2.n35_remote (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "CREATE FOREIGN TABLE app2.n35_child () INHERITS (app2.n35) SERVER loop"
            + " OPTIONS (schema_name 'app2', table_name 'n35_remote')",
        "GRANT SELECT, UPDATE ON app2.n35 TO " + APP);
    assertRefused(verdict(app, target("app2.n35")), "R-d", "foreign table");
  }

  // ---------------------------------------------------------------------------------- R-f

  @Test
  void n36_a_temporary_relation_is_refused_and_a_temporary_decoy_is_not_the_mapping()
      throws SQLException {
    plainTable("app.n36");
    try (Connection other = app.getConnection()) {
      exec(
          other,
          "CREATE TEMPORARY TABLE n36 (id bigint, tenant varchar(64),"
              + " subject varchar(64), email_idx varchar(64))");
      String tempSchema = text(other, "SELECT pg_catalog.pg_my_temp_schema()::regnamespace::text");
      // The decoy of the same name in the session's own pg_temp does not become the mapping.
      assertThat(MappingAdmission.verdict(other, target("app.n36"))).isInstanceOf(Admitted.class);
      // Mapped at a temporary relation, from another session: R-f.
      try (Connection c = app.getConnection()) {
        assertRefused(MappingAdmission.verdict(c, target(tempSchema + ".n36")), "R-f", "temporary");
      }
    }
  }

  // ---------------------------------------------------------------------------------- R-g

  @Test
  void n37_row_level_security_the_role_is_subject_to_is_refused() {
    exec(
        su,
        "CREATE TABLE app2.n37 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "INSERT INTO app2.n37 VALUES (1, 'T1', 's1', 'HMAC-RESIDUE')",
        "ALTER TABLE app2.n37 ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY hide ON app2.n37 USING (subject <> 's1')",
        "GRANT SELECT, UPDATE ON app2.n37 TO " + APP + ", shred_byp");
    assertThat(sameTextUpdate("app2.n37")).describedAs("A7: the policy hides the row").isZero();
    assertRefused(verdict(app, target("app2.n37")), "R-g", "row level security");

    // A8: FORCE ROW LEVEL SECURITY on the role's own table.
    plainTable("app.n37f");
    exec(
        app(),
        "ALTER TABLE app.n37f ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE app.n37f FORCE ROW LEVEL SECURITY",
        "CREATE POLICY hide ON app.n37f USING (subject <> 's1')");
    assertRefused(verdict(app, target("app.n37f")), "R-g", "forced");
  }

  /** S-4: bypassrls is read from the catalogue for the role running the check, never assumed. */
  @Test
  void n37_a_bypassrls_role_is_admitted_as_an_advisory_posture_read_from_pg_roles() {
    exec(
        su,
        "CREATE TABLE IF NOT EXISTS app2.n37b (id bigint, tenant varchar(64),"
            + " subject varchar(64), email_idx varchar(64))",
        "ALTER TABLE app2.n37b ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY hide ON app2.n37b USING (subject <> 's1')",
        "GRANT SELECT, UPDATE ON app2.n37b TO shred_byp");
    HikariDataSource byp = pool("shred_byp", "pw", 1, null);
    assertThat(text(byp, "SELECT rolbypassrls::text FROM pg_roles WHERE rolname = current_user"))
        .isEqualTo("true");
    Verdict verdict = verdict(byp, target("app2.n37b"));
    assertThat(verdict).isInstanceOf(Admitted.class);
    assertThat(((Admitted) verdict).warnings())
        .singleElement()
        .asString()
        .contains("[advisory posture]");
  }

  // ---------------------------------------------------------------------------------- R-h

  @Test
  void n38_select_without_update_is_refused_naming_the_grant() {
    exec(
        su,
        "CREATE TABLE app2.n38 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "GRANT SELECT ON app2.n38 TO " + APP);
    assertRefused(verdict(app, target("app2.n38")), "R-h", "SELECT but not UPDATE");
  }

  // ------------------------------------------------------------------------------ columns

  @Test
  void n39_a_mapped_column_the_table_does_not_have_is_refused_from_a_row_of_nulls()
      throws SQLException {
    plainTable("app.n39");
    try (Connection c = app.getConnection();
        PreparedStatement ps = c.prepareStatement(MappingAdmission.COLUMNS_SQL)) {
      ps.setArray(1, c.createArrayOf("text", new String[] {"tenant_id"}));
      ps.setLong(2, Long.parseLong(text(su, "SELECT 'app.n39'::regclass::oid::text")));
      try (ResultSet rs = ps.executeQuery()) {
        assertThat(rs.next()).describedAs("S-5: a row, not no row").isTrue();
        rs.getInt("attnum");
        assertThat(rs.wasNull()).isTrue();
      }
    }
    var target =
        new Target(
            Optional.of("Note"),
            TableRef.parse("app.n39"),
            List.of(new Column(ColumnRef.unquoted("tenant_id"), Use.COMPARED, "tenant column")));
    assertRefused(verdict(app, target), "C-a", "does not have");
  }

  @Test
  void n40_citext_is_refused_and_is_a_real_attack() {
    exec(
        app(),
        "CREATE TABLE app.n40 (id bigint, tenant public.citext, subject public.citext,"
            + " email_idx varchar(64))",
        "INSERT INTO app.n40 VALUES (1, 'T1', 'S1', 'HMAC-RESIDUE')");
    assertThat(sameTextUpdate("app.n40", "t1", "s1"))
        .describedAs("A2: 0 where the truth is 1")
        .isZero();
    assertThat(text(su, "SELECT count(*) FROM app.n40 WHERE tenant = 't1' AND subject = 's1'"))
        .describedAs("A2d: the application's own lookup")
        .isEqualTo("1");
    assertRefused(verdict(app, target("app.n40")), "C-b", "public.citext");
  }

  /**
   * C-b on its own: a domain over citext has no two-sided {@code =} of its own, so C-h cannot see
   * it, and its base type's implicit binary cast to {@code text} would admit it through C-c if C-c
   * were read first (mutation 21). The application's lookup still reaches {@code citext}'s operator
   * through the domain's base type.
   */
  @Test
  void n40_a_domain_over_citext_is_refused_by_c_b_alone() {
    exec(
        app(),
        "CREATE DOMAIN app.ci_dom AS public.citext",
        "CREATE TABLE app.n40d (id bigint, tenant app.ci_dom, subject app.ci_dom,"
            + " email_idx varchar(64))",
        "INSERT INTO app.n40d VALUES (1, 'T1', 'S1', 'HMAC-RESIDUE')");
    assertThat(sameTextUpdate("app.n40d", "t1", "s1")).isZero();
    assertThat(text(su, "SELECT count(*) FROM app.n40d WHERE tenant = 't1' AND subject = 's1'"))
        .isEqualTo("1");
    assertRefused(verdict(app, target("app.n40d")), "C-b", "citext");
  }

  @Test
  void n41_hstore_is_refused_at_the_check_rather_than_inside_an_erasure() {
    exec(
        app(),
        "CREATE TABLE app.n41 (id bigint, tenant public.hstore, subject varchar(64),"
            + " email_idx varchar(64))");
    assertRefused(verdict(app, target("app.n41")), "C-b", "hstore");
  }

  @Test
  void n41_a_domain_over_hstore_is_refused_by_c_b_alone() {
    exec(
        app(),
        "CREATE DOMAIN app.hs_dom AS public.hstore",
        "CREATE TABLE app.n41d (id bigint, tenant app.hs_dom, subject varchar(64),"
            + " email_idx varchar(64))");
    assertRefused(verdict(app, target("app.n41d")), "C-b", "hstore");
  }

  /** S-6: the clause that keeps the common case working is read from the catalogue's answer. */
  @Test
  void n42_varchar_is_admitted_through_its_implicit_binary_cast_read_by_namespace()
      throws SQLException {
    try (Connection c = app.getConnection();
        PreparedStatement ps = c.prepareStatement(MappingAdmission.TYPE_SQL)) {
      ps.setLong(1, 1043); // varchar
      try (ResultSet rs = ps.executeQuery()) {
        assertThat(rs.next()).isTrue();
        assertThat(rs.getString("own_eq_schema")).isNull();
        assertThat(List.of(rs.getString("binary_implicit_to").split(",")))
            .contains("pg_catalog:pg_catalog");
        assertThat(rs.getString("declared_shadow_eq_schema")).isNull();
      }
    }
    plainTable("app.n42");
    assertThat(verdict(app, target("app.n42"))).isInstanceOf(Admitted.class);
  }

  @Test
  void n43_a_domain_over_text_is_admitted_and_erases_and_an_enum_or_array_tenant_is_refused() {
    exec(
        app(),
        "CREATE DOMAIN app.plain_t AS text",
        "CREATE TYPE app.tenant_e AS ENUM ('T1', 'T2')",
        "CREATE TABLE app.n43d (id bigint, tenant app.plain_t, subject app.plain_t,"
            + " email_idx varchar(64))",
        "INSERT INTO app.n43d VALUES (1, 'T1', 's-app-n43d', 'HMAC-RESIDUE')",
        "CREATE TABLE app.n43e (id bigint, tenant app.tenant_e, subject varchar(64),"
            + " email_idx varchar(64))",
        "INSERT INTO app.n43e VALUES (1, 'T1', 's-app-n43e', 'HMAC-RESIDUE')",
        "CREATE TABLE app.n43a (id bigint, tenant text[], subject varchar(64),"
            + " email_idx varchar(64))",
        "CREATE TABLE app.n43c (id bigint, tenant char(8), subject char(32),"
            + " email_idx varchar(64))",
        "INSERT INTO app.n43c VALUES (1, 'T1', 's-app-n43c', 'HMAC-RESIDUE')");
    assertThat(verdict(app, target("app.n43d"))).isInstanceOf(Admitted.class);
    assertThat(erase(app, "app.n43d").blindIndexColumnsCleared()).isEqualTo(1);
    assertThat(verdict(app, target("app.n43c"))).isInstanceOf(Admitted.class);
    assertThat(erase(app, "app.n43c").blindIndexColumnsCleared()).isEqualTo(1);
    // C-i (security review C-19-1): an enum tenant is refused at the verdict and at the erasure.
    assertRefused(verdict(app, target("app.n43e")), "C-i", "app.tenant_e");
    assertThat(code(catchThrowable(() -> erase(app, "app.n43e"))))
        .isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertRefused(verdict(app, target("app.n43a")), "C-c", "text[]");
  }

  @Test
  void n44_a_non_deterministic_collation_is_refused_and_is_a_real_attack() {
    exec(
        app(),
        "CREATE COLLATION app.ci (provider = icu, locale = 'und-u-ks-level2',"
            + " deterministic = false)",
        "CREATE TABLE app.n44 (id bigint, tenant text COLLATE app.ci,"
            + " subject text COLLATE app.ci, email_idx varchar(64))",
        "INSERT INTO app.n44 VALUES (1, 'T1', 's1', 'HMAC-1'), (2, 't1', 'S1', 'HMAC-OTHER')",
        "CREATE DOMAIN app.ci_t AS text COLLATE app.ci",
        "CREATE TABLE app.n44d (id bigint, tenant app.ci_t, subject app.ci_t,"
            + " email_idx varchar(64))");
    assertThat(
            text(
                su,
                "SELECT count(*) FROM app.n44 WHERE tenant OPERATOR(pg_catalog.=) 'T1'"
                    + " AND subject OPERATOR(pg_catalog.=) 's1'"))
        .describedAs("A9: the qualified comparison matches another tenant's row too")
        .isEqualTo("2");
    assertRefused(verdict(app, target("app.n44")), "C-e", "not deterministic");
    assertRefused(verdict(app, target("app.n44d")), "C-e", "not deterministic");
  }

  /** S-5: a bigint id column has no collation, and NULL is admitted by its own branch. */
  @Test
  void n44b_a_non_collatable_identifier_is_admitted() throws SQLException {
    plainTable("app.n44b");
    try (Connection c = app.getConnection();
        PreparedStatement ps = c.prepareStatement(MappingAdmission.COLUMNS_SQL)) {
      ps.setArray(1, c.createArrayOf("text", new String[] {"id"}));
      ps.setLong(2, Long.parseLong(text(su, "SELECT 'app.n44b'::regclass::oid::text")));
      try (ResultSet rs = ps.executeQuery()) {
        assertThat(rs.next()).isTrue();
        rs.getBoolean("collisdeterministic");
        assertThat(rs.wasNull()).describedAs("NULL, not false").isTrue();
      }
    }
    assertThat(verdict(app, target("app.n44b"))).isInstanceOf(Admitted.class);
  }

  @Test
  void n45_a_not_null_or_generated_blind_index_column_is_refused_naming_the_column() {
    exec(
        app(),
        "CREATE TABLE app.n45n (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64) NOT NULL)",
        "CREATE TABLE app.n45g (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(200) GENERATED ALWAYS AS (tenant || subject) STORED)");
    assertRefused(verdict(app, target("app.n45n")), "C-f", "email_idx is NOT NULL");
    assertRefused(verdict(app, target("app.n45g")), "C-g", "generated column");
  }

  /** S-1, D6b: P-1 one type-definition away from citext. */
  @Test
  void n45b_an_application_defined_equality_on_the_declared_type_is_refused() {
    exec(
        app(),
        "CREATE DOMAIN app.tenant_t AS text",
        "CREATE FUNCTION app.ci_eq(app.tenant_t, app.tenant_t) RETURNS boolean LANGUAGE sql"
            + " IMMUTABLE AS $$ SELECT pg_catalog.lower($1::pg_catalog.text)"
            + " OPERATOR(pg_catalog.=) pg_catalog.lower($2::pg_catalog.text) $$",
        "CREATE OPERATOR app.= (LEFTARG = app.tenant_t, RIGHTARG = app.tenant_t,"
            + " PROCEDURE = app.ci_eq, COMMUTATOR = OPERATOR(app.=))",
        "CREATE TABLE app.n45b (id bigint, tenant app.tenant_t, subject app.tenant_t,"
            + " email_idx varchar(64))",
        "INSERT INTO app.n45b VALUES (1, 'T1', 'S1', 'HMAC-RESIDUE')");
    assertThat(sameTextUpdate("app.n45b", "t1", "s1")).isZero();
    assertThat(text(app, "SELECT count(*) FROM app.n45b WHERE tenant = 't1' AND subject = 's1'"))
        .describedAs("D6b: the application's own unqualified lookup")
        .isEqualTo("1");
    assertRefused(verdict(app, target("app.n45b")), "C-h", "app.=(tenant_t, tenant_t)");
  }

  /** D8: the one-sided spelling is not selected for an unknown literal and is not C-h. */
  @Test
  void n45b_a_one_sided_equality_does_not_trigger_c_h() {
    exec(
        app(),
        "CREATE DOMAIN app.tenant_one AS text",
        "CREATE FUNCTION app.ci_eq1(app.tenant_one, pg_catalog.text) RETURNS boolean"
            + " LANGUAGE sql IMMUTABLE AS $$ SELECT pg_catalog.lower($1::pg_catalog.text)"
            + " OPERATOR(pg_catalog.=) pg_catalog.lower($2) $$",
        "CREATE OPERATOR app.= (LEFTARG = app.tenant_one, RIGHTARG = pg_catalog.text,"
            + " PROCEDURE = app.ci_eq1)",
        "CREATE TABLE app.n45c (id bigint, tenant app.tenant_one, subject varchar(64),"
            + " email_idx varchar(64))");
    assertThat(verdict(app, target("app.n45c"))).isInstanceOf(Admitted.class);
  }

  // ------------------------------------------------------------- hostile path, hostile text

  /**
   * A24: the verdicts are identical on a path where every function and operator the statements use
   * has a lying shadow ahead of {@code pg_catalog}, and a relation decoy of the same name sits in
   * the first schema. Mutation 28 (leave the statements unqualified) is red here and only here.
   */
  @Test
  void n46_the_verdicts_are_the_same_on_a_hostile_path() {
    plainTable("app.n46");
    exec(
        app(),
        "CREATE VIEW app.n46_v AS SELECT * FROM app.n46",
        "CREATE TABLE decoy.n46 (id bigint)",
        "CREATE FUNCTION decoy.parse_ident(text) RETURNS text[] LANGUAGE sql"
            + " AS $$ SELECT ARRAY['decoy', 'n46'] $$",
        "CREATE FUNCTION decoy.has_table_privilege(oid, text) RETURNS boolean LANGUAGE sql"
            + " AS $$ SELECT true $$",
        "CREATE FUNCTION decoy.pg_has_role(oid, text) RETURNS boolean LANGUAGE sql"
            + " AS $$ SELECT true $$",
        "CREATE FUNCTION decoy.cardinality(anyarray) RETURNS integer LANGUAGE sql"
            + " AS $$ SELECT 2 $$",
        "CREATE VIEW decoy.pg_class AS SELECT * FROM pg_catalog.pg_class WHERE false",
        "CREATE FUNCTION decoy.f_name(pg_catalog.name, pg_catalog.name) RETURNS boolean"
            + " LANGUAGE sql AS $$ SELECT false $$",
        "CREATE OPERATOR decoy.= (LEFTARG = pg_catalog.name, RIGHTARG = pg_catalog.name,"
            + " PROCEDURE = decoy.f_name)",
        "CREATE FUNCTION decoy.f_text(pg_catalog.text, pg_catalog.text) RETURNS boolean"
            + " LANGUAGE sql AS $$ SELECT false $$",
        "CREATE OPERATOR decoy.= (LEFTARG = pg_catalog.text, RIGHTARG = pg_catalog.text,"
            + " PROCEDURE = decoy.f_text)",
        "CREATE FUNCTION decoy.f_oid(pg_catalog.oid, pg_catalog.oid) RETURNS boolean"
            + " LANGUAGE sql AS $$ SELECT false $$",
        "CREATE OPERATOR decoy.= (LEFTARG = pg_catalog.oid, RIGHTARG = pg_catalog.oid,"
            + " PROCEDURE = decoy.f_oid)",
        "CREATE FUNCTION decoy.f_char(pg_catalog.\"char\", pg_catalog.\"char\")"
            + " RETURNS boolean LANGUAGE sql AS $$ SELECT false $$",
        "CREATE OPERATOR decoy.= (LEFTARG = pg_catalog.\"char\","
            + " RIGHTARG = pg_catalog.\"char\", PROCEDURE = decoy.f_char)");
    HikariDataSource hostile =
        pool(APP, "pw", 1, "SET search_path = decoy, app, public, pg_catalog");
    for (String table : List.of("app.n46", "app.n46_v", "app.n46_absent")) {
      Verdict clean = verdict(app, target(table));
      Verdict onHostilePath = verdict(hostile, target(table));
      assertThat(onHostilePath).describedAs(table).isEqualTo(clean);
    }
    assertThat(verdict(hostile, target("app.n46"))).isInstanceOf(Admitted.class);
  }

  /** A21b: the strict one-argument parse_ident refuses what it cannot parse. */
  @Test
  void n47_hostile_table_text_is_refused_by_the_strict_parse() throws SQLException {
    for (String hostile :
        List.of("app.n47; DROP TABLE app.n47", "app.n47)", "", "\"app\".\"n47\" x")) {
      try (Connection c = app.getConnection();
          PreparedStatement ps = c.prepareStatement(MappingAdmission.RELATION_SQL)) {
        ps.setString(1, hostile);
        ps.setString(2, hostile);
        ps.setString(3, hostile);
        Throwable thrown = catchThrowable(ps::executeQuery);
        assertThat(thrown).describedAs(hostile).isInstanceOf(SQLException.class);
        assertThat(((SQLException) thrown).getSQLState()).describedAs(hostile).isEqualTo("22023");
      }
    }
    assertThat(MappingAdmission.RELATION_SQL + MappingAdmission.COLUMNS_SQL)
        .describedAs("the two-argument form is never built")
        .doesNotContain("strict")
        .doesNotContain("parse_ident(?,");
  }

  // ---------------------------------------------------------------- unverifiable, ordering

  /** The connection dies between the LOCK and the verdict: unverifiable, never a pass. */
  @Test
  void n48_a_catalogue_read_that_fails_is_unverifiable_and_nothing_is_recorded() {
    plainTable("app.n48");
    long before = Long.parseLong(text(su, "SELECT count(*) FROM public.shredding_erasure"));
    DataSource killing =
        hooked(
            app,
            MappingAdmission.RELATION_SQL,
            true,
            c ->
                exec(
                    su,
                    "SELECT pg_catalog.pg_terminate_backend("
                        + text(c, "SELECT pg_catalog.pg_backend_pid()::text")
                        + ")"));

    Throwable thrown = catchThrowable(() -> erase(killing, "app.n48"));

    assertThat(code(thrown)).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    assertThat(Long.parseLong(text(su, "SELECT count(*) FROM public.shredding_erasure")))
        .isEqualTo(before);
    assertThat(text(su, "SELECT email_idx FROM app.n48")).isEqualTo("HMAC-RESIDUE");
  }

  /**
   * D16, as an interleaving. Right after the verdict's first statement has read the relation, a
   * second session tries to swap the table for a hiding view of the same name. Under the step-1
   * lock that swap waits, and the erasure's own UPDATE hits the relation the verdict described.
   * With the verdict moved ahead of the lock (mutation 26) the swap succeeds and the erasure
   * reports COMPLETE over the residue now hidden behind the view.
   */
  @Test
  void n49_the_lock_is_taken_before_the_verdict_so_a_swap_waits() {
    plainTable("app.n49");
    var swap = new AtomicReference<String>();
    DataSource swapping =
        hooked(
            app,
            MappingAdmission.RELATION_SQL,
            false,
            c ->
                swap.set(
                    concurrently(
                        "ALTER TABLE app.n49 RENAME TO n49_old;"
                            + " CREATE VIEW app.n49 AS SELECT * FROM app.n49_old"
                            + " WHERE (subject <> 's-app-n49')")));
    erase(swapping, "app.n49");
    assertThat(swap.get()).describedAs("the swap waits on the erasure's lock").isEqualTo("55P03");
    assertThat(text(su, "SELECT count(*) FROM app.n49 WHERE email_idx IS NOT NULL")).isEqualTo("0");
  }

  /** N50: once per erasure per table, never per row. */
  @Test
  void n50_the_verdict_statements_run_once_per_erasure_per_table_whatever_the_row_count() {
    plainTable("app.n50");
    exec(
        su,
        "INSERT INTO app.n50 SELECT g, 'T1', 's-app-n50', 'HMAC'"
            + " FROM pg_catalog.generate_series(2, 6) g");
    var executions = new Counter();
    erase(counting(app, executions), "app.n50");
    assertThat(executions.of(MappingAdmission.RELATION_SQL)).isEqualTo(1);
    assertThat(executions.of(MappingAdmission.COLUMNS_SQL)).isEqualTo(1);
    assertThat(executions.of(MappingAdmission.CHILDREN_SQL)).isZero();
    assertThat(executions.of(MappingAdmission.TYPE_SQL))
        .describedAs("varchar for tenant and subject and the index, once")
        .isEqualTo(1);
  }

  // ---------------------------------------------------------------------------- helpers

  private static List<Column> cols() {
    return List.of(
        new Column(ColumnRef.unquoted("tenant"), Use.COMPARED, "tenant column"),
        new Column(ColumnRef.unquoted("subject"), Use.COMPARED, "subject column"),
        new Column(ColumnRef.unquoted("id"), Use.COMPARED, "identifier column"),
        new Column(ColumnRef.unquoted("email_idx"), Use.ASSIGNED, "blind-index column"));
  }

  private static Target target(String table) {
    return new Target(Optional.of("Note"), TableRef.parse(table), cols());
  }

  private static Verdict verdict(DataSource ds, Target target) {
    try (Connection c = ds.getConnection()) {
      return MappingAdmission.verdict(c, target);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void assertRefused(Verdict verdict, String rule, String fragment) {
    assertThat(verdict).isInstanceOf(Refused.class);
    assertThat(((Refused) verdict).rule()).isEqualTo(rule);
    assertThat(((Refused) verdict).message()).contains(fragment);
  }

  private static void plainTable(String table) {
    exec(
        app(),
        "CREATE TABLE "
            + table
            + " (id bigint, tenant varchar(64), subject varchar(64), email_idx varchar(64))",
        "INSERT INTO " + table + " VALUES (1, 'T1', '" + subject(table) + "', 'HMAC-RESIDUE')");
  }

  /**
   * Each erased table has its own subject, so one test's tombstone never short-circuits another.
   */
  private static String subject(String table) {
    return "s-" + table.replace('.', '-');
  }

  /** The erasure's own UPDATE, as the module renders it, run by the runtime role in a rollback. */
  private static int sameTextUpdate(String table) {
    return sameTextUpdate(table, "T1", "s1");
  }

  private static int sameTextUpdate(String table, String tenant, String subject) {
    TableRef ref = TableRef.parse(table);
    try (Connection c = app.getConnection()) {
      c.setAutoCommit(false);
      try (PreparedStatement ps =
          c.prepareStatement(
              "UPDATE "
                  + ref.sql()
                  + " SET email_idx = NULL WHERE (tenant OPERATOR(pg_catalog.=) ?)"
                  + " AND (subject OPERATOR(pg_catalog.=) ?) AND email_idx IS NOT NULL")) {
        ps.setString(1, tenant);
        ps.setString(2, subject);
        return ps.executeUpdate();
      } finally {
        c.rollback();
        c.setAutoCommit(true);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static BlindIndexColumn column(String table) {
    return new BlindIndexColumn(
        TableRef.parse(table),
        ColumnRef.unquoted("email_idx"),
        ColumnRef.unquoted("subject"),
        ColumnRef.unquoted("tenant"),
        Optional.of("tenant"),
        Optional.of("subject"));
  }

  /** The framework's shape: bare operators, inside the window, on the erasure's connection. */
  private static BlindIndexResidual honestResidual() {
    return (c, col, tenant, subject) -> {
      try (PreparedStatement ps =
          c.prepareStatement(
              "SELECT count(*) FROM "
                  + col.table().sql()
                  + " WHERE "
                  + col.tenantColumn().sql()
                  + " = ? AND "
                  + col.subjectColumn().sql()
                  + " = ? AND "
                  + col.column().sql()
                  + " IS NOT NULL")) {
        ps.setString(1, tenant.value());
        ps.setString(2, subject.value());
        try (ResultSet rs = ps.executeQuery()) {
          return rs.next() ? rs.getLong(1) : 0L;
        }
      } catch (SQLException e) {
        throw new IllegalStateException(e.getMessage(), e);
      }
    };
  }

  /** Runs {@code during} while the erasure's transaction holds its locks, then reads honestly. */
  private static BlindIndexResidual whileHeld(Runnable during) {
    BlindIndexResidual honest = honestResidual();
    return (c, col, tenant, subject) -> {
      during.run();
      return honest.count(c, col, tenant, subject);
    };
  }

  private static JdbcErasureStore store(DataSource ds, String table, BlindIndexResidual residual) {
    return new JdbcErasureStore(
        ds, schema, ErasureChain.keyed(SECRET, "k1"), List.of(column(table)), residual);
  }

  private static ErasureStore.Outcome erase(DataSource ds, String table) {
    return eraseWith(store(ds, table, honestResidual()), table);
  }

  private static ErasureStore.Outcome erase(
      DataSource ds, String table, BlindIndexResidual residual) {
    return eraseWith(store(ds, table, residual), table);
  }

  private static ErasureStore.Outcome eraseWith(JdbcErasureStore store, String table) {
    SubjectId subject = SubjectId.of(subject(table));
    return store.erase(T1, subject, (destroyed, cleared) -> record(subject, destroyed, cleared));
  }

  private static ErasureRecord record(SubjectId subject, int destroyed, int cleared) {
    return ErasureRecord.of(
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
        Instant.now().plus(Duration.ofDays(30)));
  }

  /** A second session, one statement, a one-second lock timeout: its SQLState, or "ok". */
  private static String concurrently(String sql) {
    try (Connection c = su.getConnection();
        Statement st = c.createStatement()) {
      st.execute("SET lock_timeout = '1s'");
      st.execute(sql);
      return "ok";
    } catch (SQLException e) {
      return e.getSQLState();
    }
  }

  private static final class Counter {
    private final Map<String, AtomicInteger> counts = new ConcurrentHashMap<>();

    void hit(String sql) {
      counts.computeIfAbsent(sql, k -> new AtomicInteger()).incrementAndGet();
    }

    int of(String sql) {
      return counts.getOrDefault(sql, new AtomicInteger()).get();
    }
  }

  private static DataSource counting(DataSource ds, Counter counter) {
    return proxy(ds, (sql, connection, after) -> counter.hit(sql), null, false);
  }

  /** Runs {@code hook} on the connection when a statement with exactly {@code sql} executes. */
  private static DataSource hooked(
      DataSource ds, String sql, boolean before, Consumer<Connection> hook) {
    return proxy(
        ds,
        (text, connection, after) -> {
          if (text.equals(sql) && after != before) {
            hook.accept(connection);
          }
        },
        sql,
        true);
  }

  @FunctionalInterface
  private interface StatementHook {
    void run(String sql, Connection connection, boolean after);
  }

  private static DataSource proxy(
      DataSource ds, StatementHook hook, String onlySql, boolean beforeAndAfter) {
    return (DataSource)
        Proxy.newProxyInstance(
            DataSource.class.getClassLoader(),
            new Class<?>[] {DataSource.class},
            (p, m, a) -> {
              Object result = invoke(ds, m, a);
              if (!"getConnection".equals(m.getName())) {
                return result;
              }
              Connection real = (Connection) result;
              return Proxy.newProxyInstance(
                  Connection.class.getClassLoader(),
                  new Class<?>[] {Connection.class},
                  connectionHandler(real, hook, beforeAndAfter));
            });
  }

  private static InvocationHandler connectionHandler(
      Connection real, StatementHook hook, boolean beforeAndAfter) {
    return (p, m, a) -> {
      Object result = invoke(real, m, a);
      if (!"prepareStatement".equals(m.getName()) || a == null || a.length != 1) {
        return result;
      }
      String sql = (String) a[0];
      PreparedStatement ps = (PreparedStatement) result;
      return Proxy.newProxyInstance(
          PreparedStatement.class.getClassLoader(),
          new Class<?>[] {PreparedStatement.class},
          (pp, pm, pa) -> {
            boolean executes = pm.getName().startsWith("execute") && pa == null;
            if (executes && beforeAndAfter) {
              hook.run(sql, real, false);
            }
            Object r = invoke(ps, pm, pa);
            if (executes) {
              hook.run(sql, real, true);
            }
            return r;
          });
    };
  }

  private static Object invoke(Object target, java.lang.reflect.Method m, Object[] a)
      throws Throwable {
    try {
      return m.invoke(target, a);
    } catch (InvocationTargetException e) {
      throw e.getCause();
    }
  }

  private static String code(Throwable thrown) {
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    return ((ShreddingException) thrown).code();
  }

  private static HikariDataSource app() {
    return app;
  }

  private static HikariDataSource pool(String user, String password, int size, String init) {
    return poolAt(POSTGRES.getJdbcUrl(), user, size, init, password);
  }

  private static HikariDataSource poolAt(String url, String user, int size, String init) {
    return poolAt(url, user, size, init, "pw");
  }

  private static HikariDataSource poolAt(
      String url, String user, int size, String init, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(url);
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(size);
    if (init != null) {
      config.setConnectionInitSql(init);
    }
    var ds = new HikariDataSource(config);
    pools.add(ds);
    return ds;
  }

  private static void exec(DataSource ds, String... sql) {
    try (Connection c = ds.getConnection()) {
      exec(c, sql);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void exec(Connection c, String... sql) {
    try (Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }

  private static String text(DataSource ds, String sql) {
    try (Connection c = ds.getConnection()) {
      return text(c, sql);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String text(Connection c, String sql) {
    try (Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getString(1) : null;
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }
}
