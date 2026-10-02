package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review probes, PR 13, <b>fifth pass</b>: the name classes the design review measured on
 * revision 1 of the name-resolution page and that {@link CipherProbeNoDdlPr13dTest} does not cover.
 * Design {@code name-resolution-design.md} revision 2.1, findings N-1 (the exact-type shadow), M5
 * (collation and the keyword operators) and M6 / E3a / C-16d (the precedence trap).
 *
 * <p>Three independent classes, all of them the same shape as C-13-13 to C-13-15 and none of them
 * reached by the {@code search_path} pin:
 *
 * <ol>
 *   <li><b>N-1, an exact-type shadow.</b> PostgreSQL ships no {@code =} with {@code varchar} on
 *       either side; {@code varchar = varchar} reaches {@code texteq} by coercion. An {@code
 *       app.=(varchar, varchar)} is an exact match, is selected at step 2 of operator resolution
 *       whatever the path order, and {@code tenant} and {@code subject} are {@code varchar(255)} in
 *       every one of this module's own tables. So the module's <em>own</em> statements - not only
 *       the framework-rendered one - answer whatever the role's operator says.
 *   <li><b>The keyword operators.</b> {@code IS DISTINCT FROM} is {@code =} and {@code LIKE} is
 *       {@code ~~}: both resolve along {@code search_path} and neither can be written {@code
 *       OPERATOR(pg_catalog.…)}. A statement that needs one is a statement that cannot be made
 *       sound by qualification, so the rule is that this module builds none, and the bundled script
 *       is where the rule is broken today.
 *   <li><b>The precedence trap.</b> Qualifying the guard bodies' operators is the fix for C-13-14,
 *       and every {@code OPERATOR(…)}-qualified operator takes one generic precedence, so {@code a
 *       OPERATOR(pg_catalog.<>) b OPERATOR(pg_catalog.+) 1} parses as {@code (a <> b) + 1} and
 *       fails at run time <em>inside the trigger</em>, on the honest write. The parentheses are
 *       part of the control, not of its formatting, and the only thing that holds them there is a
 *       test.
 * </ol>
 *
 * <p>Fixture: the hardened two-role posture of SECURITY-NOTES "Database roles", the same as {@link
 * CipherProbeNoDdlPr13dTest}. The runtime role is {@code NOSUPERUSER NOCREATEDB NOCREATEROLE},
 * holds no {@code CREATE} and no {@code TEMPORARY} on the database and none on {@code public}, and
 * owns one schema of its own in which it defines the shadow - which is not a privilege the hardened
 * deployment can revoke.
 *
 * <p>All five are RED on {@code 1e562d0}.
 */
@Testcontainers
class CipherProbeNamePr13eTest {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String APP = "probe_name_app";
  private static final String OWNER = "probe_name_owner";

  /** The role's own schema, and the only thing it needs to own to run any of these. */
  private static final String OWN = "app";

  private static final byte[] SECRET =
      "probe-chain-secret-0123456789abcdef".getBytes(StandardCharsets.UTF_8);
  private static final TenantId TENANT = TenantId.of("t1");

  private static HikariDataSource superuserDs;
  private final List<HikariDataSource> perTest = new ArrayList<>();

  @BeforeAll
  static void start() {
    POSTGRES.start();
    superuserDs = pool(POSTGRES.getUsername(), POSTGRES.getPassword());
    su(
        "DROP ROLE IF EXISTS " + APP,
        "DROP ROLE IF EXISTS " + OWNER,
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw' NOSUPERUSER");
  }

  @AfterAll
  static void stop() {
    close(superuserDs);
    POSTGRES.stop();
  }

  @BeforeEach
  void freshDatabase() {
    su(
        "ALTER ROLE " + APP + " RESET search_path",
        "ALTER ROLE " + OWNER + " RESET search_path",
        "DROP SCHEMA IF EXISTS " + OWN + " CASCADE",
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA " + OWN + " AUTHORIZATION " + APP,
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM PUBLIC",
        "REVOKE ALL ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP,
        "GRANT CONNECT ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
  }

  @AfterEach
  void closePerTestPools() {
    perTest.forEach(CipherProbeNamePr13eTest::close);
    perTest.clear();
  }

  // ------------------------------------------------------- N-1: the exact-type shadow

  /**
   * The erasure's own statements, on the role's own path, with {@code app.=(varchar,varchar) ->
   * false} installed. {@code shredding_data_key.tenant} and {@code .subject} are {@code
   * varchar(255)}, so {@code lockKeyRows}, {@code alreadyErased} and {@code deleteKeyRows} all
   * compare {@code varchar} to a bound {@code varchar}: an exact-type shadow, which no {@code
   * search_path} order can demote.
   *
   * <p>What it costs: the key row survives, the erasure log records the erasure anyway, and {@code
   * keysDestroyed} is 0 - a proof of erasure for a subject whose key is still there, which is the
   * one thing {@code ErasureStore}'s contract says must be impossible.
   */
  @Test
  void probe_a_shadowed_varchar_equality_cannot_make_an_erasure_record_a_key_it_left_alive() {
    ownerInstallsInPublicAndGrantsTheBlock();
    DataSource clean = freshPool(APP);
    var schema = JdbcSupport.verifySchema(clean, false).schema();
    SubjectId subject = SubjectId.of("s1");
    keyProvider(clean, schema).currentForWrite(TENANT, subject);
    assertThat(keyRows()).describedAs("the subject has a live data key").isEqualTo(1);

    shadowVarcharEquality(clean, "false");
    DataSource shadowed = hostilePath();

    var outcome =
        erasureStore(shadowed, schema)
            .erase(TENANT, subject, (destroyed, cleared) -> record(subject, destroyed, cleared));

    assertThat(keyRows())
        .describedAs(
            "the erasure returned %s; the data key it is the proof of destruction for is still in"
                + " the table",
            outcome)
        .isZero();
    assertThat(outcome.keysDestroyed()).isEqualTo(1);
  }

  /**
   * The read half of the same shadow, on the smallest entry point there is. {@code forRead}
   * returning {@code empty()} has exactly one documented meaning - the key row is gone, the subject
   * was erased - so a shadow that hides a live row makes every shredded field of a live subject
   * read as erased, and makes {@code recordEncryptions} refuse with {@code SHRED-ERASED}.
   */
  @Test
  void probe_a_shadowed_varchar_equality_cannot_make_a_live_key_read_as_destroyed() {
    ownerInstallsInPublicAndGrantsTheBlock();
    DataSource clean = freshPool(APP);
    var schema = JdbcSupport.verifySchema(clean, false).schema();
    SubjectId subject = SubjectId.of("s1");
    keyProvider(clean, schema).currentForWrite(TENANT, subject);

    shadowVarcharEquality(clean, "false");
    var keys = keyProvider(hostilePath(), schema);

    assertThat(keys.forRead(TENANT, subject, 1))
        .describedAs("an absent key row is read as a destroyed key, and this one is present")
        .isPresent();
    assertThatCode(() -> keys.recordEncryptions(TENANT, subject, 1, 1))
        .describedAs("the encryption counter of a live key")
        .doesNotThrowAnyException();
  }

  // --------------------------------------------------- M5: the keyword operators

  /**
   * {@code IS DISTINCT FROM} and {@code LIKE} are operator names that cannot be qualified. Both are
   * measured here against the role's own shadow, and the rule that follows is that this module
   * builds no statement containing one: the bundled script's {@code
   * shredding_erasure_anchor_monotonic} body is the one place it does, and {@code keyed} is {@code
   * NOT NULL} on both {@code OLD} and {@code NEW}, so {@code <>} is equivalent there and can be
   * qualified.
   */
  @Test
  void probe_no_statement_this_module_builds_contains_a_keyword_operator() {
    su("GRANT USAGE, CREATE ON SCHEMA public TO " + APP);
    DataSource app = freshPool(APP);
    exec(
        app,
        "CREATE FUNCTION "
            + OWN
            + ".vtrue(pg_catalog.varchar, pg_catalog.varchar)"
            + " RETURNS boolean AS $$ SELECT true $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".= (LEFTARG = pg_catalog.varchar,"
            + " RIGHTARG = pg_catalog.varchar, FUNCTION = "
            + OWN
            + ".vtrue)",
        "CREATE FUNCTION "
            + OWN
            + ".vfalse(pg_catalog.varchar, pg_catalog.varchar)"
            + " RETURNS boolean AS $$ SELECT false $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".~~ (LEFTARG = pg_catalog.varchar,"
            + " RIGHTARG = pg_catalog.varchar, FUNCTION = "
            + OWN
            + ".vfalse)");
    su("ALTER ROLE " + APP + " SET search_path = public, " + OWN + ", pg_catalog");
    DataSource shadowed = freshPool(APP);

    assertThat(
            bool(
                shadowed,
                "SELECT ('a'::pg_catalog.varchar) IS DISTINCT FROM ('b'::pg_catalog.varchar)"))
        .describedAs("IS DISTINCT FROM resolves the type's =, and the role owns one")
        .isFalse();
    assertThat(bool(shadowed, "SELECT ('abc'::pg_catalog.varchar) LIKE ('a%'::pg_catalog.varchar)"))
        .describedAs("LIKE is ~~, and the role owns one")
        .isFalse();

    String script = JdbcSupport.schemaScript();
    assertThat(script)
        .describedAs("a keyword operator in a shipped statement cannot be qualified")
        .doesNotContain("IS DISTINCT FROM")
        .doesNotContain(" LIKE ")
        .doesNotContain(" ILIKE ")
        .doesNotContain("COLLATE");
  }

  // ------------------------------------- M6 / E3a / C-16d: the precedence trap

  /**
   * The qualified form of the guard body, and the trap that comes with it. Every {@code
   * OPERATOR(…)} operator takes one generic precedence, measured here on the review's own
   * expression: {@code 'ab' OPERATOR(pg_catalog.=) 'a' OPERATOR(pg_catalog.||) 'b'} is not a
   * boolean at all, it is the text {@code falseb}. Inside the trigger body the same re-association
   * raises {@code operator does not exist: boolean pg_catalog.+ integer} on the <b>honest</b>
   * append, which is why the parentheses are asserted here and the three real appends after them
   * are the regression guard.
   */
  @Test
  void probe_every_operator_in_a_guard_body_is_qualified_and_parenthesised() {
    ownerInstallsInPublicAndGrantsTheBlock();

    assertThat(
            text(
                superuserDs,
                "SELECT ('ab' OPERATOR(pg_catalog.=) 'a' OPERATOR(pg_catalog.||) 'b')"
                    + "::pg_catalog.text"))
        .describedAs("two qualified operators with no parentheses re-associate silently")
        .isEqualTo("falseb");

    String body = guardBody("shredding_erasure_anchor_monotonic");
    assertThat(body)
        .describedAs("every operator in the guard body is qualified (C-13-14)")
        .contains("OPERATOR(pg_catalog.<>)")
        .contains("OPERATOR(pg_catalog.+)")
        .contains("OPERATOR(pg_catalog.=)");
    assertThat(body)
        .describedAs("and every binary application of one is parenthesised (E3a, C-16d)")
        .contains("(OLD.row_count OPERATOR(pg_catalog.+) 1)");
    assertThat(bareOperatorTokens(body))
        .describedAs("no operator in the body is left for the writing session to resolve")
        .isEmpty();

    DataSource app = freshPool(APP);
    var store = erasureStore(app, JdbcSupport.verifySchema(app, false).schema());
    for (int i = 1; i <= 3; i++) {
      int n = i;
      store.append(record(SubjectId.of("s" + n), 1, 0));
      assertThat(anchorRowCount())
          .describedAs("the honest append must still advance the anchor by exactly one")
          .isEqualTo((long) n);
    }
  }

  /**
   * The {@code proconfig} half of C-13-14, and the leg that makes it verifiable. The three guards
   * are created with {@code SET search_path = pg_catalog, pg_temp}, which is what keeps their
   * bodies out of the writing session's path; and {@code SchemaVerification} must <b>require</b>
   * exactly that value rather than requiring {@code proconfig IS NULL}, because {@code CREATE OR
   * REPLACE FUNCTION} with no {@code SET} clause clears the column with no error and an old copy of
   * the script is therefore a silent disarm.
   */
  @Test
  void probe_the_guards_carry_the_pinned_proconfig_and_verification_requires_it() {
    ownerInstallsInPublicAndGrantsTheBlock();
    for (String guard :
        List.of(
            "shredding_erasure_append_only",
            "shredding_erasure_anchor_monotonic",
            "shredding_erasure_anchor_append_only")) {
      assertThat(proconfig(guard))
          .describedAs("guard %s resolves its body's names in pg_catalog only", guard)
          .isEqualTo("{\"search_path=pg_catalog, pg_temp\"}");
    }

    DataSource app = freshPool(APP);
    assertThatCode(() -> JdbcSupport.verifySchema(app, false))
        .describedAs("the honest hardened posture, which must verify")
        .doesNotThrowAnyException();

    HikariDataSource owner = freshPool(OWNER);
    exec(owner, "ALTER FUNCTION public.shredding_erasure_anchor_monotonic() RESET search_path");

    assertThatThrownBy(() -> JdbcSupport.verifySchema(app, false))
        .describedAs("a cleared proconfig is a disarmed guard, not a clean one")
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("shredding_erasure_anchor_monotonic")
        .hasMessageContaining("proconfig")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
  }

  // ------------------------------------------------------------------ fixture

  /** The hardened posture of SECURITY-NOTES "Database roles", applied to {@code public}. */
  private void ownerInstallsInPublicAndGrantsTheBlock() {
    HikariDataSource owner = freshPool(OWNER);
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
  }

  /**
   * The shadow, and the fixture note of design §6 that cost an experiment: a shadow declared {@code
   * LEFTARG = varchar} while the role also owns a domain of that name is created on the domain and
   * shadows nothing, so every argument type here is spelled {@code pg_catalog.varchar}.
   */
  private void shadowVarcharEquality(DataSource own, String answer) {
    exec(
        own,
        "CREATE FUNCTION "
            + OWN
            + ".vc(pg_catalog.varchar, pg_catalog.varchar)"
            + " RETURNS boolean AS $$ SELECT "
            + answer
            + " $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".= (LEFTARG = pg_catalog.varchar,"
            + " RIGHTARG = pg_catalog.varchar, FUNCTION = "
            + OWN
            + ".vc)");
  }

  private DataSource hostilePath() {
    su("ALTER ROLE " + APP + " SET search_path = public, " + OWN + ", pg_catalog");
    return freshPool(APP);
  }

  private JdbcKeyProvider keyProvider(DataSource ds, VerifiedSchema schema) {
    return new JdbcKeyProvider(
        ds, schema, MasterKey.fromBytes(new byte[32]), RandomSource.secure(), Clock.systemUTC());
  }

  private JdbcErasureStore erasureStore(DataSource ds, VerifiedSchema schema) {
    return new JdbcErasureStore(
        ds,
        schema,
        ErasureChain.keyed(SECRET, "k1"),
        List.of(),
        (connection, column, tenant, subject) -> 0L);
  }

  private ErasureRecord record(SubjectId subject, int destroyed, int cleared) {
    return ErasureRecord.of(
        Instant.now(),
        TENANT,
        new Pseudonymiser(SECRET).pseudonym(TENANT, subject),
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

  /**
   * Every operator character run in the body that is not part of an {@code OPERATOR(pg_catalog.…)}
   * spelling, of the plpgsql assignment {@code :=}, or inside a string literal. Deliberately crude:
   * the gate of design §3.5 is the real lexer, and this is the one assertion the guard body needs
   * before that gate exists.
   */
  private static List<String> bareOperatorTokens(String body) {
    String stripped =
        body.replace("OPERATOR(pg_catalog.<>)", " ")
            .replace("OPERATOR(pg_catalog.+)", " ")
            .replace("OPERATOR(pg_catalog.=)", " ")
            .replaceAll("'[^']*'", " ")
            .replaceAll("--[^\\n]*", " ")
            .replace(":=", " ");
    var found = new ArrayList<String>();
    var run = new StringBuilder();
    for (char ch : stripped.toCharArray()) {
      if ("+-*/<>=~!@#%^&|`?".indexOf(ch) >= 0) {
        run.append(ch);
      } else if (run.length() > 0) {
        found.add(run.toString());
        run.setLength(0);
      }
    }
    if (run.length() > 0) {
      found.add(run.toString());
    }
    return found;
  }

  private static String guardBody(String name) {
    return text(
        superuserDs,
        "SELECT p.prosrc FROM pg_catalog.pg_proc p"
            + " JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace"
            + " WHERE n.nspname = 'public' AND p.proname = '"
            + name
            + "'");
  }

  private static String proconfig(String name) {
    return text(
        superuserDs,
        "SELECT p.proconfig::text FROM pg_catalog.pg_proc p"
            + " JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace"
            + " WHERE n.nspname = 'public' AND p.proname = '"
            + name
            + "'");
  }

  private static long anchorRowCount() {
    return Long.parseLong(
        text(superuserDs, "SELECT row_count::text FROM public.shredding_erasure_anchor"));
  }

  private static int keyRows() {
    return Integer.parseInt(
        text(superuserDs, "SELECT count(*)::text FROM public.shredding_data_key"));
  }

  private static boolean bool(DataSource ds, String sql) {
    return Boolean.parseBoolean(
        text(ds, "SELECT (" + sql.substring("SELECT ".length()) + ")::text"));
  }

  private static String text(DataSource ds, String sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement();
        var rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getString(1) : null;
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * A new pool every time, never a soft eviction: a role-level {@code search_path} is resolved when
   * the session starts, so a pooled connection opened before {@code ALTER ROLE} still answers the
   * old value.
   */
  private HikariDataSource freshPool(String user) {
    HikariDataSource ds = pool(user, "pw");
    perTest.add(ds);
    return ds;
  }

  private static HikariDataSource pool(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(3);
    return new HikariDataSource(config);
  }

  private static void close(HikariDataSource ds) {
    if (ds != null) {
      ds.close();
    }
  }

  private static void su(String... sql) {
    exec(superuserDs, sql);
  }

  private static void exec(DataSource ds, String... sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }
}
