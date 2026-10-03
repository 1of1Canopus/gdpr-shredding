package com.housedevinci.shredding.namegate;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The name gate, section 3.5 of the name-resolution design (test N22).
 *
 * <p>It is a drift gate: it decides that no name in any statement this module builds is left for
 * the server to resolve by {@code search_path}, and it decides nothing else. The qualification
 * itself is measured behaviourally by {@code CipherProbeNamePr13eTest} and {@code
 * CipherProbeNamePr13eStarterTest} against a hostile path; what this gate adds is the next
 * statement, the one nobody has written yet.
 *
 * <p>Two sites the second security review ruled on explicitly, because an unresolvable statement
 * argument must be a refusal and not a skip:
 *
 * <ul>
 *   <li>{@code JdbcSupport.schemaScript()} is accepted as a <b>file read</b>, on the condition that
 *       the gate asserts the file it lexed is the resource {@code JdbcSupport.SCHEMA_RESOURCE}
 *       names, byte for byte ({@link #the_script_the_gate_lexes_is_the_resource_the_module_ships}).
 *       Without that assertion the gate could pass by lexing a file the module does not ship.
 *   <li>{@code SchemaVerification}'s shared relation reader takes a {@link
 *       java.sql.PreparedStatement} and its two statements are {@code private static final String}
 *       constants, one per call site, rather than a parameter the gate would have to hop through. A
 *       one-hop resolver is more untested code inside a control than two constants are in the
 *       source, and a hop that exists grows to two.
 * </ul>
 *
 * <p>What the gate deliberately does not check, stated so the next reader does not assume it does:
 * a type position is {@code ::} and {@code CAST(... AS ...)} only. A column type in a {@code CREATE
 * TABLE} is a type position too, and the script's three non-keyword column types are qualified by
 * hand (section 5) and held by {@code SchemaExpectations.COLUMNS}, which compares what the server
 * actually stored.
 */
class NameQualificationGateTest {

  /** The resource path {@code JdbcSupport.SCHEMA_RESOURCE} names. Compared, not assumed. */
  private static final String SCHEMA_RESOURCE = "/com/housedevinci/shredding/schema-postgresql.sql";

  private static Path coreMain() {
    return Path.of("src/main/java/com/housedevinci/shredding/adapter/jdbc");
  }

  private static Path starterMain() {
    return Path.of(
        "../gdpr-shredding-spring-boot-starter/src/main/java/com/housedevinci/shredding/autoconfigure");
  }

  private static Path scriptOnDisk() {
    return Path.of("src/main/resources" + SCHEMA_RESOURCE);
  }

  /**
   * The two starter files named below, and nothing else under {@link #starterMain}, builds a
   * statement on the application's own connection (C-A-13's closure assertion checks the rest).
   */
  private static final List<String> STARTER_FILES =
      List.of("WriteVerification.java", "ShreddingEventListener.java");

  /**
   * Every Java file the gate reads: the whole JDBC adapter package, plus the two starter files that
   * build statements on the application's own connection (P2b, section 3.4). The list is a
   * directory walk and two named files rather than a list of statements, so a new adapter file is
   * covered the day it is added, and {@link #assertStarterListIsClosed} covers a new starter file.
   */
  private static List<Path> sources() {
    try (Stream<Path> core = Files.walk(coreMain())) {
      var out =
          new ArrayList<Path>(core.filter(p -> p.toString().endsWith(".java")).sorted().toList());
      for (String name : STARTER_FILES) {
        out.add(starterMain().resolve(name));
      }
      for (Path p : out) {
        assertThat(p).describedAs("the gate's source list must not rot").exists();
      }
      assertStarterListIsClosed();
      return out;
    } catch (IOException e) {
      throw new IllegalStateException("the gate could not walk " + coreMain().toAbsolutePath(), e);
    }
  }

  /**
   * The closure C-A-13 asks for: {@link #STARTER_FILES} is two hard-coded names with nothing that
   * fails if a third starter file starts building a statement on the connection. Walks every other
   * {@code .java} file under {@link #starterMain} and fails if it calls a method in {@link
   * SqlSites#STATEMENT_CALLS} - the file would then build a statement the gate never reads.
   */
  private static void assertStarterListIsClosed() throws IOException {
    try (Stream<Path> walk = Files.walk(starterMain())) {
      for (Path p : walk.filter(path -> path.toString().endsWith(".java")).toList()) {
        String fileName = p.getFileName().toString();
        if (STARTER_FILES.contains(fileName)) {
          continue;
        }
        String text = SqlSites.read(p);
        for (String call : SqlSites.STATEMENT_CALLS) {
          assertThat(text.contains(call + "("))
              .describedAs(
                  fileName
                      + " calls "
                      + call
                      + "( and is not in NameQualificationGateTest.STARTER_FILES (C-A-13): add it"
                      + " to the gate's source list or this closure assertion is false")
              .isFalse();
        }
      }
    }
  }

  @Test
  void every_statement_this_module_builds_in_java_resolves_no_name() {
    var scan = SqlSites.scan(sources());

    assertThat(scan.unresolved())
        .describedAs(
            "a statement call whose argument the gate cannot resolve is a refusal, not a skip:"
                + " unverifiable is not clean. Either build the statement from literals, or name"
                + " the site in SqlSites.FILE_READ_CALLS with an identity assertion beside it.")
        .isEmpty();

    assertThat(scan.sites())
        .describedAs("the gate must be reading the module's statements, not an empty list")
        .hasSizeGreaterThan(30);

    var refusals = new ArrayList<String>();
    for (var site : scan.sites()) {
      for (String variant : site.variants()) {
        for (var refusal : SqlNameLexer.refusals(variant)) {
          refusals.add(site.file() + ":" + site.line() + " " + refusal);
        }
      }
    }
    assertThat(refusals)
        .describedAs(
            "every operator, function, aggregate, type, cast and relation name in a statement this"
                + " module builds must name its schema (design section 3.1). A column reference"
                + " resolves against the FROM list and is not a name; a bind parameter is never a"
                + " name. There is no open refusal, no allowlist and no relaxation: a keyword"
                + " operator is refused wherever it appears (finding C-18-6).")
        .isEmpty();
  }

  /**
   * The invariant the window's javadoc states and this is what checks it (design section 4.3, M9,
   * as tightened by finding C-18-6): <b>no statement this module writes sits inside a window</b>.
   * The window exists for text this module cannot qualify, which is the framework-rendered
   * read-back and nothing else; a statement of the module's own in there would be a control that no
   * test can show working, and would put module-written text under a weaker reading of the gate.
   * Everything else that makes the window acceptable also rests on its width: the erasure's own
   * {@code UPDATE} runs outside it on the arrived path, the application's trigger still fires
   * (T17), and no exception can be swallowed with the path still replaced.
   *
   * <p>The framework-rendered read-back's statement is issued by Hibernate, not by a {@code
   * prepareStatement} in this module's source, so a text gate cannot see it at all. That window's
   * one-statement property rests on {@code StatelessSession} being unable to flush, on {@code
   * HibernateBlindIndexResidual}'s contract, and on the behavioural probes - not on this assertion.
   */
  @Test
  void every_window_holds_zero_statements_of_this_modules_own() {
    var scan = SqlSites.scan(sources());

    assertThat(scan.windows())
        .describedAs("the framework read-back's window must be found at all")
        .isNotEmpty();
    assertThat(scan.windows().stream().filter(w -> w.statements() > 0).toList())
        .describedAs(
            "a statement this module wrote, inside a window: the window is for text the module"
                + " cannot qualify, and the gate holds this module's own text to the full rule")
        .isEmpty();
  }

  /**
   * The negative of the rule above, on a synthetic source rather than on this module's own: the
   * gate has to be able to see a module-written statement in a window, or the assertion above is
   * decoration.
   */
  @Test
  void a_window_holding_two_statements_is_seen_by_the_gate(@TempDir Path dir) throws IOException {
    Path two = dir.resolve("TwoStatements.java");
    Files.writeString(
        two,
        """
        class TwoStatements {
          void run() {
            JdbcSupport.inOneStatementWindow(
                c,
                () -> {
                  c.prepareStatement("SELECT pg_catalog.count(*) FROM pg_catalog.pg_class");
                  c.prepareStatement("SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc");
                  return 1L;
                });
          }
        }
        """);

    var scan = SqlSites.scan(List.of(two));

    assertThat(scan.windows()).hasSize(1);
    assertThat(scan.windows().get(0).statements()).isEqualTo(2);
    assertThat(scan.sites()).hasSize(2);
  }

  /**
   * There is no admission: a keyword operator ({@code IS DISTINCT FROM}, {@code LIKE}, ...) has no
   * {@code OPERATOR(pg_catalog....)} spelling, and since finding C-18-6 no statement this module
   * writes is run inside the window that used to excuse it. It is refused everywhere.
   */
  @Test
  void a_keyword_operator_is_refused_everywhere() {
    assertThat(rules("SELECT pg_catalog.count(*) FROM s.t WHERE a IS DISTINCT FROM ?"))
        .containsExactly("keyword operator");
    assertThat(rules("SELECT 1 FROM s.t WHERE a LIKE ?")).containsExactly("keyword operator");
    assertThat(rules("SELECT 1 FROM s.t WHERE (a OPERATOR(pg_catalog.=) ? COLLATE ci)"))
        .contains("keyword operator");
  }

  /**
   * The names in this module that qualification cannot reach: <b>none, as of this PR</b>.
   *
   * <p>Until this PR the list held nine entries, all the same name - the user table a blind-index
   * statement addresses, rendered by {@code TableRef.sql()}. {@code TableRef.schema} is an {@code
   * Optional}, and a {@code @Shredded} entity whose mapping named no schema - no
   * {@code @Table(schema)}, no {@code hibernate.default_schema} - rendered {@code "customer"},
   * which the server resolved along the writing session's {@code search_path}. The review measured
   * it: as the runtime role, with {@code search_path = decoy, app, pg_catalog} and a {@code
   * decoy.customer} it owns, {@code SELECT email_cipher FROM "customer"} read the decoy.
   *
   * <p><b>The mechanism that closes them is design section 3.2, and it is in this PR.</b> {@code
   * ShreddedModel} now refuses at startup, with {@code SHRED-CONFIG-001}, any entity carrying
   * {@code @Shredded} or {@code @BlindIndex} whose table expression names no schema. A one-part
   * rendering is therefore unreachable for every {@code TableRef} these statements are built from,
   * {@code TableRef.sql} has joined {@code SqlSites.QUALIFYING_CALLS}, and the nine entries are
   * gone. Section 3.2 was put in this PR rather than the previous one because it is also what makes
   * section 4's one-statement window sound: the window must leave no role-writable schema on the
   * path, so the relation has to come from the mapping.
   *
   * <p>The list stays, empty, rather than being deleted with the carry: {@link
   * #the_nine_refusal_carry_expires_the_day_table_ref_sql_joins_qualifying_calls} reads it in both
   * directions, so an edit that took {@code sql} back out of {@code QUALIFYING_CALLS} without
   * re-stating what is then unqualified fails the gate.
   */
  private static final List<String> OPEN_REFUSALS = List.of();

  /**
   * C-A-14: {@link #OPEN_REFUSALS} and {@code TableRef.sql} being in {@link
   * SqlSites#QUALIFYING_CALLS} are one fact read two ways, and this is the assertion that keeps
   * them one. The nine entries the previous PR carried existed only because the mechanism of design
   * section 3.2 had not landed; this PR lands it, {@code sql} joins {@code QUALIFYING_CALLS}, and
   * the list is empty. It fails on either drift: a carry still listed after the mechanism landed
   * (the gate reporting an exposure it no longer has, and keeping the nine entries as a permanent
   * allowlist), or the mechanism taken back out with no carry re-stating what is then unqualified
   * (the gate reporting clean over a name the server resolves, which is what the dead leg did).
   */
  @Test
  void the_nine_refusal_carry_expires_the_day_table_ref_sql_joins_qualifying_calls() {
    boolean tableRefSqlQualifies = SqlSites.QUALIFYING_CALLS.contains("sql");
    assertThat(tableRefSqlQualifies)
        .describedAs(
            "SqlSites.QUALIFYING_CALLS containing \"sql\" and OPEN_REFUSALS being non-empty must"
                + " never both be true, and must never both be false: one is the reason for the"
                + " other")
        .isEqualTo(OPEN_REFUSALS.isEmpty());
  }

  @Test
  void the_bundled_script_resolves_no_name() {
    var refusals = SqlNameLexer.refusals(SqlSites.read(scriptOnDisk()));
    assertThat(refusals)
        .describedAs(
            "the script is the one path where no pin is available - an unqualified CREATE TABLE"
                + " targets current_schema(), so pg_catalog cannot be put first - which makes"
                + " qualification the only mechanism it has (design section 5)")
        .isEmpty();
  }

  /**
   * The condition the review attached to accepting {@code schemaScript()} as a file read: the file
   * the gate lexed is the resource the module ships, byte for byte. A gate that lexes a file nobody
   * loads is not a gate.
   */
  @Test
  void the_script_the_gate_lexes_is_the_resource_the_module_ships() throws IOException {
    try (InputStream in = NameQualificationGateTest.class.getResourceAsStream(SCHEMA_RESOURCE)) {
      assertThat(in)
          .describedAs("the bundled schema resource must be on the classpath")
          .isNotNull();
      String fromClasspath = new String(in.readAllBytes(), StandardCharsets.UTF_8);
      assertThat(SqlSites.read(scriptOnDisk()))
          .describedAs(
              "the file the gate lexes and the resource JdbcSupport.SCHEMA_RESOURCE loads must be"
                  + " the same bytes, or the gate passes on a file the module does not ship")
          .isEqualTo(fromClasspath);
    }
  }

  // --------------------------------------------- one negative per rule class

  private static List<String> rules(String sql) {
    return SqlNameLexer.refusals(sql).stream()
        .map(SqlNameLexer.Refusal::rule)
        .toList();
  }

  @Test
  void a_bare_equals_is_refused() {
    assertThat(rules("SELECT 1 FROM pg_catalog.pg_class WHERE (relname = ?)"))
        .containsExactly("unqualified operator");
  }

  @Test
  void an_operator_no_list_would_have_held_is_refused() {
    // The 22 spellings revision 1's token list missed. None of them is enumerated anywhere in the
    // gate: they are refused by the operator character class, maximal-munch.
    for (String op : List.of("~", "@>", "->>", "#", "|/", "!!", "^@", "~~*", "&&", "<@")) {
      assertThat(rules("SELECT 1 FROM pg_catalog.pg_class WHERE (relname " + op + " ?)"))
          .describedAs(op)
          .contains("unqualified operator");
    }
  }

  @Test
  void a_keyword_operator_is_refused() {
    assertThat(rules("SELECT 1 FROM pg_catalog.pg_class WHERE (relname LIKE ?)"))
        .containsExactly("keyword operator");
    assertThat(rules("SELECT 1 FROM pg_catalog.pg_class WHERE (a IS DISTINCT FROM b)"))
        .contains("keyword operator");
    assertThat(rules("SELECT 1 FROM pg_catalog.pg_class WHERE (a IN (?, ?))"))
        .containsExactly("keyword operator");
    assertThat(rules("SELECT 1 FROM pg_catalog.pg_class WHERE (a BETWEEN ? AND ?)"))
        .containsExactly("keyword operator");
  }

  @Test
  void a_collate_clause_is_refused() {
    // M5: a non-deterministic collation overrides a fully qualified operator - the review measured
    // ('HMAC-RESIDUE' COLLATE ci) OPERATOR(pg_catalog.=) 'hmac-residue' answering t (C-6).
    assertThat(rules("SELECT 1 WHERE ((a COLLATE ci) OPERATOR(pg_catalog.=) ?)"))
        .contains("keyword operator");
  }

  @Test
  void an_unqualified_function_or_aggregate_is_refused() {
    assertThat(rules("SELECT count(*) FROM pg_catalog.pg_class"))
        .containsExactly("unqualified function or aggregate");
    assertThat(rules("SELECT pg_catalog.count(*) FROM pg_catalog.pg_class")).isEmpty();
  }

  @Test
  void a_quoted_grammar_keyword_before_a_paren_is_refused() {
    // C-5d: with CREATE FUNCTION app."numeric"(int4) in place, "numeric"(1) returned
    // HIJACK-numeric, while the unquoted numeric(1) is a grammar type and a syntax error in
    // expression position (C-5a). The allowance is keyed on the token being unquoted.
    assertThat(rules("SELECT numeric(1)"))
        .describedAs("the unquoted spelling is a grammar type with a length modifier (C-5a)")
        .isEmpty();
    assertThat(rules("SELECT \"numeric\"(1)"))
        .describedAs(
            "a quoted keyword in a function position is a resolvable call and must not be allowed"
                + " by the grammar-type allowance")
        .isNotEmpty();
  }

  @Test
  void a_bare_cast_is_refused() {
    assertThat(rules("SELECT 'pg_class'::regclass")).containsExactly("unqualified type");
    assertThat(rules("SELECT 'pg_class'::pg_catalog.regclass")).isEmpty();
  }

  @Test
  void a_cast_written_as_a_function_is_refused() {
    // M4 / C-4: with CREATE DOMAIN app.text in place, CAST('x' AS text) resolved the domain exactly
    // as 'x'::text did. No statement on this head uses CAST( AS ); the rule keeps that true.
    assertThat(rules("SELECT CAST(? AS myschema.weird)")).containsExactly("unqualified type");
    assertThat(rules("SELECT CAST(? AS pg_catalog.text)")).isEmpty();
  }

  @Test
  void an_unclassified_character_is_refused() {
    assertThat(rules("SELECT (?)[1]")).contains("unclassified character");
    assertThat(rules("SELECT ARRAY[?]")).contains("unclassified character");
    assertThat(rules("SELECT 'a\\b'")).isEmpty(); // inside a literal, which is not a name
    assertThat(rules("SELECT a \\ b")).contains("unclassified character");
  }

  @Test
  void the_operator_allowance_is_a_token_sequence_and_not_a_string_match() {
    // M7 / C-16e: both of these parse and both answer t, and neither is a spelling this module
    // writes. OPERATOR(app.=) is the attack itself.
    assertThat(rules("SELECT 1 WHERE (a OPERATOR ( pg_catalog . = ) b)"))
        .contains("unqualified operator");
    assertThat(rules("SELECT 1 WHERE (a OPERATOR(\"pg_catalog\".=) b)"))
        .contains("unqualified operator");
    assertThat(rules("SELECT 1 WHERE (a OPERATOR(app.=) b)")).contains("unqualified operator");
    assertThat(rules("SELECT 1 WHERE (a OPERATOR(pg_catalog.=) b)")).isEmpty();
  }

  @Test
  void an_unparenthesised_two_operator_expression_is_refused() {
    // M6 / C-16d: 'ab' OPERATOR(pg_catalog.=) 'a' OPERATOR(pg_catalog.||) 'b' evaluates to the
    // TEXT 'falseb', not to a boolean, because every qualified operator takes one generic
    // precedence. E3a is the same lesson inside a guard body, where it fails at run time.
    assertThat(rules("SELECT 'ab' OPERATOR(pg_catalog.=) 'a' OPERATOR(pg_catalog.||) 'b'"))
        .contains("unparenthesised operator sequence");
    assertThat(rules("SELECT ('ab' OPERATOR(pg_catalog.=) ('a' OPERATOR(pg_catalog.||) 'b'))"))
        .isEmpty();
  }

  @Test
  void an_unparenthesised_or_chain_is_refused() {
    // The verifyChunk chain of section 3.4, which must be wrapped by construction so it cannot bind
    // looser than a neighbouring AND.
    assertThat(
            rules(
                "SELECT id FROM app.t WHERE id OPERATOR(pg_catalog.=) ?"
                    + " OR id OPERATOR(pg_catalog.=) ?"))
        .contains("unparenthesised operator sequence");
    assertThat(
            rules(
                "SELECT id FROM app.t WHERE ((id OPERATOR(pg_catalog.=) ?)"
                    + " OR (id OPERATOR(pg_catalog.=) ?))"))
        .isEmpty();
  }

  @Test
  void an_unqualified_relation_is_refused() {
    assertThat(rules("SELECT 1 FROM pg_class")).containsExactly("unqualified relation");
    assertThat(rules("UPDATE shredding_data_key SET a = ?")).contains("unqualified relation");
    assertThat(rules("INSERT INTO shredding_data_key (a) VALUES (?)"))
        .contains("unqualified relation");
    assertThat(rules("SELECT 1 FROM pg_catalog.pg_class")).isEmpty();
    assertThat(rules("SELECT 1 FROM " + hole()))
        .describedAs(
            "a hole is NOT evidence that a relation is qualified (C-A-5): the leg used to skip it,"
                + " and TableRef.sql() renders one part whenever the mapping names no schema")
        .containsExactly("unqualified relation");
    assertThat(rules("SELECT 1 FROM " + qualifiedHole()))
        .describedAs(
            "the one hole the leg accepts: a call that cannot return a one-part name"
                + " (VerifiedSchema.qualify, which is quote(schema) + \".\" + quote(relation)"
                + " with no branch)")
        .isEmpty();
    assertThat(rules("SELECT 1 FROM \"t\""))
        .describedAs("quoting changes case folding, not resolution")
        .containsExactly("unqualified relation");
    assertThat(rules("UPDATE \"t\" SET c = ?")).contains("unqualified relation");
    assertThat(rules("SELECT 1 FROM \"s\".\"t\"")).isEmpty();
  }

  @Test
  void a_ddl_object_name_is_decided_by_the_grammar_and_not_by_proximity() {
    // C-A-3: the object being created is the first non-keyword identifier after the verb, and
    // nothing further along is. The lookback it replaces read every call inside an index
    // expression as the object being created.
    assertThat(rules("CREATE INDEX i ON t (lower(c))"))
        .describedAs("lower( resolves along the applying session's path")
        .contains("unqualified function or aggregate");
    assertThat(rules("CREATE INDEX IF NOT EXISTS i ON t (pg_catalog.lower(c))"))
        .describedAs(
            "the ON relation of a CREATE INDEX is the section 5.2 class: resolved in the applying"
                + " session, covered by the index leg of schema verification, not by qualification")
        .isEmpty();
    assertThat(rules("CREATE TABLE IF NOT EXISTS t (a pg_catalog.text DEFAULT lower(?))"))
        .describedAs("a call in a column default is not the object being created either")
        .contains("unqualified function or aggregate");
    assertThat(
            rules(
                "CREATE OR REPLACE FUNCTION f() RETURNS pg_catalog.text AS $$ BEGIN"
                    + " RETURN pg_catalog.lower('a'); END $$ LANGUAGE plpgsql"))
        .isEmpty();
  }

  @Test
  void only_the_top_level_equals_of_a_set_clause_is_an_assignment() {
    // C-A-4: the inner `=` of SET a = (b = c) is a resolvable operator. Nothing in this module
    // writes that shape; the gate exists for the edit that does.
    assertThat(rules("UPDATE \"s\".\"t\" SET a = (b = c)")).contains("unqualified operator");
    assertThat(rules("UPDATE \"s\".\"t\" SET a = ?, b = ?")).isEmpty();
    assertThat(rules("UPDATE \"s\".\"t\" SET a = (b OPERATOR(pg_catalog.=) c)")).isEmpty();
    assertThat(
            rules(
                "UPDATE \"s\".\"t\" SET a = (a OPERATOR(pg_catalog.+) ?) WHERE"
                    + " (b OPERATOR(pg_catalog.=) ?)"))
        .describedAs("the shape the key adapter writes")
        .isEmpty();
  }

  @Test
  void a_shadowable_type_name_is_refused_in_both_positions() {
    // C-A-1 / C-A-2: the grammar has no TEXT, BYTEA, TIMESTAMPTZ, INT2, INT4 or INT8 production,
    // so all six are ordinary names resolved along search_path in a type position and in a call
    // position alike. varchar(255) stays allowed: it is a production, and a syntax error in
    // expression position.
    for (String type : List.of("text", "bytea", "timestamptz", "int2", "int4", "int8")) {
      assertThat(rules("SELECT ?::" + type)).describedAs("::" + type).contains("unqualified type");
      assertThat(rules("SELECT CAST(? AS " + type + ")"))
          .describedAs("CAST AS " + type)
          .contains("unqualified type");
      assertThat(rules("SELECT " + type + "(?)"))
          .describedAs(type + "(")
          .contains("unqualified function or aggregate");
      assertThat(rules("SELECT ?::pg_catalog." + type)).describedAs("qualified " + type).isEmpty();
    }
    assertThat(rules("SELECT numeric(1)")).isEmpty();
    assertThat(rules("SELECT ?::varchar")).isEmpty();
  }

  @Test
  void a_comment_is_lexed_and_not_stripped() {
    // The objection GuardBodies' javadoc raises against a regex stripper: a -- inside a literal is
    // not a comment, and a /* */ nests. The gate has a lexer; GuardBodies still does not.
    assertThat(rules("SELECT 1 FROM pg_catalog.pg_class -- WHERE relname = ?")).isEmpty();
    assertThat(rules("SELECT /* a /* nested */ comment */ 1 FROM pg_catalog.pg_class")).isEmpty();
    assertThat(rules("SELECT '-- not a comment' FROM pg_class"))
        .containsExactly("unqualified relation");
  }

  @Test
  void a_dollar_quoted_body_is_lexed_recursively() {
    assertThat(
            rules(
                "CREATE OR REPLACE FUNCTION f() RETURNS trigger AS $$ BEGIN"
                    + " IF NEW.a <> OLD.a THEN RAISE EXCEPTION 'no'; END IF; RETURN NEW;"
                    + " END $$ LANGUAGE plpgsql"))
        .describedAs("the three guard bodies are covered by this path and by nothing else")
        .contains("unqualified operator");
    assertThat(
            rules(
                "CREATE OR REPLACE FUNCTION f() RETURNS trigger AS $$ BEGIN"
                    + " IF NEW.a OPERATOR(pg_catalog.<>) OLD.a THEN RAISE EXCEPTION 'no';"
                    + " END IF; RETURN NEW; END $$ LANGUAGE plpgsql"))
        .isEmpty();
  }

  @Test
  void a_statement_whose_argument_cannot_be_resolved_is_refused() throws IOException {
    Path dir = Files.createTempDirectory("namegate");
    Path file = dir.resolve("Unresolvable.java");
    Files.writeString(
        file,
        """
        class Unresolvable {
          void go(java.sql.Connection c, String fromSomewhereElse) throws Exception {
            c.prepareStatement(fromSomewhereElse).execute();
          }
        }
        """);
    var scan = SqlSites.scan(List.of(file));
    assertThat(scan.unresolved())
        .describedAs("the coverage refusal: a hop the gate cannot resolve fails the gate")
        .hasSize(1);
    Files.delete(file);
    Files.delete(dir);
  }

  @Test
  void a_literal_that_never_reaches_a_statement_is_not_selected() throws IOException {
    // The over-refusal the review measured in the naive "literal containing a SQL keyword" rule:
    // 27 prose error messages on this head, one of which is reproduced here verbatim in shape.
    Path dir = Files.createTempDirectory("namegate");
    Path file = dir.resolve("Prose.java");
    Files.writeString(
        file,
        """
        class Prose {
          static final String ADVICE =
              "set shredding.jdbc.initialize-schema=true and run the bundled"
                  + " schema-postgresql.sql, which does CREATE TABLE shredding_data_key";
        }
        """);
    var scan = SqlSites.scan(List.of(file));
    assertThat(scan.sites()).isEmpty();
    assertThat(scan.unresolved()).isEmpty();
    Files.delete(file);
    Files.delete(dir);
  }

  private static String hole() {
    return "\u0001HOLE\u0001";
  }

  private static String qualifiedHole() {
    return "\u0001QHOLE\u0001";
  }
}
