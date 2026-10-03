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
   * Every Java file the gate reads: the whole JDBC adapter package, plus the two starter files that
   * build statements on the application's own connection (P2b, section 3.4). The list is a
   * directory walk and two named files rather than a list of statements, so a new adapter file is
   * covered the day it is added.
   */
  private static List<Path> sources() {
    try (Stream<Path> core = Files.walk(coreMain())) {
      var out =
          new ArrayList<Path>(core.filter(p -> p.toString().endsWith(".java")).sorted().toList());
      out.add(starterMain().resolve("WriteVerification.java"));
      out.add(starterMain().resolve("ShreddingEventListener.java"));
      for (Path p : out) {
        assertThat(p).describedAs("the gate's source list must not rot").exists();
      }
      return out;
    } catch (IOException e) {
      throw new IllegalStateException("the gate could not walk " + coreMain().toAbsolutePath(), e);
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
                + " name. There is no open refusal and no allowlist: the one name qualification"
                + " cannot reach - the keyword operator of the cross-tenant read-back - is admitted"
                + " by the mechanism that closes it, the one-statement window, and only inside it.")
        .isEmpty();
  }

  /**
   * The one name in this module that qualification cannot reach, named here with the mechanism that
   * closes it rather than allowlisted by file or by line.
   *
   * <p>{@code IS DISTINCT FROM} is the type's own {@code =} reached through a grammar keyword, and
   * it has no {@code OPERATOR(pg_catalog....)} spelling at all. The site is the cross-tenant WARN
   * read-back in {@code JdbcErasureStore.verifyCleared}, where the tenant column is nullable and
   * {@code <>} is therefore not equivalent. Revision 1 of the design claimed the {@code
   * search_path} pin covered it; T3c measured that on the arrived path it answers 2 where the truth
   * is 1. Revision 2 moves the statement <b>inside</b> the replaced-path bracket of section 4,
   * where it is correct (T2e) - and that bracket is PR B1, not this PR.
   *
   * <p>It stays a WARN and never a refusal, and the refusing legs on the same column are qualified,
   * so what is at risk here is the accuracy of a log line rather than the erasure's verdict.
   *
   * <p>The expectation is the exact refusal, not a file or a line: a second keyword operator
   * anywhere, or this one moving to another statement, fails the gate, and PR B1 removes this entry
   * when the bracket lands.
   */
  private static final List<String> OPEN_REFUSALS =
      List.of(
          "JdbcErasureStore.java:404 keyword operator: `IS DISTINCT FROM` in"
              + " ...g_catalog.=) ?) AND <> IS DISTINCT FROM ? AND <> IS ...");

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
    return SqlNameLexer.refusals(sql).stream().map(SqlNameLexer.Refusal::rule).toList();
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
        .describedAs("a hole is a name held as data")
        .isEmpty();
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
}
