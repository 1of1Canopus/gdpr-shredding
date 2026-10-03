package com.housedevinci.shredding.namegate;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Cipher probes, review of PR A of the name-resolution design, second pass (2026-10-03).
 *
 * <p>Head {@code e918d02}. Every statement below is accepted by the gate on this head and resolves
 * a name through {@code search_path} on PostgreSQL 16.14 (the digest the module's own tests pin),
 * in the same two-role fixture the first pass used: {@code shred_app} is {@code NOSUPERUSER
 * NOCREATEDB NOCREATEROLE}, owns schema {@code decoy}, and set its own {@code search_path = decoy,
 * app, pg_catalog}. Every hijack claimed in a comment was executed as that role before the test was
 * written.
 */
class CipherProbeNamePr13gGateTest {

  private static List<String> rules(String sql) {
    return SqlNameLexer.refusals(sql).stream().map(SqlNameLexer.Refusal::rule).toList();
  }

  @Test
  @DisplayName("C-A-9: five names in the gate's own allowlists are resolvable, and all five hijack")
  void probe_the_allowlists_still_carry_names_the_server_resolves() {
    // The C-A-1/C-A-2 fix removed six names from GRAMMAR_TYPES and wrote down the membership rule
    // ("every spelling here is a production in gram.y"), but the list was not checked against the
    // rule and the second allowlist in the same branch was not looked at:
    //
    //   checkFunctionCall: if (KEYWORDS.contains(word) || GRAMMAR_TYPES.contains(word)) return;
    //
    // pg_get_keywords() answers the membership question exactly. catcode 'C' is "unreserved
    // (cannot be function or type name)", which is what makes the varchar(255) allowance sound.
    // Measured on 16.14: of GRAMMAR_TYPES' sixteen entries fifteen are catcode 'C' and `double`
    // is catcode 'U'; `left` and `right` are catcode 'T' ("reserved (can be function or type
    // name)"); `replace` and `mode` are 'U'. All four of the KEYWORDS entries exist in pg_catalog
    // as functions, so all four are shadowable, and `double` is shadowable in both positions.
    //
    // Executed as shred_app, each after CREATE FUNCTION decoy."<name>"(...) of its own:
    //   SELECT left('abcdef', 2)      -> HIJACKED      (pg_catalog.left -> ab)
    //   SELECT right('abcdef', 2)     -> HIJACKED
    //   SELECT replace('aaa','a','b') -> HIJACKED-replace  (pg_catalog.replace -> bbb)
    //   SELECT mode(1)                -> HIJACKED-mode
    //   SELECT double(1)              -> HIJACKED-double
    //   CREATE DOMAIN decoy.double AS pg_catalog.varchar(3);
    //   SELECT 'abcdefgh'::double     -> abc          (and 1::double errors until the domain
    // exists)
    //
    // No statement on this head writes any of the five; the consequence is drift, which is the
    // same ground C-A-3 and C-A-4 were ruled LOW on.
    for (String name : List.of("left", "right", "replace", "mode", "double")) {
      assertThat(rules("SELECT " + name + "(?)"))
          .describedAs(
              name
                  + "( is a resolvable function call: pg_catalog has it and the role can shadow it")
          .contains("unqualified function or aggregate");
    }
    assertThat(rules("SELECT ?::double"))
        .describedAs(
            "`double` alone is not a grammar production - `double precision` is - so ::double"
                + " resolves a domain along the path")
        .contains("unqualified type");
    assertThat(rules("SELECT CAST(? AS double)"))
        .describedAs("the same type position written as a function")
        .contains("unqualified type");
    // The allowance that is sound stays sound: these are catcode 'C' and a syntax error in
    // expression position.
    assertThat(rules("SELECT numeric(1)")).isEmpty();
    assertThat(rules("SELECT ?::varchar")).isEmpty();
  }

  @Test
  @DisplayName("C-A-10: the relation leg reads only the first entry of a FROM list")
  void probe_the_relation_leg_reads_only_the_first_entry_of_a_from_list() {
    // checkRelationPosition decides the position from the single preceding token - FROM, JOIN,
    // INTO, UPDATE, LOCK TABLE - so the second and third entries of a comma-separated FROM list
    // are never visited, and neither is a relation behind a keyword the leg returns early on.
    //
    // This is live. SchemaVerification.java:508 is the one statement in the module with a
    // comma-separated FROM list:
    //   FROM pg_catalog.pg_class s, pg_catalog.pg_class t, pg_catalog.pg_attribute a
    // All three entries are qualified today, and the gate reports the statement clean because the
    // leg never looked at two of them rather than because they are qualified. Measured as
    // shred_app, with a decoy.customer the role owns:
    //   SELECT b.id FROM app.customer a, customer b WHERE a.id OPERATOR(pg_catalog.=) 1  -> 99,
    // the decoy row.
    String live =
        "SELECT s.relkind FROM pg_catalog.pg_class s, pg_catalog.pg_class t,"
            + " pg_catalog.pg_attribute a WHERE (s.relname OPERATOR(pg_catalog.=) ?)";
    assertThat(rules(live))
        .describedAs("the live shape, which is correct, must stay clean")
        .isEmpty();
    assertThat(rules(live.replace(", pg_catalog.pg_class t", ", pg_class t")))
        .describedAs("the second entry of the live statement, un-qualified: the gate must refuse")
        .contains("unqualified relation");
    assertThat(rules(live.replace(", pg_catalog.pg_attribute a", ", \"pg_attribute\" a")))
        .describedAs("the third entry, quoted and un-qualified")
        .contains("unqualified relation");
    assertThat(rules(live.replace(", pg_catalog.pg_class t", ", " + hole() + " t")))
        .describedAs("a bare hole in the second entry carries no evidence either (C-A-5's rule)")
        .contains("unqualified relation");
    // And the keyword forms, none of them live, each of which puts one token between the position
    // keyword and the name: ONLY is the sharpest, because it also defeats the plain-hole refusal
    // this round added.
    assertThat(rules("SELECT 1 FROM ONLY \"t\""))
        .describedAs("FROM ONLY t resolves t along the path exactly as FROM t does")
        .contains("unqualified relation");
    assertThat(rules("SELECT 1 FROM ONLY " + hole()))
        .describedAs("one keyword and the hole refusal of C-A-5 is gone")
        .contains("unqualified relation");
    assertThat(rules("DELETE FROM pg_catalog.pg_class USING \"t\""))
        .describedAs("the USING list of a DELETE is a relation position")
        .contains("unqualified relation");
    assertThat(rules("TRUNCATE \"t\""))
        .describedAs("TRUNCATE names a relation and the leg has no entry for it")
        .contains("unqualified relation");
    assertThat(rules("LOCK TABLE ONLY \"t\""))
        .describedAs("the leg's LOCK TABLE entry requires the name to follow TABLE immediately")
        .contains("unqualified relation");
  }

  @Test
  @DisplayName("C-A-11: two name positions the gate reads no evidence about")
  void probe_a_hole_in_a_type_position_and_an_operator_class_are_accepted_without_evidence() {
    // checkTypeName returns on Kind.HOLE with no comment and without the QUALIFIED_HOLE
    // distinction the relation leg now makes, so a type name that comes from Java is reported
    // clean on no evidence. The asymmetry is unstated: the same token in relation position is a
    // refusal, on the stated ground that "the gate has no evidence about what it carries".
    // Not live - the three casts in the module's 48 resolved variants are ::pg_catalog.regclass,
    // ::pg_catalog.oid and ::pg_catalog.text - so this is drift, like C-A-3 and C-A-4.
    assertThat(rules("SELECT ?::" + hole()))
        .describedAs("a hole after :: is not evidence that the type names its schema")
        .contains("unqualified type");
    assertThat(rules("SELECT CAST(? AS " + hole() + ")"))
        .describedAs("the same position written as CAST")
        .contains("unqualified type");
    assertThat(rules("SELECT ?::" + qualifiedHole()))
        .describedAs("the one hole spelling that carries its schema stays accepted")
        .isEmpty();
    // The operator class of an index column is resolved along search_path too, and no leg reads
    // it. The bundled script names none, so this is drift as well.
    assertThat(rules("CREATE INDEX i ON t (c text_ops)"))
        .describedAs("an operator class is a schema-qualifiable name resolved along the path")
        .isNotEmpty();
  }

  @Test
  @DisplayName("C-A-12: SECURITY-NOTES still documents a spelling no main source contains")
  void probe_security_notes_names_a_residual_the_code_no_longer_has() throws IOException {
    // C-A-6 rewrote the cross-tenant WARN read-back as
    //   (<tenant> IS NULL OR NOT (<tenant> OPERATOR(pg_catalog.=) ?))
    // and deleted the gate's allowance. SECURITY-NOTES.md's "What is still resolved by a session"
    // was not updated: it still says the read-back "uses IS DISTINCT FROM", that "the rewrite is
    // not available either", and that the consequence is an over-count. Two of the three are now
    // false and the third was measured backwards. With decoy.=(varchar, varchar) returning false
    // and one NULL tenant among three rows, as shred_app:
    //   ... AND tenant IS DISTINCT FROM 't1' ...                        -> 0   (under-counts)
    //   ... AND (tenant IS NULL OR NOT (tenant OPERATOR(pg_catalog.=) 't1')) -> 2   (honest)
    //   ... AND (tenant OPERATOR(pg_catalog.<>) 't1') ...               -> 1   (drops the NULL)
    // The keyword form suppressed the WARN rather than inflating it, so the document also states
    // the wrong failure direction for a control a reader is told to rely on.
    boolean inMainSources =
        mainSources().stream()
            .map(SqlSites::read)
            .anyMatch(
                s ->
                    s.contains("IS DISTINCT FROM")
                        && !s.contains("rather than written IS DISTINCT"));
    assertThat(inMainSources)
        .describedAs("no main source spells IS DISTINCT FROM in a statement any more (C-A-6)")
        .isFalse();
    List<String> claims =
        SqlSites.read(Path.of("../SECURITY-NOTES.md"))
            .lines()
            .filter(l -> l.contains("IS DISTINCT FROM"))
            .toList();
    assertThat(claims)
        .describedAs(
            "a security document must not describe a residual exposure the code no longer has:"
                + " the cross-tenant WARN read-back is qualified since C-A-6")
        .isEmpty();
  }

  private static List<Path> mainSources() throws IOException {
    var out = new ArrayList<Path>();
    for (Path root :
        List.of(
            Path.of("src/main/java/com/housedevinci/shredding/adapter/jdbc"),
            Path.of(
                "../gdpr-shredding-spring-boot-starter/src/main/java/com/housedevinci/shredding/autoconfigure"))) {
      try (Stream<Path> s = Files.walk(root)) {
        out.addAll(s.filter(p -> p.toString().endsWith(".java")).sorted().toList());
      }
    }
    return out;
  }

  private static String hole() {
    return "\u0001HOLE\u0001";
  }

  private static String qualifiedHole() {
    return "\u0001QHOLE\u0001";
  }
}
