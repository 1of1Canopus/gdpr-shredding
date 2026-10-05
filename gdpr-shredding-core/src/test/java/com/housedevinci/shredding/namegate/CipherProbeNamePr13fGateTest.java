package com.housedevinci.shredding.namegate;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Cipher probes, review of PR A of the name-resolution design (2026-10-03).
 *
 * <p>Each test states a statement the gate accepts today and that PostgreSQL 16.15 resolves through
 * {@code search_path} on a session whose path names {@code pg_catalog} last. Measured in a two-role
 * fixture: {@code shred_app} owns {@code decoy}, {@code search_path = decoy, app, pg_catalog}.
 */
class CipherProbeNamePr13fGateTest {

  private static List<String> rules(String sql) {
    return SqlNameLexer.refusals(sql).stream().map(SqlNameLexer.Refusal::rule).toList();
  }

  @Test
  @DisplayName(
      "C-A-1: ::text, ::int8, ::timestamptz, ::bytea, ::int2, ::int4 are not grammar types")
  void probe_the_gate_allows_unqualified_casts_to_shadowable_type_names() {
    // Measured: CREATE DOMAIN decoy.text AS char(3); then 'abcdefgh'::text answers 'abc'
    // and pg_typeof still prints `text`. CREATE DOMAIN decoy.int8 AS smallint; '12'::int8
    // answers int8, the domain. The grammar has no TEXT, BYTEA, TIMESTAMPTZ, INT2, INT4 or
    // INT8 production: those six spellings are ordinary type names looked up along the path.
    assertThat(rules("SELECT relname::text FROM pg_catalog.pg_class"))
        .as("::text is resolvable: a decoy.text domain over char(3) truncates silently")
        .contains("unqualified type");
    assertThat(rules("SELECT relpages::int8 FROM pg_catalog.pg_class"))
        .as("::int8 is resolvable: a decoy.int8 domain over smallint overflows")
        .contains("unqualified type");
    assertThat(rules("SELECT pg_catalog.now()::timestamptz"))
        .as("::timestamptz is resolvable: a decoy.timestamptz domain over date drops the time")
        .contains("unqualified type");
    assertThat(rules("SELECT CAST(relname AS text) FROM pg_catalog.pg_class"))
        .as("CAST(x AS text) is the same type position")
        .contains("unqualified type");
  }

  @Test
  @DisplayName("C-A-2: text(x) and int8(x) are function calls, not grammar type keywords")
  void probe_the_gate_allows_function_syntax_casts_to_shadowable_type_names() {
    // varchar(255) in expression position is a syntax error, which is why the grammar-type
    // allowance is sound for VARCHAR. text(x) and int8(x) are not syntax errors: they are
    // plain function calls resolved along the path, so decoy.text(anyelement) answers them.
    assertThat(rules("SELECT text(relname) FROM pg_catalog.pg_class"))
        .as("text( is an unqualified function call")
        .contains("unqualified function or aggregate");
    assertThat(rules("SELECT int8(relpages) FROM pg_catalog.pg_class"))
        .as("int8( is an unqualified function call")
        .contains("unqualified function or aggregate");
  }

  @Test
  @DisplayName("C-A-3: an unqualified function in a CREATE INDEX expression passes isDdlObjectName")
  void probe_the_gate_allows_an_unqualified_function_inside_a_create_index_expression() {
    // isDdlObjectName looks back up to six tokens for `index` and then up to four more for
    // `create`, so every call inside the index expression is treated as the object being
    // created rather than as a name being resolved.
    assertThat(rules("CREATE INDEX i ON t (lower(c))"))
        .as("lower( in an index expression resolves along the applying session's path")
        .contains("unqualified function or aggregate");
  }

  @Test
  @DisplayName("C-A-4: an unqualified = inside a SET-clause expression is read as an assignment")
  void probe_the_gate_allows_an_unqualified_equals_inside_a_set_clause_expression() {
    // isAssignment fires on any `=` whose previous token is an identifier while the lexer is
    // still inside a SET clause, so the inner `=` of `SET a = (b = c)` is allowed.
    assertThat(rules("UPDATE \"s\".\"t\" SET a = (b = c)"))
        .as("the inner = is a resolvable operator, not an assignment")
        .contains("unqualified operator");
  }

  @Test
  @DisplayName(
      "C-A-5: the relation leg never fires on a quoted name, which is the only kind this"
          + " module emits")
  void probe_the_gate_never_refuses_a_quoted_unqualified_relation() {
    // checkRelationPosition returns early unless the token is an unquoted IDENT. TableRef.sql()
    // always quotes, and TableRef.schema is an Optional, so an unqualified entity table reaches
    // the server as `"t"` - a name PostgreSQL resolves along the writing session's search_path.
    // Measured: with search_path = decoy, app, pg_catalog a `decoy."t"` shadows `app."t"`.
    assertThat(rules("SELECT a FROM \"t\" WHERE i OPERATOR(pg_catalog.=) ?"))
        .as("a quoted unqualified relation is still resolved by search_path")
        .contains("unqualified relation");
    assertThat(rules("UPDATE \"t\" SET c = ? WHERE i OPERATOR(pg_catalog.=) ?"))
        .as("the three starter statements of section 3.4 have exactly this shape")
        .contains("unqualified relation");
    // And the hole: SqlSites turns a non-literal into one HOLE token on the stated ground that it
    // carries "a name the module holds as data and not a name the server resolves". For a
    // TableRef with no schema that ground does not hold, and the hole is ignored here too.
    assertThat(rules("SELECT a FROM " + hole() + " WHERE i OPERATOR(pg_catalog.=) ?"))
        .as("a hole in relation position is not evidence that the name is qualified")
        .contains("unqualified relation");
  }

  private static String hole() {
    return "\u0001HOLE\u0001";
  }
}
