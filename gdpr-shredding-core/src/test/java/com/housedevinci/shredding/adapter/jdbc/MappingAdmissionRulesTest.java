package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Admitted;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.ColumnFacts;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Descendant;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Refused;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.RelationFacts;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.TypeFacts;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Use;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Verdict;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.TableRef;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * The rules of addendum section A.3 over hand-built catalogue facts: every ordering and every NULL
 * branch the design names, with no database. The Testcontainers suite proves the facts are the
 * catalogue's; this one proves what the rules do with them.
 */
class MappingAdmissionRulesTest {

  private static final Column TENANT =
      new Column(ColumnRef.unquoted("tenant"), Use.COMPARED, "tenant column");
  private static final Column INDEX =
      new Column(ColumnRef.unquoted("email_idx"), Use.ASSIGNED, "blind-index column");
  private static final Target TARGET =
      new Target(Optional.of("Note"), TableRef.parse("app.note"), List.of(TENANT, INDEX));

  private static final TypeFacts VARCHAR =
      type(
          "b",
          "S",
          "pg_catalog",
          "character varying",
          null,
          List.of("pg_catalog:-", "pg_catalog:pg_catalog"),
          null);
  private static final TypeFacts CITEXT =
      type(
          "b",
          "S",
          "public",
          "citext",
          "public",
          List.of("pg_catalog:-", "pg_catalog:pg_catalog"),
          "public");

  @Test
  void a_plain_table_with_a_varchar_tenant_is_admitted() {
    assertThat(judge(table(), List.of(), facts(VARCHAR, VARCHAR, Optional.of(true))))
        .isEqualTo(new Admitted(List.of()));
  }

  /** Mutation 21: C-c read before C-b admits citext through its implicit cast to text. */
  @Test
  void c_b_is_read_before_c_c() {
    TypeFacts domainOverCitext = type("d", "S", "app", "ci_dom", null, List.of(), null);
    assertRule(
        judge(table(), List.of(), facts(domainOverCitext, CITEXT, Optional.of(true))), "C-b");
  }

  /** S-6: C-c reads the target's namespace and the target's own equality, not a type name. */
  @Test
  void c_c_admits_only_a_pg_catalog_target_whose_own_equality_is_pg_catalogs() {
    for (List<String> refused :
        List.of(
            List.<String>of(),
            List.of("pg_catalog:-"),
            List.of("app:pg_catalog"),
            List.of("pg_catalog:app"))) {
      TypeFacts base = type("b", "S", "app", "t", null, refused, null);
      assertRule(judge(table(), List.of(), facts(base, base, Optional.of(true))), "C-c");
    }
    assertThat(MappingAdmission.reachesCatalogEquality(List.of("app:-", "pg_catalog:pg_catalog")))
        .isTrue();
  }

  @Test
  void c_d_refuses_an_array_a_composite_and_a_range_and_admits_an_enum() {
    TypeFacts array = type("b", "A", "pg_catalog", "text[]", "pg_catalog", List.of(), null);
    TypeFacts composite = type("c", "C", "app", "pair", "pg_catalog", List.of(), null);
    TypeFacts range = type("r", "R", "pg_catalog", "int4range", "pg_catalog", List.of(), null);
    TypeFacts enumType = type("e", "E", "app", "tenant_e", "pg_catalog", List.of(), null);
    for (TypeFacts t : List.of(array, composite, range)) {
      assertRule(judge(table(), List.of(), facts(t, t, Optional.of(true))), "C-d");
    }
    assertThat(judge(table(), List.of(), facts(enumType, enumType, Optional.empty())))
        .isInstanceOf(Admitted.class);
  }

  /** S-5 and N44b: NULL (non-collatable) is admitted by its own branch, never read as false. */
  @Test
  void c_e_admits_a_non_collatable_column_and_refuses_only_an_explicit_false() {
    assertThat(judge(table(), List.of(), facts(VARCHAR, VARCHAR, Optional.empty())))
        .isInstanceOf(Admitted.class);
    assertRule(judge(table(), List.of(), facts(VARCHAR, VARCHAR, Optional.of(false))), "C-e");
  }

  /** S-1: C-h is read on the declared type even when the base type's own equality is admitted. */
  @Test
  void c_h_refuses_an_application_equality_on_the_declared_type() {
    TypeFacts domain = type("d", "S", "app", "tenant_t", null, List.of(), "app");
    TypeFacts text =
        type("b", "S", "pg_catalog", "text", "pg_catalog", List.of("pg_catalog:pg_catalog"), null);
    assertRule(judge(table(), List.of(), facts(domain, text, Optional.of(true))), "C-h");
  }

  @Test
  void the_assigned_column_is_refused_when_not_null_or_generated_and_its_type_is_not_read() {
    var notNull =
        new ColumnFacts(
            INDEX, true, true, "", Optional.empty(), Optional.empty(), Optional.empty());
    var generated =
        new ColumnFacts(
            INDEX, true, false, "s", Optional.empty(), Optional.empty(), Optional.empty());
    assertRule(
        judge(table(), List.of(), List.of(tenant(VARCHAR, VARCHAR, Optional.of(true)), notNull)),
        "C-f");
    assertRule(
        judge(table(), List.of(), List.of(tenant(VARCHAR, VARCHAR, Optional.of(true)), generated)),
        "C-g");
  }

  @Test
  void c_a_is_a_row_of_nulls() {
    var absent =
        new ColumnFacts(
            TENANT, false, false, "", Optional.empty(), Optional.empty(), Optional.empty());
    assertRule(judge(table(), List.of(), List.of(absent)), "C-a");
  }

  /** S-4, mutation 31: R-g reads bypassrls from the relation leg, and labels the admission. */
  @Test
  void r_g_reads_the_role_s_bypassrls_and_ownership_and_force() {
    assertRule(judge(rls(false, false, false), List.of(), ok()), "R-g");
    assertRule(judge(rls(true, true, false), List.of(), ok()), "R-g");
    assertThat(judge(rls(true, false, false), List.of(), ok())).isEqualTo(new Admitted(List.of()));
    Verdict bypass = judge(rls(false, false, true), List.of(), ok());
    assertThat(bypass).isInstanceOf(Admitted.class);
    assertThat(((Admitted) bypass).warnings())
        .singleElement()
        .asString()
        .contains("[advisory posture]");
  }

  /** S-3: one rule over the descendant set; a partitioned partition is not a leaf. */
  @Test
  void r_d_reads_the_whole_descendant_set_by_kind_leaf_and_persistence() {
    assertThat(judge(partitioned(), List.of(d("p", "p", 1), d("r", "p", 0)), ok()))
        .isInstanceOf(Admitted.class);
    assertRule(judge(partitioned(), List.of(d("p", "p", 0)), ok()), "R-d");
    assertRule(judge(partitioned(), List.of(d("f", "p", 0)), ok()), "R-d");
    assertRule(judge(partitioned(), List.of(d("r", "t", 0)), ok()), "R-d");
    Verdict unlogged = judge(table(), List.of(d("r", "u", 0)), ok());
    assertThat(((Admitted) unlogged).warnings()).singleElement().asString().contains("UNLOGGED");
  }

  @Test
  void the_relation_rules_refuse_by_kind_persistence_and_privilege() {
    assertRule(judge(rel(2, "v", "p", true, true), List.of(), ok()), "R-c");
    assertRule(judge(rel(2, "m", "p", true, true), List.of(), ok()), "R-c");
    assertRule(judge(rel(2, "r", "t", true, true), List.of(), ok()), "R-f");
    assertRule(judge(rel(2, "r", "p", true, false), List.of(), ok()), "R-h");
    assertRule(judge(rel(1, "r", "p", true, true), List.of(), ok()), "R-a");
    assertThat(
            judge(
                new RelationFacts(
                    2, Optional.empty(), "", "", false, false, false, false, false, false, 0),
                List.of(),
                ok()))
        .isInstanceOf(MappingAdmission.Absent.class);
  }

  @Test
  void the_erasure_targets_group_blind_index_columns_by_table_in_order() {
    var a = TableRef.parse("app.a");
    var b = TableRef.parse("app.b");
    var targets = Target.forErasure(List.of(bic(b, "x_idx"), bic(a, "y_idx"), bic(b, "z_idx")));
    assertThat(targets).extracting(Target::table).containsExactly(b, a);
    assertThat(targets.get(0).columns())
        .extracting(c -> c.ref().text())
        .containsExactly("tenant", "subject", "x_idx", "z_idx");
    assertThat(targets.get(0).entity()).isEmpty();
  }

  // ------------------------------------------------------------------------------------------

  private static BlindIndexColumn bic(TableRef table, String index) {
    return new BlindIndexColumn(
        table,
        ColumnRef.unquoted(index),
        ColumnRef.unquoted("subject"),
        ColumnRef.unquoted("tenant"),
        Optional.empty(),
        Optional.empty());
  }

  private static Verdict judge(RelationFacts r, List<Descendant> d, List<ColumnFacts> c) {
    return MappingAdmission.judge(TARGET, r, d, c);
  }

  private static void assertRule(Verdict verdict, String rule) {
    assertThat(verdict).isInstanceOf(Refused.class);
    assertThat(((Refused) verdict).rule()).isEqualTo(rule);
  }

  private static RelationFacts rel(
      int parts, String kind, String persistence, boolean read, boolean write) {
    return new RelationFacts(
        parts, Optional.of(1L), kind, persistence, false, false, true, read, write, false, 0);
  }

  private static RelationFacts table() {
    return rel(2, "r", "p", true, true);
  }

  private static RelationFacts partitioned() {
    return rel(2, "p", "p", true, true);
  }

  private static RelationFacts rls(boolean owns, boolean force, boolean bypass) {
    return new RelationFacts(
        2, Optional.of(1L), "r", "p", true, force, owns, true, true, bypass, 0);
  }

  private static Descendant d(String kind, String persistence, long children) {
    return new Descendant(2L, kind, persistence, children);
  }

  private static List<ColumnFacts> ok() {
    return facts(VARCHAR, VARCHAR, Optional.of(true));
  }

  private static List<ColumnFacts> facts(
      TypeFacts declared, TypeFacts base, Optional<Boolean> det) {
    return List.of(
        tenant(declared, base, det),
        new ColumnFacts(
            INDEX, true, false, "", Optional.of(true), Optional.of(VARCHAR), Optional.of(VARCHAR)));
  }

  private static ColumnFacts tenant(TypeFacts declared, TypeFacts base, Optional<Boolean> det) {
    return new ColumnFacts(TENANT, true, false, "", det, Optional.of(declared), Optional.of(base));
  }

  private static TypeFacts type(
      String typtype,
      String category,
      String schema,
      String spelled,
      String ownEq,
      List<String> implicit,
      String shadow) {
    return new TypeFacts(
        typtype,
        category,
        0L,
        schema,
        spelled,
        Optional.ofNullable(ownEq),
        implicit,
        Optional.ofNullable(shadow));
  }
}
