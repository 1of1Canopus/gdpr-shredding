package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** The owner-context rules O1 (closure), O2 and O3 in Java, with no database. */
class OwnerContextRulesTest {

  private static final long APP = 20_000;
  private static final long PG = 10;
  private static final Set<Long> REACH = Set.of(APP);

  private static OwnerContext.Fact fact(String kind, String label, long owner, long other) {
    return new OwnerContext.Fact(kind, 1, label, owner, owner == PG ? "postgres" : "app", other);
  }

  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void call_site_list_matches_the_pinned_sources(int major) throws IOException {
    String grep;
    try (InputStream in =
        OwnerContextRulesTest.class.getResourceAsStream("/owner-context/grep-" + major + ".txt")) {
      assertThat(in)
          .describedAs("tools/owner-context-call-sites.sh output for " + major)
          .isNotNull();
      grep = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    var sites = grep.lines().filter(l -> !l.startsWith("#") && !l.isBlank()).toList();
    Map<String, String> map = OwnerContext.callSites(major).orElseThrow();
    assertThat(map.keySet())
        .describedAs("every call site in the pinned sources has exactly one line in the map")
        .containsExactlyElementsOf(sites);
    assertThat(OwnerContext.CALL_SITES).containsAll(map.values());
    assertThat(OwnerContext.callSitesMapped(major)).isTrue();
  }

  @Test
  void a_major_with_no_call_site_map_is_not_mapped() {
    assertThat(OwnerContext.callSites(15)).isEmpty();
    assertThat(OwnerContext.callSitesMapped(15)).isFalse();
  }

  @Test
  void o2_does_not_apply_with_no_entry_point() {
    var facts =
        List.of(
            fact("nsp", "appsch", APP, 0),
            fact("crt", "appsch", APP, APP),
            fact("own", "table appsch.t", APP, 1259),
            fact("fk", "foreign key k on appsch.c referencing appsch.p", APP, APP),
            fact("def", "appsch.f()", APP, 0));
    var v = OwnerContext.judge(facts, REACH, true, 17);
    assertThat(v.entryPoints()).isEmpty();
    assertThat(v.o2()).isEmpty();
  }

  @Test
  void o2_applies_with_no_condition_when_the_sites_are_not_mapped() {
    var v = OwnerContext.judge(List.of(fact("nsp", "appsch", APP, 0)), REACH, false, 18);
    assertThat(v.o2())
        .singleElement()
        .extracting(OwnerContext.Line::rest)
        .asString()
        .startsWith("owns schema appsch")
        .contains("identity-switch sites for PostgreSQL 18 are not all mapped");
  }

  @ParameterizedTest
  @ValueSource(strings = {"referencing", "referenced"})
  void a_foreign_key_with_either_table_outside_reach_is_an_entry_point(String side) {
    var fk =
        side.equals("referencing")
            ? fact("fk", "foreign key k on public.c referencing appsch.p", PG, APP)
            : fact("fk", "foreign key k on appsch.c referencing public.p", APP, PG);
    var v =
        OwnerContext.judge(List.of(fk, fact("own", "table appsch.t", APP, 1259)), REACH, true, 16);
    assertThat(v.entryPoints()).hasSize(1);
    assertThat(v.o2())
        .singleElement()
        .extracting(OwnerContext.Line::rest)
        .asString()
        .startsWith("owns table appsch.t, and this database runs code");
  }

  @Test
  void o2_lists_create_for_public_and_schemas_owned_outside_reach_are_not_listed() {
    var facts =
        List.of(
            fact("def", "public.f()", PG, 0),
            fact("nsp", "public", PG, 0),
            fact("crt", "s", PG, 0));
    var v = OwnerContext.judge(facts, REACH, true, 17);
    assertThat(v.o2())
        .singleElement()
        .satisfies(
            l -> {
              assertThat(l.who()).isZero();
              assertThat(l.rest()).startsWith("holds CREATE on schema s");
            });
  }

  @Test
  void o3_refuses_maintain_on_a_relation_owned_outside_reach_only() {
    var facts = List.of(fact("mnt", "public.tm", PG, APP), fact("mnt", "appsch.mine", APP, APP));
    var v = OwnerContext.judge(facts, REACH, true, 17);
    assertThat(v.o3())
        .singleElement()
        .extracting(OwnerContext.Line::rest)
        .asString()
        .startsWith("holds MAINTAIN on relation public.tm");
  }

  // ------------------------------------------------------------- O1: statement 4 in Java

  private static FunctionGrantsSql.OwnerFact row(
      String kind, long rel, String label, long owner, int slot, long typ, long fn) {
    return new FunctionGrantsSql.OwnerFact(
        kind,
        rel,
        label,
        owner,
        "postgres",
        slot,
        typ,
        fn,
        "f()",
        fn == 0 ? "" : "public.f()",
        false,
        false);
  }

  @Test
  void a_domain_inside_an_array_inside_a_composite_is_followed() {
    long target = 1, composite = 2, array = 3, domain = 4, base = 23;
    var rows =
        List.of(
            row("tgt", target, "public.ch", PG, 0, 0, 0),
            row("col", target, "", 0, 0, composite, 0),
            row("edge", composite, "", 0, 0, array, 0),
            row("edge", array, "", 0, 0, domain, 0),
            row("edge", domain, "", 0, 0, base, 0),
            row("dfn", domain, "constraint c on domain public.d", 0, 10, 0, 99));
    var callers = FunctionGrants.ownerContextCallers(rows, REACH);
    assertThat(callers)
        .singleElement()
        .satisfies(
            c -> {
              assertThat(c.kind()).isEqualTo(FunctionGrants.OWNER_CONTEXT);
              assertThat(c.label())
                  .startsWith("constraint c on domain public.d, a type in table public.ch");
              assertThat(c.fn()).isEqualTo(99);
              assertThat(c.owner()).isEqualTo(PG);
            });
  }

  @Test
  void a_target_owned_in_reach_gives_no_owner_context_row() {
    var rows =
        List.of(
            row("tgt", 1, "appsch.ch", APP, 0, 0, 0),
            row("fn", 1, "column k of appsch.ch", 0, 1, 0, 99));
    assertThat(FunctionGrants.ownerContextCallers(rows, REACH)).isEmpty();
  }

  @Test
  void a_row_naming_no_function_is_dropped_and_duplicates_are_one_row() {
    var rows =
        List.of(
            row("tgt", 1, "public.ch", PG, 0, 0, 0),
            row("fn", 1, "column k of public.ch", 0, 1, 0, 0),
            row("fn", 1, "column k of public.ch", 0, 1, 0, 99),
            row("fn", 1, "column k of public.ch", 0, 1, 0, 99));
    assertThat(FunctionGrants.ownerContextCallers(rows, REACH)).hasSize(1);
  }

  @Test
  void closure_stops_on_a_cycle() {
    var edges = Map.of(1L, Set.of(2L), 2L, Set.of(1L, 3L));
    assertThat(FunctionGrants.closure(Set.of(1L), edges)).containsExactly(1L, 2L, 3L);
  }

  @Test
  void every_owner_context_slot_is_owner_checked() {
    for (int slot = 1;
        slot <= FunctionGrants.SLOTS.get(FunctionGrants.OWNER_CONTEXT).size();
        slot++) {
      assertThat(FunctionGrants.ownerChecked(FunctionGrants.OWNER_CONTEXT, slot)).isTrue();
      assertThat(FunctionGrants.noCheck(FunctionGrants.OWNER_CONTEXT, slot)).isFalse();
    }
  }
}
