package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.adapter.jdbc.FunctionGrantsSql.ExecuteFact;
import com.housedevinci.shredding.adapter.jdbc.FunctionGrantsSql.RecordFact;
import com.housedevinci.shredding.adapter.jdbc.PinnedCatalogue.CoreNative;
import com.housedevinci.shredding.adapter.jdbc.PinnedCatalogue.Member;
import com.housedevinci.shredding.adapter.jdbc.PinnedCatalogue.Version;
import com.housedevinci.shredding.adapter.jdbc.PinnedCatalogue.Withheld;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * The rules of the function-grants leg (C-PR45-3) over synthetic facts, with no database: each case
 * is one row of statement 1 or 2 as the server would return it.
 */
class FunctionGrantsRulesTest {

  private static final long APP = 16_500;
  private static final long OWNER = 10;

  /** A pinned catalogue shaped like the 16 pin, cut down to what the cases need. */
  private static PinnedCatalogue catalogue() {
    return PinnedCatalogue.of(
        16,
        List.of(
            new Withheld(
                765,
                "pg_catalog.lo_export(oid, text)",
                "lo_export(oid,text)",
                "be_lo_export",
                false,
                "@owner=X"),
            new Withheld(
                2622,
                "pg_catalog.pg_rotate_logfile()",
                "pg_rotate_logfile()",
                "pg_rotate_logfile_v2",
                false,
                "@owner=X")),
        List.of(
            new Member("adminpack", "1.1", "pg_logfile_rotate()", "pg_rotate_logfile", false, true),
            new Member(
                "adminpack",
                "2.0",
                "pg_file_write(text,text,bool)",
                "pg_file_write_v1_1",
                false,
                true),
            new Member("pgstattuple", "1.4", "pgstattuple(text)", "pgstattuple", false, false),
            new Member("pgstattuple", "1.5", "pgstattuple(text)", "pgstattuple_v1_5", false, true),
            new Member("dblink", "1.2", "dblink_connect(text)", "dblink_connect", false, false),
            new Member("dblink", "1.2", "dblink_connect_u(text)", "dblink_connect", true, true)),
        List.of(
            new Version("adminpack", "1.1", true, ""),
            new Version("adminpack", "2.0", true, ""),
            new Version("dblink", "1.2", true, ""),
            new Version("pgstattuple", "1.4", true, ""),
            new Version("pgstattuple", "1.5", true, ""),
            new Version("plperl", "1.0", false, "could not load library \"plperl.so\"")),
        List.of(
            new CoreNative(
                "pg_catalog.pg_rotate_logfile_old()",
                "internal",
                "pg_rotate_logfile",
                "-",
                false)));
  }

  /** A native function PUBLIC may execute, outside any extension, owned by the superuser. */
  private static ExecuteFact fn(long oid, String label, String symbol) {
    return new ExecuteFact(
        oid,
        label,
        OptionalLong.of(0),
        "",
        false,
        true,
        "c",
        symbol,
        false,
        "",
        "",
        label,
        OWNER,
        "postgres",
        "f",
        "");
  }

  private static ExecuteFact with(ExecuteFact f, String field, Object value) {
    return new ExecuteFact(
        field.equals("oid") ? (Long) value : f.oid(),
        f.label(),
        field.equals("grantee") ? (OptionalLong) value : f.grantee(),
        field.equals("privtype") ? (String) value : f.privtype(),
        field.equals("shippedPublic") ? (Boolean) value : f.shippedPublic(),
        f.nativeCode(),
        field.equals("language") ? (String) value : f.language(),
        f.symbol(),
        field.equals("secdef") ? (Boolean) value : f.securityDefiner(),
        field.equals("extension") ? ((String[]) value)[0] : f.extension(),
        field.equals("extension") ? ((String[]) value)[1] : f.version(),
        field.equals("key") ? (String) value : f.key(),
        field.equals("owner") ? (Long) value : f.owner(),
        f.ownerName(),
        field.equals("kind") ? (String) value : f.kind(),
        field.equals("library") ? (String) value : f.library());
  }

  private static List<FunctionGrants.ExecuteRow> judge(List<String> accepted, ExecuteFact... f) {
    return FunctionGrants.judgeExecutes(List.of(f), catalogue(), accepted, Set.of(APP), Map.of());
  }

  private static List<FunctionGrants.ExecuteRow> judge(ExecuteFact... f) {
    return judge(List.of(), f);
  }

  /** The W row for lo_export: a baseline oid, nobody of interest may execute it. */
  private static ExecuteFact loExport() {
    return with(
        with(fn(765, "pg_catalog.lo_export(oid, text)", "be_lo_export"), "language", "internal"),
        "grantee",
        OptionalLong.empty());
  }

  @Test
  void a_withheld_function_granted_to_public_is_leg_1() {
    var rows = judge(with(loExport(), "grantee", OptionalLong.of(0)));
    assertThat(rows).singleElement().satisfies(r -> assertThat(r.leg()).isEqualTo(1));
  }

  @Test
  void an_owner_in_reach_of_a_withheld_function_is_leg_1_with_the_owner_text() {
    var owned = with(with(loExport(), "owner", APP), "grantee", OptionalLong.of(APP));
    var rows = judge(owned);
    assertThat(rows).singleElement().satisfies(r -> assertThat(r.granteeOwns()).isTrue());
  }

  @Test
  void a_function_whose_shipped_record_gives_public_execute_is_not_in_w() {
    // Mutation 8: W is only what the record withholds. A member shipped to PUBLIC with an explicit
    // record is not withheld, so PUBLIC on it is no leg 1 row, and its symbol makes no alias.
    var shipped =
        with(
            with(
                with(fn(17_200, "public.pgstattuple(text)", "pgstattuple"), "privtype", "e"),
                "shippedPublic",
                true),
            "extension",
            new String[] {"pgstattuple", "1.4"});
    var keyed = with(shipped, "key", "pgstattuple(text)");
    var copy = fn(20_100, "public.copy(text)", "pgstattuple");
    assertThat(judge(keyed)).isEmpty();
    // C-RC021-2: leg 4 gives one line per function, whatever its grants, from judgeHandMade; the
    // per-grantee rows stay empty, so an alias (leg 2) row would still show here.
    assertThat(judge(keyed, copy)).isEmpty();
    assertThat(FunctionGrants.judgeHandMade(List.of(keyed, copy)))
        .containsExactly("public.copy(text)");
  }

  @Test
  void a_caller_rights_alias_of_a_withheld_symbol_is_leg_2() {
    var rows = judge(loExport(), fn(20_000, "public.save_blob(oid, text)", "be_lo_export"));
    assertThat(rows)
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.leg()).isEqualTo(2);
              assertThat(r.sameAs()).isEqualTo("pg_catalog.lo_export(oid, text)");
            });
  }

  @Test
  void a_security_definer_function_is_never_an_alias_and_its_copy_is_not_one_either() {
    // F16: dblink_connect beside dblink_connect_u. The W function is SECURITY DEFINER, so a
    // caller-rights function with its symbol runs the C code's own checks.
    var connectU =
        with(
            with(
                with(
                    with(
                        fn(17_000, "public.dblink_connect_u(text)", "dblink_connect"),
                        "secdef",
                        true),
                    "privtype",
                    "e"),
                "grantee",
                OptionalLong.empty()),
            "extension",
            new String[] {"dblink", "1.2"});
    var connect =
        with(
            with(
                fn(17_001, "public.dblink_connect(text)", "dblink_connect"),
                "key",
                "dblink_connect(text)"),
            "extension",
            new String[] {"dblink", "1.2"});
    var keyed = with(connectU, "key", "dblink_connect_u(text)");
    assertThat(judge(keyed, connect)).isEmpty();
  }

  @Test
  void a_core_internal_function_is_compared_with_the_initdb_part_of_w_only() {
    // F47: core pg_rotate_logfile_old() shares its symbol with adminpack 1.1 pg_logfile_rotate().
    var extW =
        with(
            with(
                with(
                    fn(17_100, "public.pg_logfile_rotate()", "pg_rotate_logfile"), "privtype", "e"),
                "grantee",
                OptionalLong.empty()),
            "extension",
            new String[] {"adminpack", "1.1"});
    var core =
        with(
            fn(4099, "pg_catalog.pg_rotate_logfile_old()", "pg_rotate_logfile"),
            "language",
            "internal");
    assertThat(judge(with(extW, "key", "pg_logfile_rotate()"), core)).isEmpty();
  }

  @Test
  void a_core_function_rewritten_to_language_c_is_compared_with_all_of_w() {
    // C-PR45-3-16: CREATE OR REPLACE keeps oid 4099 but makes it language c over a withheld symbol.
    var extW =
        with(
            with(
                with(
                    fn(17_100, "public.pg_file_write(text, text, boolean)", "pg_file_write_v1_1"),
                    "privtype",
                    "e"),
                "grantee",
                OptionalLong.empty()),
            "extension",
            new String[] {"adminpack", "2.0"});
    var rewritten = fn(4099, "pg_catalog.pg_rotate_logfile_old()", "pg_file_write_v1_1");
    assertThat(judge(extW, rewritten))
        .singleElement()
        .satisfies(r -> assertThat(r.leg()).isEqualTo(2));
  }

  @Test
  void a_native_security_definer_function_is_leg_3() {
    var rows =
        judge(with(fn(20_001, "public.rawpage(text, bigint)", "get_raw_page_1_9"), "secdef", true));
    assertThat(rows).singleElement().satisfies(r -> assertThat(r.leg()).isEqualTo(3));
  }

  @Test
  void a_native_function_made_by_hand_outside_any_extension_is_r3() {
    var f = fn(20_002, "public.write_any(text, text, boolean)", "custom_symbol");
    // C-RC021-2: leg 4 is one line per function from judgeHandMade, never a per-grantee row.
    assertThat(judge(f)).isEmpty();
    assertThat(FunctionGrants.judgeHandMade(List.of(f)))
        .containsExactly("public.write_any(text, text, boolean)");
  }

  @Test
  void leg_4_closure_gives_one_line_per_hand_made_native_function_whatever_its_grants() {
    // C-RC021-2, ruling 2: a revoked function (no grantee row) still refuses; two grantee rows of
    // one function give one line; core, extension members and aggregates are not leg 4; oid order.
    var revoked = with(fn(20_010, "public.b()", "b_sym"), "grantee", OptionalLong.empty());
    var granted = fn(20_005, "public.a()", "a_sym");
    var grantedTwice = with(granted, "grantee", OptionalLong.of(OWNER));
    var core = fn(12_500, "pg_catalog.x()", "x_sym");
    var member = with(fn(20_020, "public.m()", "m_sym"), "extension", new String[] {"e", "1"});
    var aggregate = with(fn(20_030, "public.g(int4)", "g_sym"), "kind", "a");
    assertThat(
            FunctionGrants.judgeHandMade(
                List.of(revoked, granted, grantedTwice, core, member, aggregate)))
        .containsExactly("public.a()", "public.b()");
  }

  @Test
  void a_core_function_below_16384_is_not_r3() {
    assertThat(judge(with(fn(12_500, "pg_catalog.x()", "x_sym"), "language", "internal")))
        .isEmpty();
  }

  @Test
  void r5a_case_1_refuses_a_member_whose_pinned_entry_is_withheld() {
    var f =
        with(
            with(
                fn(20_003, "pg_catalog.pg_file_write(text, text, boolean)", "pg_file_write_v1_1"),
                "key",
                "pg_file_write(text,text,bool)"),
            "extension",
            new String[] {"adminpack", "2.0"});
    assertThat(judge(f))
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.leg()).isEqualTo(5);
              assertThat(r.sub()).isEqualTo(1);
            });
  }

  @Test
  void r5a_case_2_refuses_another_name_over_a_withheld_symbol_of_the_installed_version() {
    var f =
        with(
            with(
                fn(20_004, "public.fw2(text, text, boolean)", "pg_file_write_v1_1"),
                "key",
                "fw2(text,text,bool)"),
            "extension",
            new String[] {"adminpack", "2.0"});
    assertThat(judge(f)).singleElement().satisfies(r -> assertThat(r.sub()).isEqualTo(2));
  }

  @Test
  void r5a_case_3_refuses_a_baseline_symbol_inside_any_extension() {
    var f =
        with(
            with(fn(20_005, "public.blob(oid, text)", "be_lo_export"), "key", "blob(oid,text)"),
            "extension",
            new String[] {"dblink", "1.2"});
    // Without the W row of lo_export in the facts, leg 2 cannot see it: R5a still does.
    assertThat(judge(f))
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.leg()).isEqualTo(5);
              assertThat(r.sub()).isEqualTo(3);
            });
  }

  @Test
  void r5a_case_4_refuses_a_withheld_contrib_symbol_inside_an_accepted_extension() {
    var f =
        with(
            with(
                fn(20_006, "public.tpw(text, text, boolean)", "pg_file_write_v1_1"),
                "key",
                "tpw(text,text,bool)"),
            "extension",
            new String[] {"tp", "1.0"});
    var rows = judge(List.of("tp"), f);
    assertThat(rows).singleElement().satisfies(r -> assertThat(r.sub()).isEqualTo(4));
    String message = FunctionGrantMessages.held(rows.get(0), "PUBLIC", "PUBLIC", catalogue());
    assertThat(message)
        .contains("adminpack 2.0 pg_file_write(text,text,bool)")
        .contains("revoke EXECUTE on it from PUBLIC and from every role in reach")
        .contains("Accepting the extension does not relax this");
  }

  @Test
  void r5b_i_refuses_an_older_version_recreated_with_the_newer_symbol() {
    var f =
        with(
            with(
                fn(20_007, "public.pgstattuple(text)", "pgstattuple_v1_5"),
                "key",
                "pgstattuple(text)"),
            "extension",
            new String[] {"pgstattuple", "1.4"});
    assertThat(judge(f))
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.leg()).isEqualTo(6);
              assertThat(r.sub()).isEqualTo(1);
            });
  }

  @Test
  void the_installed_version_entry_verifies_an_older_version_shipped_public() {
    var f =
        with(
            with(fn(20_008, "public.pgstattuple(text)", "pgstattuple"), "key", "pgstattuple(text)"),
            "extension",
            new String[] {"pgstattuple", "1.4"});
    assertThat(judge(f)).isEmpty();
  }

  @Test
  void r5b_ii_refuses_a_third_party_extension_until_it_is_accepted() {
    var f =
        with(
            with(
                fn(20_009, "public.l2_distance(vector, vector)", "l2_distance"),
                "key",
                "l2_distance(vector,vector)"),
            "extension",
            new String[] {"vector", "0.8.0"});
    assertThat(judge(f)).singleElement().satisfies(r -> assertThat(r.sub()).isEqualTo(2));
    assertThat(judge(List.of("vector"), f)).isEmpty();
    assertThat(FunctionGrantMessages.held(judge(f).get(0), "PUBLIC", "PUBLIC", catalogue()))
        .contains("third-party extension vector")
        .contains(FunctionGrantMessages.PROPERTY);
  }

  @Test
  void a_listed_but_uninstallable_extension_is_judged_like_a_third_party_one() {
    var f =
        with(
            with(
                fn(20_010, "pg_catalog.plperl_call_handler()", "plperl_call_handler"),
                "key",
                "plperl_call_handler()"),
            "extension",
            new String[] {"plperl", "1.0"});
    var rows = judge(f);
    assertThat(FunctionGrantMessages.held(rows.get(0), "PUBLIC", "PUBLIC", catalogue()))
        .contains("lists but cannot install");
    assertThat(judge(List.of("plperl"), f)).isEmpty();
  }

  @Test
  void a_shipped_extension_at_an_unlisted_version_is_left_to_r5v() {
    var f =
        with(
            with(
                fn(20_011, "public.pgstattuple(text)", "pgstattuple_v1_9"),
                "key",
                "pgstattuple(text)"),
            "extension",
            new String[] {"pgstattuple", "1.9"});
    assertThat(judge(f)).isEmpty();
  }

  @Test
  void an_aggregate_owned_by_a_role_in_reach_is_not_judged_as_code() {
    var agg =
        with(
            with(
                with(fn(20_012, "shadow.count()", "aggregate_dummy"), "language", "internal"),
                "kind",
                "a"),
            "owner",
            APP);
    assertThat(judge(agg)).isEmpty();
  }

  @Test
  void an_aggregate_owned_outside_reach_is_judged_by_r6_not_by_r3() {
    // Revision 5 replaces the interim accident: an aggregate runs no code of its own (symbol
    // aggregate_dummy), so R3 does not apply; R6 judges the functions it calls.
    var agg =
        with(
            with(fn(20_013, "public.readall(boolean)", "aggregate_dummy"), "language", "internal"),
            "kind",
            "a");
    assertThat(judge(agg)).isEmpty();
  }

  @Test
  void each_function_and_grantee_pair_is_reported_once_by_its_lowest_leg() {
    // A W function that is also SECURITY DEFINER and made by hand: leg 1 only.
    var f =
        with(
            with(with(fn(20_014, "public.w()", "w_sym"), "privtype", "e"), "secdef", true),
            "shippedPublic",
            false);
    var both = new ArrayList<ExecuteFact>(List.of(f, with(f, "grantee", OptionalLong.of(APP))));
    var rows = FunctionGrants.judgeExecutes(both, catalogue(), List.of(), Set.of(APP), Map.of());
    assertThat(rows).hasSize(2).allSatisfy(r -> assertThat(r.leg()).isEqualTo(1));
  }

  // ------------------------------------------------------------------ statement 1

  private static RecordFact rec(long oid, String privtype, String acl, String signature) {
    return new RecordFact(
        "fn",
        oid,
        privtype,
        acl,
        acl.contains("PUBLIC"),
        acl.contains("late"),
        true,
        signature,
        "",
        "",
        false,
        "",
        "",
        "");
  }

  private static RecordFact ext(String name, String version, String targets) {
    return new RecordFact(
        "ext", 30_000, "", "", false, false, false, "", "", "", false, name, version, targets);
  }

  private static List<String> rules(RecordFact... facts) {
    return FunctionGrants.judgeRecords(List.of(facts), catalogue()).stream()
        .map(FunctionGrants.RecordRow::rule)
        .toList();
  }

  private static RecordFact rotate() {
    return rec(2622, "i", "@owner=X", "pg_catalog.pg_rotate_logfile()");
  }

  @Test
  void the_intact_record_gives_no_row() {
    assertThat(rules(rec(765, "i", "@owner=X", "pg_catalog.lo_export(oid, text)"), rotate()))
        .isEmpty();
  }

  @Test
  void r0_refuses_a_baseline_oid_with_another_signature_or_no_function() {
    assertThat(rules(rec(765, "i", "@owner=X", "pg_catalog.foo(text)"), rotate()))
        .containsExactly("R0");
    assertThat(rules(rotate())).containsExactly("R0");
  }

  @Test
  void r1_refuses_a_missing_changed_or_unknown_initdb_record() {
    assertThat(rules(rec(765, "", "", "pg_catalog.lo_export(oid, text)"), rotate()))
        .containsExactly("R1-missing");
    assertThat(
            rules(
                rec(765, "i", "pg_monitor=X,@owner=X", "pg_catalog.lo_export(oid, text)"),
                rotate()))
        .containsExactly("R1-changed");
    assertThat(
            rules(
                rec(765, "i", "@owner=X", "pg_catalog.lo_export(oid, text)"),
                rotate(),
                rec(999, "i", "@owner=X", "pg_catalog.extra()")))
        .containsExactly("R1-unknown");
  }

  @Test
  void r2_refuses_public_or_a_late_role_in_an_initdb_record() {
    assertThat(
            rules(rec(765, "i", "@owner=X,PUBLIC=X", "pg_catalog.lo_export(oid, text)"), rotate()))
        .contains("R1-changed", "R2");
  }

  @Test
  void r4_refuses_an_extension_record_that_spells_public() {
    assertThat(
            rules(
                rec(765, "i", "@owner=X", "pg_catalog.lo_export(oid, text)"),
                rotate(),
                rec(17_000, "e", "@owner=X,PUBLIC=X", "public.pg_file_write(text, text, boolean)")))
        .containsExactly("R4");
  }

  @Test
  void r5v_refuses_an_unlisted_version_and_names_the_update_remedy_for_an_update_source() {
    var intact = List.of(rec(765, "i", "@owner=X", "pg_catalog.lo_export(oid, text)"), rotate());
    var newer = new ArrayList<>(intact);
    newer.add(ext("pgstattuple", "1.9", ""));
    var rows = FunctionGrants.judgeRecords(newer, catalogue());
    assertThat(rows).singleElement().satisfies(r -> assertThat(r.rule()).isEqualTo("R5v"));
    assertThat(FunctionGrantMessages.version(rows.get(0), catalogue()))
        .contains("installed at version 1.9")
        .contains("A module release with that version in its manifest fixes it");

    var older = new ArrayList<>(intact);
    older.add(ext("pgstattuple", "1.3", "1.4\t1.5"));
    var source = FunctionGrants.judgeRecords(older, catalogue());
    assertThat(FunctionGrantMessages.version(source.get(0), catalogue()))
        .contains("ALTER EXTENSION pgstattuple UPDATE");

    var thirdParty = new ArrayList<>(intact);
    thirdParty.add(ext("vector", "0.8.0", ""));
    assertThat(FunctionGrants.judgeRecords(thirdParty, catalogue())).isEmpty();
  }

  @Test
  void a_normal_form_acl_is_sorted_by_byte_order() {
    assertThat(FunctionGrants.normalAcl("pg_monitor=X,@owner=X"))
        .isEqualTo("@owner=X,pg_monitor=X");
    assertThat(FunctionGrants.normalAcl("")).isEmpty();
  }

  // ------------------------------------------------------------------ files and the list

  @Test
  void the_shipped_files_load_for_each_shipped_major_and_for_no_other() {
    for (int major : PinnedCatalogue.shippedMajors()) {
      var c = PinnedCatalogue.forMajor(major).orElseThrow();
      assertThat(c.baseline()).hasSize(62);
      assertThat(c.manifest()).hasSizeGreaterThan(3_000);
    }
    assertThat(PinnedCatalogue.forMajor(18)).isEmpty();
    assertThat(PinnedCatalogue.forMajor(15)).isEmpty();
  }

  @Test
  void missing_or_malformed_pinned_file_refuses_with_005() {
    Map<String, String> files = new TreeMap<>();
    files.put(
        PinnedCatalogue.baselineResource(16),
        "765\tpg_catalog.lo_export(oid, text)\tlo_export(oid,text)\tbe_lo_export\tf\t@owner=X\n");
    files.put(PinnedCatalogue.versionsResource(16), "dblink\t1.2\tok\t\n");
    files.put(
        PinnedCatalogue.coreResource(16),
        "pg_catalog.pg_rotate_logfile_old()\tinternal\tpg_rotate_logfile\t-\tf\n");
    assertThatThrownBy(() -> PinnedCatalogue.load(16, n -> open(files, n)))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE));
    files.put(PinnedCatalogue.manifestResource(16), "dblink\t1.2\tx()\tx\tmaybe\tf\t\n");
    assertThatThrownBy(() -> PinnedCatalogue.load(16, n -> open(files, n)))
        .hasMessageContaining("a flag must be t or f");
    files.put(PinnedCatalogue.manifestResource(16), "");
    assertThatThrownBy(() -> PinnedCatalogue.load(16, n -> open(files, n)))
        .hasMessageContaining("non-empty");
    files.put(PinnedCatalogue.manifestResource(16), "adminpack\t9.9\tx()\tx\tf\tf\t\n");
    assertThatThrownBy(() -> PinnedCatalogue.load(16, n -> open(files, n)))
        .hasMessageContaining("no ok line");
    files.put(PinnedCatalogue.versionsResource(16), "dblink\t1.2\tfails\tpermission denied\n");
    assertThatThrownBy(() -> PinnedCatalogue.load(16, n -> open(files, n)))
        .hasMessageContaining("could not load library");
  }

  @Test
  void a_baseline_oid_of_10000_or_more_is_malformed() {
    assertThatThrownBy(
            () ->
                PinnedCatalogue.parseBaseline("b", "12001\tpg_catalog.f()\tf()\tf\tf\t@owner=X\n"))
        .hasMessageContaining("not fixed by pg_proc.dat");
  }

  @Test
  void a_missing_statement_file_refuses_with_005() {
    assertThatThrownBy(() -> FunctionGrantsSql.resource("function-grants-9.sql"))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE));
    assertThat(FunctionGrantsSql.statementOne()).contains("pg_catalog.pg_init_privs");
    assertThat(FunctionGrantsSql.statementTwo()).contains("pg_catalog.aclexplode");
  }

  @Test
  void the_accepted_list_is_trimmed_and_a_blank_entry_refuses() {
    assertThat(AcceptedExtensions.normalise(List.of(" vector ", "postgis")))
        .containsExactly("vector", "postgis");
    assertThat(AcceptedExtensions.normalise(null)).isEmpty();
    assertThatThrownBy(() -> AcceptedExtensions.normalise(List.of("vector", " ")))
        .isInstanceOfSatisfying(
            ShreddingException.class, e -> assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG))
        .hasMessageContaining("entry 1 is blank");
    assertThat(AcceptedExtensions.warning(List.of("vector"))).contains("limit L20");
  }

  @Test
  void a_manifest_name_in_the_accepted_list_refuses_whatever_its_case() {
    assertThatThrownBy(() -> catalogue().refuseInstallableNames(List.of("AdminPack")))
        .isInstanceOfSatisfying(
            ShreddingException.class, e -> assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG))
        .hasMessageContaining("F41");
  }

  @Test
  void uninstallable_extension_name_may_be_accepted() {
    catalogue().refuseInstallableNames(List.of("plperl", "vector"));
  }

  // ------------------------------------------------------------------ generator

  @Test
  void generator_refuses_an_initdb_oid_of_10000_or_more() {
    var row =
        new PinnedCatalogueGenerator.BaselineRow(
            12_001, "pg_catalog.f()", "f()", "f", false, "@owner=X", false);
    assertThatThrownBy(() -> PinnedCatalogueGenerator.baselineText(List.of(row)))
        .hasMessageContaining("oid 12001 is not fixed by pg_proc.dat");
  }

  @Test
  void generator_refuses_an_unexpected_install_error() {
    assertThatThrownBy(
            () ->
                PinnedCatalogueGenerator.version(
                    "pg_stat_statements",
                    "1.11",
                    Optional.of("permission denied to create \"pg_catalog.pg_stat_statements\"")))
        .isInstanceOf(PinnedCatalogueGenerator.Refused.class);
  }

  @Test
  void generator_refuses_a_core_exemption_that_would_give_a_symbol_away() {
    var none = List.<ExecuteFact>of();
    assertThatThrownBy(
            () ->
                PinnedCatalogueGenerator.proveCoreExemption(
                    none,
                    catalogue(),
                    Map.of("pg_rotate_logfile", "adminpack 1.1 pg_logfile_rotate()")))
        .isInstanceOf(PinnedCatalogueGenerator.Refused.class);
    var core =
        with(
            fn(4099, "pg_catalog.pg_rotate_logfile_old()", "pg_rotate_logfile"),
            "language",
            "internal");
    PinnedCatalogueGenerator.proveCoreExemption(
        List.of(core),
        catalogue(),
        Map.of("pg_rotate_logfile", "adminpack 1.1 pg_logfile_rotate()"));
  }

  private static java.io.InputStream open(Map<String, String> files, String name) {
    String text = files.get(name);
    return text == null ? null : new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
  }

  // ------------------------------------------------------------------ R6, caller objects

  private static FunctionGrantsSql.CallerFact caller(String kind, long owner, int slot, long fn) {
    return new FunctionGrantsSql.CallerFact(
        kind,
        30_000,
        "public.agg(boolean)",
        owner,
        "postgres",
        true,
        slot,
        fn,
        "k(text)",
        "public.k(text)",
        false,
        true);
  }

  private static List<FunctionGrants.CallerRow> judgeCallers(FunctionGrantsSql.CallerFact c) {
    return FunctionGrants.judgeCallers(
        List.of(c), List.of(loExport()), catalogue(), List.of(), Set.of(APP));
  }

  @Test
  void r6_refuses_an_aggregate_owned_outside_reach_over_a_withheld_function() {
    assertThat(judgeCallers(caller("agg", OWNER, 1, 765)))
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.leg()).isEqualTo(1);
              assertThat(r.slot()).isEqualTo("transfn");
              assertThat(r.function()).isEqualTo("pg_catalog.lo_export(oid, text)");
            });
  }

  @Test
  void r6_skips_an_object_owned_in_reach_or_usable_by_nobody_in_reach() {
    assertThat(judgeCallers(caller("agg", APP, 1, 765))).isEmpty();
    var unusable = caller("agg", OWNER, 1, 765);
    assertThat(
            judgeCallers(
                new FunctionGrantsSql.CallerFact(
                    "agg",
                    30_000,
                    "a",
                    OWNER,
                    "postgres",
                    false,
                    1,
                    765,
                    "k(text)",
                    "public.k(text)",
                    false,
                    true)))
        .isEmpty();
    assertThat(unusable.usable()).isTrue();
  }

  @Test
  void r6_judges_a_no_check_slot_whoever_owns_the_object() {
    // C-PR47-1: the owner skip is for owner-checked (aggregate) slots only.
    assertThat(FunctionGrants.ownerChecked("agg", 1)).isTrue();
    assertThat(FunctionGrants.ownerChecked("lang", 3)).isFalse();
    assertThat(FunctionGrants.ownerChecked("opr", 2)).isFalse();
    assertThat(judgeCallers(caller("opr", APP, 1, 765))).isEmpty();
    assertThat(judgeCallers(caller("opr", APP, 2, 765))).hasSize(1);
    assertThat(judgeCallers(caller("opr", APP, 3, 765))).hasSize(1);
    for (int slot = 1; slot <= 3; slot++) {
      assertThat(judgeCallers(caller("lang", APP, slot, 765))).hasSize(1);
    }
    var row = judgeCallers(caller("lang", APP, 3, 765)).get(0);
    assertThat(FunctionGrantMessages.caller(row, catalogue()))
        .contains("owned by postgres, whose validator")
        .doesNotContain("outside reach");
  }

  private static FunctionGrantsSql.CallerFact wrapper(
      String kind, long owner, int slot, boolean definer, boolean reachMayRun) {
    return new FunctionGrantsSql.CallerFact(
        kind,
        30_000,
        "public.agg(boolean)",
        owner,
        "postgres",
        true,
        slot,
        99_999,
        "w(text)",
        "public.w(text)",
        definer,
        reachMayRun);
  }

  @Test
  void r6_refuses_a_slot_function_that_is_a_revoked_security_definer_wrapper() {
    // C-PR47-2: statement 2 has no row for the wrapper (oid 99999); its own facts decide.
    assertThat(judgeCallers(wrapper("agg", OWNER, 1, true, false)))
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.leg()).isEqualTo(7);
              assertThat(r.function()).isEqualTo("public.w(text)");
            });
    assertThat(judgeCallers(wrapper("lang", APP, 3, true, false))).hasSize(1);
    assertThat(judgeCallers(wrapper("agg", OWNER, 1, true, true))).isEmpty();
    assertThat(judgeCallers(wrapper("agg", OWNER, 1, false, false))).isEmpty();
    assertThat(judgeCallers(wrapper("agg", APP, 1, true, false))).isEmpty();
    assertThat(judgeCallers(wrapper("opr", OWNER, 1, true, false))).isEmpty();
    var row = judgeCallers(wrapper("agg", OWNER, 1, true, false)).get(0);
    assertThat(FunctionGrantMessages.caller(row, catalogue()))
        .contains("whose transfn is function public.w(text)")
        .contains(
            "SECURITY DEFINER function that neither PUBLIC nor a role whose rights the login may use may execute");
  }

  @Test
  void r6_skips_operator_code_and_judges_estimators_and_every_language_slot() {
    assertThat(judgeCallers(caller("opr", OWNER, 1, 765))).isEmpty();
    assertThat(judgeCallers(caller("opr", OWNER, 2, 765))).hasSize(1);
    assertThat(judgeCallers(caller("opr", OWNER, 3, 765))).hasSize(1);
    for (int slot = 1; slot <= 3; slot++) {
      assertThat(judgeCallers(caller("lang", OWNER, slot, 765))).hasSize(1);
    }
  }

  @Test
  void r6_judges_all_eight_aggregate_slots_and_skips_a_function_it_has_no_fact_for() {
    for (int slot = 1; slot <= 8; slot++) {
      int s = slot;
      assertThat(judgeCallers(caller("agg", OWNER, slot, 765)))
          .singleElement()
          .satisfies(
              r -> assertThat(r.slot()).isEqualTo(FunctionGrants.SLOTS.get("agg").get(s - 1)));
    }
    assertThat(judgeCallers(caller("agg", OWNER, 1, 99_999))).isEmpty();
  }

  @Test
  void r6_message_names_object_owner_slot_function_and_reason() {
    var row = judgeCallers(caller("lang", OWNER, 3, 765)).get(0);
    assertThat(FunctionGrantMessages.caller(row, catalogue()))
        .contains("may create functions in language public.agg(boolean), owned by postgres")
        .contains("whose validator is function pg_catalog.lo_export(oid, text)")
        .contains("ships without EXECUTE for PUBLIC");
  }

  @Test
  void supports_joins_each_aggregate_slot_in_order_and_ignores_other_objects() {
    var rows =
        List.of(
            new FunctionGrantsSql.CallerFact(
                "agg", 1, "a", 10, "p", true, 3, 5, "c(x,x)", "s.f(x)", false, true),
            new FunctionGrantsSql.CallerFact(
                "agg", 1, "a", 10, "p", true, 1, 4, "t(x,y)", "s.f(x)", false, true),
            new FunctionGrantsSql.CallerFact(
                "opr", 2, "o", 10, "p", true, 1, 6, "e(x,x)", "s.f(x)", false, true));
    assertThat(FunctionGrants.supports(rows))
        .isEqualTo(Map.of(1L, "transfn=t(x,y);combinefn=c(x,x)"));
  }

  @Test
  void a_shipped_aggregate_with_other_support_functions_is_not_as_shipped() {
    var cat =
        PinnedCatalogue.of(
            16,
            catalogue().baseline(),
            List.of(
                new Member(
                    "citext",
                    "1.6",
                    "min(citext)",
                    "aggregate_dummy",
                    false,
                    false,
                    "transfn=citext_smaller(citext,citext)")),
            List.of(new Version("citext", "1.6", true, "")),
            catalogue().core());
    var agg =
        with(
            with(
                with(fn(20_020, "public.min(citext)", "aggregate_dummy"), "kind", "a"),
                "key",
                "min(citext)"),
            "extension",
            new String[] {"citext", "1.6"});
    var shipped = Map.of(20_020L, "transfn=citext_smaller(citext,citext)");
    var other = Map.of(20_020L, "transfn=citext_larger(citext,citext)");
    assertThat(FunctionGrants.judgeExecutes(List.of(agg), cat, List.of(), Set.of(APP), shipped))
        .isEmpty();
    assertThat(FunctionGrants.judgeExecutes(List.of(agg), cat, List.of(), Set.of(APP), other))
        .singleElement()
        .satisfies(r -> assertThat(r.leg()).isEqualTo(6));
  }

  // ------------------------------------------------------------------ R7, core record

  private static ExecuteFact core(String label, String language, String symbol, String library) {
    return with(
        with(with(fn(4099, label, symbol), "language", language), "library", library),
        "grantee",
        OptionalLong.empty());
  }

  @Test
  void r7_accepts_a_core_function_as_shipped() {
    var f = core("pg_catalog.pg_rotate_logfile_old()", "internal", "pg_rotate_logfile", "");
    assertThat(FunctionGrants.judgeCore(List.of(f), catalogue())).isEmpty();
  }

  @Test
  void r7_refuses_a_core_function_rewritten_in_language_symbol_library_or_rights() {
    String sig = "pg_catalog.pg_rotate_logfile_old()";
    var c = catalogue();
    assertThat(FunctionGrants.judgeCore(List.of(core(sig, "c", "pg_rotate_logfile", "x")), c))
        .singleElement()
        .satisfies(
            l -> assertThat(l).contains("is language c, symbol pg_rotate_logfile, library x"));
    assertThat(FunctionGrants.judgeCore(List.of(core(sig, "internal", "other", "")), c)).hasSize(1);
    assertThat(
            FunctionGrants.judgeCore(List.of(core(sig, "internal", "pg_rotate_logfile", "lib")), c))
        .hasSize(1);
    var definer = with(core(sig, "internal", "pg_rotate_logfile", ""), "secdef", true);
    assertThat(FunctionGrants.judgeCore(List.of(definer), c)).hasSize(1);
  }

  @Test
  void r7_refuses_a_missing_core_function_and_an_unrecorded_one_and_ignores_others() {
    var c = catalogue();
    assertThat(FunctionGrants.judgeCore(List.of(), c))
        .singleElement()
        .satisfies(l -> assertThat(l).contains("is missing on this server"));
    var asShipped = core("pg_catalog.pg_rotate_logfile_old()", "internal", "pg_rotate_logfile", "");
    var unknown = with(core("pg_catalog.f()", "internal", "f", ""), "oid", 4100L);
    assertThat(FunctionGrants.judgeCore(List.of(asShipped, unknown), c))
        .singleElement()
        .satisfies(l -> assertThat(l).contains("is not in the PostgreSQL 16 core record"));
    var normal = with(core("public.f()", "c", "f", "x"), "oid", 20_000L);
    var member = with(core("public.g()", "c", "g", "x"), "extension", new String[] {"e", "1"});
    var added =
        with(
            core("pg_catalog.pg_rotate_logfile_old()", "internal", "pg_rotate_logfile", ""),
            "extension",
            new String[] {"e", "1"});
    assertThat(FunctionGrants.judgeCore(List.of(added), c)).isEmpty();
    assertThat(FunctionGrants.judgeCore(List.of(asShipped, normal, member), c)).isEmpty();
  }

  @Test
  void a_malformed_core_record_or_support_column_refuses_with_005() {
    assertThatThrownBy(() -> PinnedCatalogue.parseCore("c", "pg_catalog.f()\tsql\tf\t-\tf\n"))
        .hasMessageContaining("internal or c");
    assertThatThrownBy(() -> PinnedCatalogue.parseCore("c", "a()\tc\tf\t-\tf\na()\tc\tg\t-\tf\n"))
        .hasMessageContaining("appears twice");
    assertThatThrownBy(() -> PinnedCatalogue.parseCore("c", "a()\tc\tf\t\tf\n"))
        .hasMessageContaining("an empty column");
    assertThatThrownBy(
            () -> PinnedCatalogue.parseManifest("m", "e\t1\tm(x)\taggregate_dummy\tf\tf\tjunk\n"))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE));
    assertThatThrownBy(
            () ->
                PinnedCatalogue.of(
                    16, catalogue().baseline(), List.of(), catalogue().versions(), List.of()))
        .hasMessageContaining("the core record has no line");
  }
}
