package com.housedevinci.shredding.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.adapter.memory.InMemoryErasureStore;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.HookOutcome;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Audit-table coverage design, section 3c, at the core boundary with no database: the binding of an
 * acknowledged copy to its clearing hook (A4, A5, A6), the retry that answers the outstanding
 * record rather than the configuration (C11, Y1-Y8), unique hook names (Y11), the append rule held
 * by the in-memory store (Y9m) and the rendering every party shares (W5, W6, W7). The clock is
 * fixed on purpose: every record of a test shares one instant, so "latest" can only mean "last
 * appended".
 */
class ErasureServiceAcknowledgementTest {

  private static final byte[] SECRET =
      "acknowledgement-chain-secret-32b".getBytes(StandardCharsets.UTF_8);
  private static final Pseudonymiser PSEUDONYMS = new Pseudonymiser(SECRET);
  private static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-10-06T10:00:00Z"), ZoneOffset.UTC);
  private static final TenantId TENANT = TenantId.of("T1");
  private static final SubjectId SUBJECT = SubjectId.of("s1");
  private static final ErasureRequest REQUEST =
      new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17");
  private static final AcknowledgedCopy TRIGGER =
      AcknowledgedCopy.trigger("public", "note", "note_audit", "scrubber");
  private static final String OBJECT = "trigger \"public\".\"note\".\"note_audit\"";

  private final Set<String> erased = new HashSet<>();
  private final InMemoryErasureStore memory =
      new InMemoryErasureStore(
          ErasureChain.keyed(SECRET, "k1"),
          (t, s) -> erased.add(t.value() + "/" + s.value()) ? new int[] {1, 1} : new int[] {0, 0});

  // ------------------------------------------------------------------------- hooks and stores

  private static PostErasureHook hook(String name, boolean succeeds) {
    return new PostErasureHook() {
      @Override
      public String name() {
        return name;
      }

      @Override
      public void afterErasure(TenantId tenant, SubjectId subject) {
        if (!succeeds) {
          throw new IllegalStateException("downstream unreachable");
        }
      }
    };
  }

  /** The in-memory store, forwarding everything, plus an acknowledgement list. */
  private ErasureStore acknowledging(List<AcknowledgedCopy> copies) {
    return new ErasureStore() {
      @Override
      public Outcome erase(TenantId tenant, SubjectId subject, RecordFactory factory) {
        return memory.erase(tenant, subject, factory);
      }

      @Override
      public List<AcknowledgedCopy> acknowledgedCopies() {
        return copies;
      }

      @Override
      public ErasureRecord append(ErasureRecord record) {
        return memory.append(record);
      }

      @Override
      public Optional<ErasureRecord> latestForSubject(TenantId tenant, String pseudonym) {
        return memory.latestForSubject(tenant, pseudonym);
      }
    };
  }

  private static ErasureService service(ErasureStore store, PostErasureHook... hooks) {
    return new ErasureService(
        store,
        new DataKeyCache(Duration.ofSeconds(60), 10, CLOCK),
        PSEUDONYMS,
        List.of(hooks),
        Duration.ZERO,
        CLOCK,
        1,
        1);
  }

  private static ErasureRecord last(ErasureResult result) {
    return result.records().get(result.records().size() - 1);
  }

  private static ErasureRecord record(ErasureOutcome outcome, HookOutcome... outcomes) {
    return ErasureRecord.of(
        CLOCK.instant(),
        TENANT,
        PSEUDONYMS.pseudonym(TENANT, SUBJECT),
        "dpo",
        "art 17",
        1,
        1,
        1,
        1,
        outcome,
        List.of(outcomes),
        CLOCK.instant());
  }

  /** The security review's scenario up to the config change: erasure PARTIAL on a failing hook. */
  private ErasureResult partialWithBoundHookFailing() {
    ErasureResult first =
        service(acknowledging(List.of(TRIGGER)), hook("scrubber", false)).erase(REQUEST);
    assertThat(first.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(first.records()).hasSize(2);
    return first;
  }

  // ------------------------------------------------------------------------ A4, A5, A6 binding

  @Test
  void a4_entry_without_registered_hook_refused() {
    assertThatThrownBy(() -> service(acknowledging(List.of(TRIGGER)), hook("other", true)))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> {
              assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG);
              assertThat(e.getMessage())
                  .isEqualTo(
                      "shredding: shredding.jdbc.acknowledged-copies[0] has cleared-by=scrubber,"
                          + " and no PostErasureHook has that name. An acknowledged copy needs the"
                          + " hook that clears it, or every erasure would be recorded COMPLETE over"
                          + " it.");
            });
  }

  @Test
  void a5_acknowledged_copy_named_pending_in_first_record_then_cleared() {
    ErasureResult result =
        service(acknowledging(List.of(TRIGGER)), hook("scrubber", true)).erase(REQUEST);

    assertThat(result.records().get(0).outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(result.records().get(0).hookOutcomes())
        .containsExactly(new HookOutcome("scrubber", false, "pending; clears " + OBJECT));
    assertThat(result.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
    assertThat(last(result).hookOutcomes())
        .containsExactly(new HookOutcome("scrubber", true, "clears " + OBJECT));
  }

  @Test
  void a6_failing_clearing_hook_keeps_partial_and_names_the_copy() {
    ErasureResult result = partialWithBoundHookFailing();

    assertThat(last(result).outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(last(result).hookOutcomes())
        .containsExactly(
            new HookOutcome(
                "scrubber", false, "java.lang.IllegalStateException; leaves " + OBJECT));
  }

  // --------------------------------------------------------------------------- C11, Y1 - Y8

  @Test
  void y1_retry_after_bound_hook_removed_stays_partial_and_names_it() {
    partialWithBoundHookFailing();

    // Trigger dropped, entry removed, hook deregistered: nothing in configuration names it now.
    ErasureResult retry = service(memory).erase(REQUEST);

    assertThat(retry.alreadyErased()).isTrue();
    assertThat(retry.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(last(retry).outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(last(retry).hookOutcomes())
        .containsExactly(
            new HookOutcome("scrubber", false, "not registered; outstanding since record 2"));
    assertThat(retry.hookOutcomes()).extracting(HookOutcome::hook).containsExactly("scrubber");
  }

  @Test
  void y2_retry_after_hook_renamed_runs_new_and_keeps_old_name_outstanding() {
    partialWithBoundHookFailing();

    ErasureResult retry = service(memory, hook("scrubberV2", true)).erase(REQUEST);

    assertThat(retry.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(last(retry).hookOutcomes())
        .containsExactly(
            new HookOutcome("scrubber", false, "not registered; outstanding since record 2"),
            HookOutcome.ok("scrubberV2"));
  }

  @Test
  void y3_retry_after_entry_removed_with_hook_kept_answers_by_name() {
    partialWithBoundHookFailing();

    ErasureResult failing = service(memory, hook("scrubber", false)).erase(REQUEST);
    assertThat(failing.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(last(failing).hookOutcomes())
        .containsExactly(HookOutcome.failed("scrubber", "java.lang.IllegalStateException"));

    ErasureResult succeeding = service(memory, hook("scrubber", true)).erase(REQUEST);
    assertThat(succeeding.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
    assertThat(last(succeeding).hookOutcomes()).containsExactly(HookOutcome.ok("scrubber"));
  }

  @Test
  void y4_crash_between_commit_and_hooks_retry_answers_the_pending_names() {
    // The destruction committed with its pending record, and the process died before the hooks.
    memory.erase(
        TENANT,
        SUBJECT,
        (keys, cleared) ->
            record(
                ErasureOutcome.PARTIAL,
                new HookOutcome("scrubber", false, "pending; clears " + OBJECT)));

    ErasureResult retry = service(memory).erase(REQUEST);

    assertThat(retry.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(last(retry).hookOutcomes())
        .containsExactly(
            new HookOutcome("scrubber", false, "not registered; outstanding since record 1"));
  }

  @Test
  void y5_reregistering_the_outstanding_name_closes_the_partial() {
    partialWithBoundHookFailing();
    service(memory).erase(REQUEST);

    ErasureResult closed =
        service(acknowledging(List.of(TRIGGER)), hook("scrubber", true)).erase(REQUEST);

    assertThat(closed.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
    assertThat(last(closed).hookOutcomes())
        .containsExactly(new HookOutcome("scrubber", true, "clears " + OBJECT));
    assertThat(service(memory).erase(REQUEST).outcome()).isEqualTo(ErasureOutcome.COMPLETE);
  }

  @Test
  void y6_second_retry_keeps_the_original_sequence() {
    partialWithBoundHookFailing();
    service(memory).erase(REQUEST);

    ErasureResult second = service(memory).erase(REQUEST);

    assertThat(last(second).sequence()).isEqualTo(4);
    assertThat(last(second).hookOutcomes())
        .containsExactly(
            new HookOutcome("scrubber", false, "not registered; outstanding since record 2"));
  }

  @Test
  void y7_unbound_hook_is_named_pending_in_the_first_record() {
    ErasureResult result = service(memory, hook("searchPurge", true)).erase(REQUEST);

    assertThat(result.records().get(0).hookOutcomes())
        .containsExactly(new HookOutcome("searchPurge", false, "pending"));
    assertThat(result.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
    assertThat(last(result).hookOutcomes()).containsExactly(HookOutcome.ok("searchPurge"));
  }

  @Test
  void y8_record_from_0_1_without_names_keeps_0_1_semantics() {
    // 0.1.x wrote its in-transaction record PARTIAL with no outcome at all.
    memory.erase(TENANT, SUBJECT, (keys, cleared) -> record(ErasureOutcome.PARTIAL));

    ErasureResult failing = service(memory, hook("searchPurge", false)).erase(REQUEST);
    assertThat(failing.outcome()).isEqualTo(ErasureOutcome.PARTIAL);

    ErasureResult none = service(memory).erase(REQUEST);
    assertThat(none.outcome())
        .describedAs("the failed searchPurge of the previous retry is now an outstanding name")
        .isEqualTo(ErasureOutcome.PARTIAL);
  }

  @Test
  void y8_record_from_0_1_without_names_and_no_hooks_completes_as_0_1_did() {
    memory.erase(TENANT, SUBJECT, (keys, cleared) -> record(ErasureOutcome.PARTIAL));

    assertThat(service(memory).erase(REQUEST).outcome()).isEqualTo(ErasureOutcome.COMPLETE);
  }

  // ------------------------------------------------------------------- Y9m, Y10 on memory

  @Test
  void y9m_in_memory_append_refuses_complete_leaving_an_outstanding_name() {
    memory.erase(
        TENANT,
        SUBJECT,
        (keys, cleared) -> record(ErasureOutcome.PARTIAL, new HookOutcome("h1", false, "pending")));
    var anchor = memory.anchor();

    assertThatThrownBy(() -> memory.append(record(ErasureOutcome.COMPLETE)))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e ->
                assertThat(e.getMessage())
                    .isEqualTo(
                        "shredding: refused to append an erasure record for this subject: record 1"
                            + " left hook h1 pending or failed and the new record does not report"
                            + " it."));
    assertThat(memory.all()).hasSize(1);
    assertThat(memory.anchor()).isEqualTo(anchor);
  }

  @Test
  void y10m_in_memory_append_refuses_partial_that_drops_an_outstanding_name() {
    memory.erase(
        TENANT,
        SUBJECT,
        (keys, cleared) -> record(ErasureOutcome.PARTIAL, new HookOutcome("h1", false, "pending")));
    var anchor = memory.anchor();

    assertThatThrownBy(
            () -> memory.append(record(ErasureOutcome.PARTIAL, HookOutcome.failed("h2", "x"))))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("record 1 left hook h1 pending or failed");
    assertThatThrownBy(() -> memory.append(record(ErasureOutcome.COMPLETE)))
        .isInstanceOf(ShreddingException.class);
    assertThatThrownBy(
            () ->
                memory.append(
                    record(ErasureOutcome.COMPLETE, HookOutcome.ok("h1"), HookOutcome.ok("h1"))))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> {
              assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG);
              assertThat(e.getMessage())
                  .isEqualTo(
                      "shredding: refused to append an erasure record for this subject: it"
                          + " reports hook h1 more than once.");
            });
    assertThat(memory.all()).hasSize(1);
    assertThat(memory.anchor()).isEqualTo(anchor);
  }

  @Test
  void c26_1_complete_record_with_a_hook_not_succeeded_is_refused_in_every_form() {
    memory.erase(
        TENANT,
        SUBJECT,
        (keys, cleared) -> record(ErasureOutcome.PARTIAL, new HookOutcome("h1", false, "pending")));
    var anchor = memory.anchor();

    for (HookOutcome notSucceeded :
        List.of(
            HookOutcome.failed("h1", "java.lang.IllegalStateException"),
            HookOutcome.failed("h1", "not registered; outstanding since record 1"),
            new HookOutcome("h1", false, "pending"))) {
      assertThatThrownBy(() -> memory.append(record(ErasureOutcome.COMPLETE, notSucceeded)))
          .isInstanceOfSatisfying(
              ShreddingException.class,
              e ->
                  assertThat(e.getMessage())
                      .isEqualTo(
                          "shredding: refused to append an erasure record for this subject: it is"
                              + " COMPLETE and reports hook h1 as not succeeded. A record is"
                              + " COMPLETE only when every hook it names succeeded."));
    }
    // An unrelated hook that failed cannot ride along on a COMPLETE either.
    assertThatThrownBy(
            () ->
                memory.append(
                    record(
                        ErasureOutcome.COMPLETE,
                        HookOutcome.ok("h1"),
                        HookOutcome.failed("h2", "x"))))
        .hasMessageContaining("reports hook h2 as not succeeded");
    assertThat(memory.all()).hasSize(1);
    assertThat(memory.anchor()).isEqualTo(anchor);
    assertThat(memory.append(record(ErasureOutcome.PARTIAL, HookOutcome.failed("h1", "x"))))
        .extracting(ErasureRecord::outcome)
        .isEqualTo(ErasureOutcome.PARTIAL);
  }

  @Test
  void in_memory_latest_is_the_last_appended_under_one_instant() {
    memory.erase(TENANT, SUBJECT, (keys, cleared) -> record(ErasureOutcome.PARTIAL));
    memory.append(record(ErasureOutcome.COMPLETE));

    assertThat(memory.latestForSubject(TENANT, PSEUDONYMS.pseudonym(TENANT, SUBJECT)))
        .get()
        .extracting(ErasureRecord::outcome)
        .isEqualTo(ErasureOutcome.COMPLETE);
  }

  // ------------------------------------------------------------------------------- Y11

  @Test
  void y11_duplicate_hook_names_refuse_startup() {
    assertThatThrownBy(() -> service(memory, hook("purge", true), hook("purge", false)))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> {
              assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG);
              assertThat(e.getMessage())
                  .isEqualTo(
                      "shredding: two post-erasure hooks are named purge. Hook names identify the"
                          + " step in the erasure trail and must be unique; rename one.");
            });
  }

  @Test
  void y11_blank_or_null_hook_name_refuses_startup() {
    for (String name : new String[] {null, "", "  "}) {
      assertThatThrownBy(() -> service(memory, hook(name, true)))
          .isInstanceOfSatisfying(
              ShreddingException.class,
              e -> assertThat(e.getMessage()).contains("has a null or blank name"));
    }
  }

  @Test
  void y11_names_are_checked_before_the_store_is_read() {
    ErasureStore unreadable =
        new ErasureStore() {
          @Override
          public Outcome erase(TenantId tenant, SubjectId subject, RecordFactory factory) {
            throw new AssertionError();
          }

          @Override
          public List<AcknowledgedCopy> acknowledgedCopies() {
            throw new AssertionError("the store was read before the hook names were checked");
          }

          @Override
          public ErasureRecord append(ErasureRecord record) {
            throw new AssertionError();
          }

          @Override
          public Optional<ErasureRecord> latestForSubject(TenantId tenant, String pseudonym) {
            throw new AssertionError();
          }
        };
    assertThatThrownBy(() -> service(unreadable, hook("x", true), hook("x", true)))
        .isInstanceOf(ShreddingException.class);
  }

  // ------------------------------------------------------------------------ W5, W6, W7

  @Test
  void w5_no_acknowledged_copies_needs_no_pending_outcome() {
    ErasureResult result = service(memory).erase(REQUEST);

    assertThat(result.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
    assertThat(result.records())
        .singleElement()
        .satisfies(r -> assertThat(r.hookOutcomes()).isEmpty());
  }

  @Test
  void w6_two_copies_on_one_hook_in_any_config_order_render_identically() {
    var a = AcknowledgedCopy.trigger("public", "note", "z_audit", "scrubber");
    var b = AcknowledgedCopy.publication("cdc", "scrubber");
    var c = AcknowledgedCopy.trigger("public", "note", "😀_audit", "scrubber");
    var d = AcknowledgedCopy.trigger("public", "note", "�_audit", "scrubber");

    String one = AcknowledgedCopy.describe(List.of(a, b, c, d));
    String two = AcknowledgedCopy.describe(List.of(d, c, b, a));

    assertThat(one).isEqualTo(two);
    assertThat(one)
        .describedAs("kind order first, then code point order: U+FFFD before U+1F600")
        .isEqualTo(
            "trigger \"public\".\"note\".\"z_audit\"; trigger \"public\".\"note\".\"�_audit\";"
                + " trigger \"public\".\"note\".\"😀_audit\"; publication \"cdc\"");
  }

  @Test
  void w7_escape_turns_every_line_breaking_character_into_text() {
    assertThat(LogText.escape("a\nb c d\u0085e\\f\u007Fg\u0000"))
        .isEqualTo("a\\u000Ab\\u2028c\\u2029d\\u0085e\\\\f\\u007Fg\\u0000");
    var odd = AcknowledgedCopy.trigger("public", "note", "x\"y\nz", "scrubber");
    assertThat(odd.object()).isEqualTo("trigger \"public\".\"note\".\"x\"\"y\nz\"");
    assertThat(odd.printable()).isEqualTo("trigger \"public\".\"note\".\"x\"\"y\\u000Az\"");
  }

  // ---------------------------------------------------------------- entry validation (C8)

  @Test
  void entry_shape_is_refused_by_its_index() {
    assertThatThrownBy(() -> AcknowledgedCopy.of(2, "publication", null, "t", "p", "h"))
        .hasMessage(
            "shredding: shredding.jdbc.acknowledged-copies[2] has kind=publication and sets table;"
                + " schema and table belong to kind=trigger only.");
    assertThatThrownBy(() -> AcknowledgedCopy.of(0, "Trigger", "s", "t", "n", "h"))
        .hasMessageContaining(
            "has kind=Trigger; kind is one of trigger, publication," + " replication-slot");
    assertThatThrownBy(() -> AcknowledgedCopy.of(0, "trigger", null, "t", "n", "h"))
        .hasMessageContaining("has kind=trigger and no schema");
    assertThatThrownBy(() -> AcknowledgedCopy.of(0, "trigger", "s", null, "n", "h"))
        .hasMessageContaining("has kind=trigger and no table");
    assertThatThrownBy(() -> AcknowledgedCopy.of(0, "replication-slot", null, null, "", "h"))
        .hasMessageContaining("has no name");
    assertThatThrownBy(() -> AcknowledgedCopy.of(0, "replication-slot", null, null, "s", null))
        .hasMessage(
            "shredding: shredding.jdbc.acknowledged-copies[0] has no cleared-by. An acknowledged"
                + " copy needs the PostErasureHook that clears it, or every erasure would be"
                + " recorded COMPLETE over it.");
    assertThat(AcknowledgedCopy.of(0, "replication-slot", null, null, "s", "h"))
        .isEqualTo(AcknowledgedCopy.replicationSlot("s", "h"));
  }
}
