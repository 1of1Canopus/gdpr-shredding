package com.housedevinci.shredding.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

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
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Security review, PR 26 pass 1, finding C-26-1 on the in-memory store (rev 5 item 4 parity).
 *
 * <p>The append guard ({@code OutstandingHooks.requireAnswered}) accepts any record that holds an
 * outcome for every outstanding name, whatever that outcome is. A record whose outcome is {@code
 * COMPLETE} while it reports the outstanding hook failed, or carried as not registered, therefore
 * passes in one append: the laundering rev 5 item 1 closed for two appends is open for one. Rev 3's
 * guard required a success outcome for a {@code COMPLETE}; rev 5 replaced the bullet and the
 * requirement was lost. After the forged append the subject's latest record is {@code COMPLETE},
 * and a retry of the erasure reports {@code COMPLETE} without running anything.
 */
class CipherProbePr26Test {

  private static final byte[] SECRET =
      "cipher-probe-pr26-chain-secret-32".getBytes(StandardCharsets.UTF_8);
  private static final Pseudonymiser PSEUDONYMS = new Pseudonymiser(SECRET);
  private static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-10-06T10:00:00Z"), ZoneOffset.UTC);
  private static final TenantId TENANT = TenantId.of("T1");
  private static final SubjectId SUBJECT = SubjectId.of("s1");

  private final Set<String> erased = new HashSet<>();
  private final InMemoryErasureStore memory =
      new InMemoryErasureStore(
          ErasureChain.keyed(SECRET, "k1"),
          (t, s) -> erased.add(t.value() + "/" + s.value()) ? new int[] {1, 1} : new int[] {0, 0});

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

  private void partialNamingScrubberPending() {
    memory.erase(
        TENANT,
        SUBJECT,
        (keys, cleared) ->
            record(
                ErasureOutcome.PARTIAL,
                new HookOutcome(
                    "scrubber",
                    false,
                    "pending; clears trigger \"public\".\"note\".\"note_audit\"")));
  }

  @Test
  void probe_complete_reporting_the_outstanding_hook_failed_is_appended() {
    partialNamingScrubberPending();
    var anchor = memory.anchor();

    Throwable thrown =
        catchThrowable(
            () ->
                memory.append(
                    record(
                        ErasureOutcome.COMPLETE,
                        HookOutcome.failed("scrubber", "java.lang.IllegalStateException"))));

    assertThat(thrown)
        .describedAs("a COMPLETE record that reports the outstanding hook failed must be refused")
        .isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.CONFIG);
    assertThat(memory.all()).hasSize(1);
    assertThat(memory.anchor()).isEqualTo(anchor);
  }

  @Test
  void probe_complete_carrying_the_outstanding_hook_as_not_registered_is_appended() {
    partialNamingScrubberPending();

    Throwable thrown =
        catchThrowable(
            () ->
                memory.append(
                    record(
                        ErasureOutcome.COMPLETE,
                        HookOutcome.failed("scrubber", OutstandingHooks.CARRIED_PREFIX + "1"))));

    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(memory.all()).hasSize(1);
  }

  @Test
  void probe_retry_after_a_forged_complete_reports_complete_over_the_pending_copy() {
    partialNamingScrubberPending();
    var unused =
        catchThrowable(
            () ->
                memory.append(
                    record(
                        ErasureOutcome.COMPLETE,
                        HookOutcome.failed("scrubber", "java.lang.IllegalStateException"))));

    // The application, scrubber removed, asks again for the DPO's proof.
    ErasureResult retry =
        new ErasureService(
                memory,
                new DataKeyCache(Duration.ofSeconds(60), 10, CLOCK),
                PSEUDONYMS,
                List.of(),
                Duration.ZERO,
                CLOCK,
                1,
                1)
            .erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));

    assertThat(retry.outcome())
        .describedAs("the trail never recorded scrubber succeeding")
        .isEqualTo(ErasureOutcome.PARTIAL);
  }
}
