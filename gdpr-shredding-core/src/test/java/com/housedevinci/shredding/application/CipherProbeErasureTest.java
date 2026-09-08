package com.housedevinci.shredding.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.adapter.memory.InMemoryErasureStore;
import com.housedevinci.shredding.adapter.memory.InMemoryKeyProvider;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Cipher probes on the erasure path: hook outcomes, chain keying, and the honest residual. */
class CipherProbeErasureTest {

  private static final byte[] SECRET =
      "erasure-log-secret-that-is-32-bytes-or-more".getBytes(StandardCharsets.UTF_8);
  private static final TenantId TENANT = TenantId.of("acme");
  private static final SubjectId SUBJECT = SubjectId.of("s-1");

  private InMemoryKeyProvider keys;
  private DataKeyCache cache;
  private FieldCipher cipher;

  @BeforeEach
  void setUp() {
    keys = new InMemoryKeyProvider(RandomSource.secure(), true);
    cache = new DataKeyCache(Duration.ofSeconds(60), 100, Clock.systemUTC());
    cipher =
        new FieldCipher(
            keys, cache, RandomSource.secure(), FieldCipher.DEFAULT_MAX_ENCRYPTIONS_PER_KEY);
  }

  private ErasureService service(
      ErasureChain chain, List<PostErasureHook> hooks, InMemoryErasureStore[] out) {
    var store = new InMemoryErasureStore(chain, (t, s) -> new int[] {keys.destroy(t, s), 0});
    out[0] = store;
    return new ErasureService(
        store,
        cache,
        new Pseudonymiser(SECRET),
        hooks,
        Duration.ofDays(30),
        Clock.systemUTC(),
        1,
        2);
  }

  /**
   * Hooks run after the key destruction commits, so a hook that fails leaves work outstanding. An
   * erasure that reports COMPLETE while a search index still holds the subject's name is a false
   * proof, and the DPO signs it.
   */
  @Test
  void probe_a_failed_post_erasure_hook_reports_complete() {
    var failing =
        new PostErasureHook() {
          @Override
          public String name() {
            return "search-index";
          }

          @Override
          public void afterErasure(TenantId tenant, SubjectId subject) {
            throw new IllegalStateException("index unreachable");
          }
        };
    var store = new InMemoryErasureStore[1];
    var service = service(ErasureChain.keyed(SECRET, "k1"), List.of(failing), store);
    cipher.encrypt(TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));

    var result = service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));

    assertThat(result.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(result.complete()).isFalse();
    assertThat(result.hookOutcomes())
        .singleElement()
        .satisfies(
            h -> {
              assertThat(h.hook()).isEqualTo("search-index");
              assertThat(h.succeeded()).isFalse();
              // the class name, never the hook's message: a message can carry the value it
              // anonymised
              assertThat(h.detail()).isEqualTo("java.lang.IllegalStateException");
            });
    assertThat(store[0].all()).hasSize(2);
    assertThat(store[0].all().get(0).outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(store[0].all().get(1).outcome()).isEqualTo(ErasureOutcome.PARTIAL);
  }

  /**
   * CIPHER-02. The subject's key is already gone (so {@code alreadyErased} is true) but the last
   * record on the trail is {@code PARTIAL}, because a hook failed the first time. A second call -
   * exactly the one a DPO makes to produce a proof of erasure - must never report {@code COMPLETE}
   * on the strength of "no key left"; it has to look at what the trail actually says, and if that
   * is not {@code COMPLETE}, re-run the hooks and report what they do now.
   */
  @Test
  void probe_a_second_erasure_of_a_partial_subject_reports_complete() {
    var calls = new java.util.concurrent.atomic.AtomicInteger();
    var hook =
        new PostErasureHook() {
          @Override
          public String name() {
            return "search-index";
          }

          @Override
          public void afterErasure(TenantId tenant, SubjectId subject) {
            // Fails the first time, succeeds on the retry the second erasure call triggers.
            if (calls.getAndIncrement() == 0) {
              throw new IllegalStateException("index unreachable");
            }
          }
        };
    var store = new InMemoryErasureStore[1];
    var service = service(ErasureChain.keyed(SECRET, "k1"), List.of(hook), store);
    cipher.encrypt(TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));

    var first = service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));
    assertThat(first.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(first.alreadyErased()).isFalse();

    var second = service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));

    assertThat(second.alreadyErased()).isTrue();
    assertThat(second.outcome())
        .as(
            "the key is gone, but the trail's last record is PARTIAL; a repeat call must not"
                + " report COMPLETE without re-running the hooks and seeing them succeed")
        .isEqualTo(ErasureOutcome.COMPLETE);
    assertThat(calls.get())
        .as("the hook was actually re-run, not assumed to have succeeded")
        .isEqualTo(2);
    assertThat(store[0].all()).hasSize(3);
    assertThat(store[0].all().get(2).outcome()).isEqualTo(ErasureOutcome.COMPLETE);
  }

  /**
   * The mirror case: the retry hook fails again. The second call must still report PARTIAL, never
   * COMPLETE, and must still append a fresh record - it is not a no-op just because the subject was
   * already erased.
   */
  @Test
  void probe_a_second_erasure_of_a_still_failing_partial_subject_stays_partial() {
    var hook =
        new PostErasureHook() {
          @Override
          public String name() {
            return "search-index";
          }

          @Override
          public void afterErasure(TenantId tenant, SubjectId subject) {
            throw new IllegalStateException("index unreachable");
          }
        };
    var store = new InMemoryErasureStore[1];
    var service = service(ErasureChain.keyed(SECRET, "k1"), List.of(hook), store);
    cipher.encrypt(TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));

    service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));
    var second = service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));

    assertThat(second.alreadyErased()).isTrue();
    assertThat(second.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
    assertThat(store[0].all()).hasSize(3);
  }

  @Test
  void a_successful_hook_makes_the_erasure_complete() {
    var ok =
        new PostErasureHook() {
          @Override
          public String name() {
            return "search-index";
          }

          @Override
          public void afterErasure(TenantId tenant, SubjectId subject) {}
        };
    var store = new InMemoryErasureStore[1];
    var service = service(ErasureChain.keyed(SECRET, "k1"), List.of(ok), store);
    cipher.encrypt(TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));

    var result = service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));

    assertThat(result.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
    assertThat(store[0].all()).hasSize(2);
    assertThat(store[0].all().get(1).outcome()).isEqualTo(ErasureOutcome.COMPLETE);
  }

  @Test
  void erasing_twice_writes_one_record() {
    var store = new InMemoryErasureStore[1];
    var service = service(ErasureChain.keyed(SECRET, "k1"), List.of(), store);
    cipher.encrypt(TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));

    var first = service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));
    var second = service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));

    assertThat(first.alreadyErased()).isFalse();
    assertThat(second.alreadyErased()).isTrue();
    assertThat(store[0].all()).hasSize(1);
  }

  @Test
  void the_record_holds_a_pseudonym_and_the_backup_clearance_date() {
    var store = new InMemoryErasureStore[1];
    var service = service(ErasureChain.keyed(SECRET, "k1"), List.of(), store);
    cipher.encrypt(TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));

    var result = service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));
    var record = result.records().get(0);

    assertThat(record.subjectPseudonym())
        .hasSize(64)
        .isNotEqualTo(com.housedevinci.shredding.domain.Hashes.sha256Hex(SUBJECT.value()));
    assertThat(record.subjectPseudonym()).doesNotContain(SUBJECT.value());
    assertThat(record.backupRetentionUntil()).isEqualTo(result.completeInBackupsAt());
    assertThat(record.keysDestroyed()).isEqualTo(1);
  }

  /**
   * The same nanosecond-precision trap that broke the JDBC chain, one layer up: the instant an API
   * hands a caller and the instant in the proof of erasure must be the same instant, not two
   * renderings of the same moment at different precisions.
   *
   * <p>The clock is nanosecond-precision on purpose. macOS's {@code Clock.systemUTC()} is only
   * microsecond-precision, so with the system clock this passes on a developer's machine and fails
   * on Linux CI, which is exactly what happened.
   */
  @Test
  void the_result_and_the_record_agree_under_a_nanosecond_precision_clock() {
    java.time.Instant nanos = java.time.Instant.parse("2026-09-08T10:00:00.123456789Z");
    Clock nanoClock =
        new Clock() {
          @Override
          public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
          }

          @Override
          public Clock withZone(java.time.ZoneId zone) {
            return this;
          }

          @Override
          public java.time.Instant instant() {
            return nanos;
          }
        };
    var store =
        new InMemoryErasureStore(
            ErasureChain.keyed(SECRET, "k1"), (t, s) -> new int[] {keys.destroy(t, s), 0});
    var service =
        new ErasureService(
            store,
            cache,
            new Pseudonymiser(SECRET),
            List.of(),
            Duration.ofDays(30),
            nanoClock,
            1,
            2);
    cipher.encrypt(TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));

    var result = service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));
    var record = result.records().get(0);

    assertThat(result.completeInBackupsAt()).isEqualTo(record.backupRetentionUntil());
    assertThat(result.completeInBackupsAt().getNano() % 1000)
        .as("only what the store can give back unchanged may reach the proof")
        .isZero();
    assertThat(record.timestamp().getNano() % 1000).isZero();
  }

  /**
   * A trail whose rows are unkeyed, or whose anchor row is missing, must never be rendered with the
   * same word as a clean keyed trail. INTACT on an unkeyed trail is a claim its data cannot
   * support: without a secret, anyone who can write the table can rewrite the whole chain
   * consistently.
   */
  @Test
  void probe_an_unkeyed_or_unanchored_erasure_chain_reports_intact() {
    var unkeyedStore = new InMemoryErasureStore[1];
    var unkeyed = service(ErasureChain.unkeyed(), List.of(), unkeyedStore);
    cipher.encrypt(TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    unkeyed.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));

    var report =
        new ErasureChainVerifier(unkeyedStore[0], unkeyedStore[0], java.util.Map.of()).verify();
    assertThat(report.status()).isEqualTo(ErasureChainVerifier.Status.INTACT_UNKEYED);
    assertThat(report.status()).isNotEqualTo(ErasureChainVerifier.Status.INTACT);

    unkeyedStore[0].dropAnchor();
    assertThat(
            new ErasureChainVerifier(unkeyedStore[0], unkeyedStore[0], java.util.Map.of())
                .verify()
                .status())
        .isEqualTo(ErasureChainVerifier.Status.NO_ANCHOR);
  }

  @Test
  void a_keyed_trail_verifies_and_a_rewritten_row_breaks_it() {
    var store = new InMemoryErasureStore[1];
    var service = service(ErasureChain.keyed(SECRET, "k1"), List.of(), store);
    for (int i = 1; i <= 3; i++) {
      SubjectId s = SubjectId.of("s-" + i);
      cipher.encrypt(TENANT, s, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
      service.erase(new ErasureRequest(TENANT, s, "dpo", "art 17"));
    }
    var keyring = java.util.Map.of("k1", SECRET);

    var report = new ErasureChainVerifier(store[0], store[0], keyring).verify();
    assertThat(report.status()).isEqualTo(ErasureChainVerifier.Status.INTACT);
    assertThat(report.verified()).isEqualTo(3);
    assertThat(report.keyIds()).containsExactly("k1");

    var tampered = store[0].all().get(1);
    store[0].replace(1, tampered.withSequence(tampered.sequence()));
    var rewritten =
        new com.housedevinci.shredding.domain.ErasureRecord(
            tampered.sequence(),
            tampered.timestamp(),
            tampered.tenant(),
            tampered.subjectPseudonym(),
            "someone-else",
            tampered.reason(),
            tampered.keysDestroyed(),
            tampered.entityCount(),
            tampered.fieldCount(),
            tampered.blindIndexColumnsCleared(),
            tampered.outcome(),
            tampered.hookOutcomes(),
            tampered.backupRetentionUntil(),
            tampered.chainVersion(),
            tampered.keyId(),
            tampered.prevHash(),
            tampered.hash());
    store[0].replace(1, rewritten);

    assertThat(new ErasureChainVerifier(store[0], store[0], keyring).verify().status())
        .isEqualTo(ErasureChainVerifier.Status.BROKEN);
  }

  @Test
  void a_verifier_without_the_row_key_id_reports_broken_not_intact() {
    var store = new InMemoryErasureStore[1];
    var service = service(ErasureChain.keyed(SECRET, "k1"), List.of(), store);
    cipher.encrypt(TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    service.erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));

    assertThat(
            new ErasureChainVerifier(store[0], store[0], java.util.Map.of("k2", SECRET))
                .verify()
                .status())
        .isEqualTo(ErasureChainVerifier.Status.BROKEN);
  }

  @Test
  void an_empty_trail_is_empty_not_intact() {
    var store =
        new InMemoryErasureStore(ErasureChain.keyed(SECRET, "k1"), (t, s) -> new int[] {0, 0});
    assertThat(
            new ErasureChainVerifier(store, store, java.util.Map.of("k1", SECRET))
                .verify()
                .status())
        .isEqualTo(ErasureChainVerifier.Status.EMPTY);
  }

  /**
   * The honest bound of the whole technique. An insider who snapshots the key table before an
   * erasure and restores it afterwards gets the plaintext back; crypto-shredding cannot stop that,
   * and this probe exists so nobody claims otherwise. It is a documented residual, not a bug: the
   * test therefore asserts both the behaviour and that SECURITY-NOTES.md states it.
   */
  @Test
  void probe_a_wrapped_key_row_restored_after_erasure_decrypts_the_value() throws Exception {
    byte[] stored =
        cipher.encrypt(
            TENANT, SUBJECT, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    byte[] snapshot = keys.export(TENANT, SUBJECT, 1).orElseThrow();

    var store = new InMemoryErasureStore[1];
    service(ErasureChain.keyed(SECRET, "k1"), List.of(), store)
        .erase(new ErasureRequest(TENANT, SUBJECT, "dpo", "art 17"));
    assertThat(cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.SENTINEL)).isEmpty();

    keys.restore(TENANT, SUBJECT, 1, snapshot);
    cache.evictSubject(TENANT, SUBJECT);

    assertThat(cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.SENTINEL))
        .as("restoring the key row brings the plaintext back; this is the residual, not a control")
        .isPresent();

    var notes = java.nio.file.Path.of("..", "SECURITY-NOTES.md");
    assertThat(java.nio.file.Files.readString(notes))
        .as("SECURITY-NOTES.md must state the wrapped-key resurrection residual")
        .contains("Wrapped-key resurrection");
  }
}
