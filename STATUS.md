# STATUS — GDPR Shredding free core

Licensing (2026-09-08): free core switched from Apache-2.0 to FSL-1.1-ALv2 (Souhaile's decision); `LICENSE`/`NOTICE` added, `pom.xml` updated, `./mvnw -B clean verify` re-confirmed green.

Re-verification (2026-09-09): Cipher's `## Re-verification (96713f9)` pass found 3 HIGH, 3 MEDIUM
and 4 LOW findings against the first review's fix. All ten closed by Isis; see the CHANGELOG's
"Fixed (re-verification at `96713f9`)" entry and QUESTIONS.md #16.

Third pass (2026-09-09): Cipher's `## Third pass (8095d2c)` pass found the read bracket was a
permission, not a proof - 4 HIGH (C-17/C-18/C-19/C-20), 3 MEDIUM (C-21/C-22/C-23), 2 LOW (C-24/C-25).
All nine closed by Isis; see the CHANGELOG's "Fixed (third pass at `8095d2c`)" entry and
QUESTIONS.md #17-#18 for the two items where the prescribed shape was adjusted (C-20's coarse
startup check ships without its own dedicated probe; C-21's probe was rewritten to assert the true,
documented - not the literally-named - outcome).

Fourth pass (2026-09-09): Cipher's `## Fourth pass (0ba0f6f)` pass found the third pass's per-bracket
frame was still keyed by `entity.field` with no row identity - a leak and a false-refusal mirror on
any multi-row query - 2 HIGH (C-26 + its mirror, C-27), 1 MEDIUM (C-29), 3 LOW (C-30/C-31/C-32). All
closed by Isis; see the CHANGELOG's "Fixed (fourth pass at `0ba0f6f`)" entry and QUESTIONS.md #19-#20
for the two items where the prescribed shape was adjusted (C-27's transaction is evicted from but not
also marked rollback-only - Spring's own `@Transactional` on `findById` already does the equivalent
and marking it explicitly broke every probe that catches the refusal and continues; the read-side
per-row re-read shares the write path's existing, undemonstrated composite-identifier residual). A
Maven profile, `probes-pending`, and `src/test-pending/java` in `gdpr-shredding-core` and
`gdpr-shredding-spring-boot-starter` are new this pass (Dollar's standing convention): a future
hand-off probe is committed to the repo, not the session scratchpad, and compiled/run only with
`-Pprobes-pending` until it is green and moved into `src/test/java`. See `CONTRIBUTING.md`.

Fifth pass (2026-09-09): Cipher's `## Fifth pass (2f72449)` pass found two HIGH, one MEDIUM and one
LOW that are one design stop - who owns `ShreddingContext`'s thread-local state and what is allowed
to clear it (C-33/C-34/C-35/C-39/C-40/C-41) - left for Thor, not touched here. Isis's own two LOW
corrections from the same pass, C-37 (the reverse metamodel scan never walked a plural attribute's
index/map-key descriptor) and C-38 (a composite-id `@Shredded` entity started up and was then
unreadable instead of being refused at boot, like the `@SecondaryTable` split), both closed; see the
CHANGELOG's "Fixed (fifth pass at `2f72449`)" entry and QUESTIONS.md #20 (reclassified to C-38,
closed).

Branch `feat/shredding-core`. `main` holds the plan commit only.
Full `./mvnw -B clean verify` green with Docker up.

## Tasks

| # | Task | State |
|---|---|---|
| 1 | Plan (`docs/plans/core-plan.md`), committed to `main` | done |
| 2 | Build skeleton, `commit-msg` hook, CI, Dependabot, ArchUnit | done |
| 3 | Crypto primitives: HKDF, AES-GCM, canonical AAD, `EncryptedValue` | done |
| 4 | Keys: `KeyProvider` SPI, master key, bounded cache, per-key counter, rotation | done |
| 5 | Erasure chain, JDBC store, anchor, triggers, verifier | done |
| 6 | `ErasureService`, hooks, blind index, tombstone | done |
| 7 | Starter: converters, write-path listeners, SpEL, properties, startup refusals, actuator | done |
| 8 | Sample: customer, audit table, erasure endpoint, end-to-end proof | done |
| 9 | Docs, `SECURITY-NOTES.md`, `CHANGELOG.md`, `QUESTIONS.md`, draft PR | done |
| 10 | Dollar's rulings on all ten QUESTIONS applied (2026-09-08) | done |
| 11 | Odin's regulatory corrections and the wording rule | done |
| 12 | CI green-locally / red-on-CI bug found and fixed (see below) | done |
| 13 | Cipher's first PR review (2026-09-08): 2 HIGH, 8 MEDIUM, 10 LOW/INFO, all closed | done |
| 14 | Cipher's re-verification (2026-09-09): 3 HIGH (CIPHER-11/12/14), 3 MEDIUM (CIPHER-13/15/16), 4 LOW (L11-L14), all closed | done |
| 15 | Cipher's third pass (2026-09-09): 4 HIGH (C-17/18/19/20), 3 MEDIUM (C-21/22/23), 2 LOW (C-24/25), all closed | done |
| 16 | Cipher's fourth pass (2026-09-09): 2 HIGH (C-26+mirror/C-27), 1 MEDIUM (C-29), 3 LOW (C-30/31/32), all closed | done |
| 17 | Cipher's fifth pass (2026-09-09), Isis's two corrections only: 2 LOW (C-37/C-38), both closed. The pass's HIGH/MEDIUM findings (C-33/34/39/40/41) are a design stop - `ShreddingContext`'s thread-local ownership - out of scope, left for Thor | done |

## Tests

| Module | Tests | Notes |
|---|---|---|
| `gdpr-shredding-core` | 77 | includes the CIPHER-01/02/03/04/05/10/15 probes and the Testcontainers PostgreSQL suite |
| `gdpr-shredding-spring-boot-starter` | 64 | includes `ShreddingIntegrationTest` (real Hibernate/Testcontainers coverage of the event listener, the context stack and the auto-configuration bean graph), `CipherProbeSpelTest`'s L12 probe, the third pass's `CipherProbeReadScopeTest` (C-17/18/22/23/C-30), `CipherProbeReverseScanTest` (C-19, isolated context), `CipherProbeMatrixTest`/`CipherProbeMatrix2Test` (the read-path and `@Immutable` sweeps, C-20/21/C-31), the fourth pass's `CipherProbeFrameTest` (C-26/C-27, six probes) and `CipherProbeEmbeddableScanTest` (C-29, two probes: `@Embedded` and `@ElementCollection`), and the fifth pass's `CipherProbeScanDepthTest` (C-37, four probes: two levels of `@Embeddable`, an `@ElementCollection` of basic values, and the map-key index descriptor) and `CipherProbeCompositeIdTest` (C-38, two probes) |
| `gdpr-shredding-sample` | 17 | includes the CIPHER-01 (moved-blob), QUESTIONS #4 (detached-merge, now wrapped in `ShreddingContext.withReadBracket`), CIPHER-08 (stale-scope), the live-actuator and the log-scan probes |
| **total** | **158** | |

Nothing is skipped and nothing is `@Disabled`.

## Coverage (`target/site/jacoco/jacoco.csv`, per module, LINE counter)

| Module | Covered / Total | % | Gate |
|---|---|---|---|
| `gdpr-shredding-core` | 979 / 1158 | 84.5% | 80% |
| `gdpr-shredding-spring-boot-starter` | 770 / 899 | 85.7% | 80% |
| `gdpr-shredding-sample` | 63 / 95 | 66.3% | 30% smoke gate (L2) |

The JaCoCo executions moved from `gdpr-shredding-core`'s own POM to the parent's
`<build><plugins>`, so all three modules now inherit them (L2). The starter's own tests previously
exercised none of `ShreddingEventListener`, `ShreddingContext`, `ShreddingRuntime` or the
auto-configuration bean graph (0% on those classes); `ShreddingIntegrationTest` closes that with
local fixture entities (`fixture.Widget`, `fixture.Gadget`) and Testcontainers PostgreSQL, so the
starter does not depend on the sample module for its own coverage.

Branch coverage is the weak number. Most of the uncovered branches are defensive validation in
`EncryptedValue`, `Identifiers` and the JDBC mapping; the security-relevant ones are covered by the
probes.

## Cipher's 19 probes

All nineteen are written and green. Each was RED before its fix; where the control was part of the
first draft, RED was demonstrated by removing the control and re-running (evidence below).

| Probe | Where | State |
|---|---|---|
| `probe_a_wrapped_key_row_restored_after_erasure_decrypts_the_value` | core `CipherProbeErasureTest` | green (documented residual + asserts `SECURITY-NOTES.md` states it) |
| `probe_field_and_entity_names_collide_in_the_aad` | core `CipherProbeAadTest` | green |
| `probe_ciphertext_moved_between_rows_still_decrypts` | core `CipherProbeFieldCipherTest` | green |
| `probe_reading_an_erased_entity_rewrites_the_column_on_flush` | sample `SampleEndToEndTest` | green |
| `probe_second_level_cache_serves_plaintext_after_erasure` | starter `CipherProbeStartupTest` | green |
| `probe_entity_tostring_leaks_the_decrypted_value` | sample `SampleEndToEndTest` | green |
| `probe_blind_index_still_matches_the_erased_subject` | core `CipherProbeJdbcTest` | green |
| `probe_blind_index_matches_the_same_value_across_tenants` | core `CipherProbeBlindIndexTest` | green |
| `probe_spel_expression_reaches_a_bean_or_a_static_type` | starter `CipherProbeSpelTest` | green |
| `probe_changing_the_subject_expression_moves_a_row_out_of_erasure_scope` | sample `SampleEndToEndTest` | green |
| `probe_key_store_outage_reads_as_erased` | core `CipherProbeFieldCipherTest` | green |
| `probe_crash_between_key_destruction_and_the_erasure_record` | core `CipherProbeJdbcTest` | green |
| `probe_concurrent_write_encrypts_under_a_destroying_key` | core `CipherProbeJdbcTest` | green (found a real bug, see below) |
| `probe_an_unkeyed_or_unanchored_erasure_chain_reports_intact` | core `CipherProbeErasureTest` | green |
| `probe_tenant_b_decrypts_tenant_a_value_for_the_same_subject_id` | core `CipherProbeFieldCipherTest` | green |
| `probe_core_reads_a_plaintext_column_as_plaintext` | core `CipherProbeFormatTest` | green |
| `probe_master_key_appears_in_actuator_env` | starter `CipherProbeActuatorTest` | green |
| `probe_encryption_passes_the_per_key_2_32_limit` | core `CipherProbeFieldCipherTest` | green |
| `probe_a_failed_post_erasure_hook_reports_complete` | core `CipherProbeErasureTest` | green |

### RED evidence

- `probe_field_and_entity_names_collide_in_the_aad`: first draft concatenated the AAD components
  without a length prefix; the probe failed, the length-prefixed form fixed it.
- `probe_core_reads_a_plaintext_column_as_plaintext`: first draft had a `decodeOrPlaintext` that
  handed back unrecognised bytes; the probe failed to compile against the strict `decode`, which is
  the API that replaced it.
- `probe_blind_index_matches_the_same_value_across_tenants`: run against a draft whose HKDF info
  omitted the tenant; the probe failed with two identical index values.
- `probe_ciphertext_moved_between_rows_still_decrypts`, `probe_key_store_outage_reads_as_erased`,
  `probe_encryption_passes_the_per_key_2_32_limit`: run against drafts with the entity/field AAD
  component removed, with the outage swallowed as an erasure, and with the rotation removed. All
  three failed.
- `probe_a_wrapped_key_row_restored_after_erasure_decrypts_the_value`: failed because
  `SECURITY-NOTES.md` did not yet exist to state the residual.
- `probe_concurrent_write_encrypts_under_a_destroying_key`: failed against the implementation as
  designed - see below.

## Cipher's fourth-pass probes (0ba0f6f)

Eight probes, all green, all RED before their fix (proven by reverting to the third-pass code and
re-running, not assumed):

| Probe | Where | State |
|---|---|---|
| `probe_a_moved_ciphertext_in_a_second_row_of_one_result_set` (C-26, the leak) | starter `CipherProbeFrameTest` | green |
| `probe_a_refused_row_is_returned_on_the_retry_from_the_persistence_context` (C-27) | starter `CipherProbeFrameTest` | green |
| `probe_a_nested_repository_call_does_not_absolve_the_outer_frames_debt` (regression guard) | starter `CipherProbeFrameTest` | green |
| `probe_empty_results_are_not_refused` (regression guard) | starter `CipherProbeFrameTest` | green |
| `probe_a_read_only_manual_flush_transaction_still_refuses_a_moved_ciphertext` (regression guard) | starter `CipherProbeFrameTest` | green |
| `probe_two_rows_of_two_subjects_read_in_one_query` (C-26, the false-refusal mirror; strengthened per Dollar's instruction to assert each row's own value, not just "no exception") | starter `CipherProbeFrameTest` | green |
| `probe_a_shredded_field_inside_an_embeddable` (C-29, `@Embedded`) | starter `CipherProbeEmbeddableScanTest` | green |
| `probe_a_shredded_field_inside_an_element_collection_of_embeddables` (C-29, `@ElementCollection`; Dollar's mandated companion) | starter `CipherProbeEmbeddableScanTest` | green |

Plus the LOW fixes with no new probe of their own: C-30 rewrote an existing probe on a
single-shredded-field fixture asserting the exact code (`CipherProbeReadScopeTest`); C-31 renamed a
probe (`CipherProbeMatrixTest`); C-32 is exercised by every probe above that reaches a mismatch or a
refusal, since `withReadBracket` is the mechanism every one of them goes through.

## The CI-only failure, 2026-09-08 (run 34240131889, HEAD `8f3e0fb`)

**Symptom.** `CipherProbeJdbcTest.the_erasure_record_chain_verifies_end_to_end` expected `INTACT`
and got `BROKEN` on GitHub Actions, while `./mvnw -B clean verify` was green on the developer's
machine.

**Root cause.** `ErasureRecord.timestamp` and `backupRetentionUntil` are inside the hashed material,
and PostgreSQL's `timestamptz` holds **microseconds** and *rounds* anything finer. A nanosecond
`Instant` therefore came back out of the column as a different instant
(`...123456789Z` was stored and read back as `...123457Z`), so the verifier recomputed a different
hash from a row nobody had touched. It never failed locally because **macOS's `Clock.systemUTC()`
is microsecond-precision while Linux's is nanosecond**: the developer's clock could not produce the
input that triggers it.

**Ruled out first, with evidence, before changing anything:** the probe reads no environment
variables (the HMAC secret and key id are hard-coded in the test); the canonical form contains no
locale- or zone-sensitive formatting (`Instant.toString` is ISO-8601 UTC, and this machine runs
`fr_FR`/`Europe/Paris` and was green); it has no newlines, so line endings cannot reach it; the
Postgres image is pinned by the same digest on both sides; and `@BeforeEach` drops and recreates
every table, so there is no shared state or ordering effect between the class's tests.

**`java.lang.IllegalStateException: index unreachable` in the same CI log is a red herring.** It is
the deliberate hook fixture in `CipherProbeErasureTest.probe_a_failed_post_erasure_hook_reports_complete`,
logged with its stack trace by `ErasureService` at WARN because that is what a failed hook is
supposed to do. It is expected output of a passing test.

**Fix.** `ErasureRecord` truncates both instants to `STORAGE_PRECISION` (`ChronoUnit.MICROS`) in its
compact constructor, so hashed material can only ever hold values the store gives back unchanged,
whatever precision the caller's `Clock` has. Truncation and not rounding, so an erasure is never
timestamped later than it happened.

**A second instance, unmasked by the first fix** (CI run 34264742233). With the chain green,
`CipherProbeErasureTest.the_record_holds_a_pseudonym_and_the_backup_clearance_date` failed on the
same nanosecond input: `ErasureResult.completeInBackupsAt` was untruncated while the record's
`backupRetentionUntil` was, so the date the API hands a caller and the date in the proof of erasure
were two different instants. That is a real inconsistency, not a test artefact, so the fix is in
`ErasureResult`, not in the assertion. `DataKey.createdAt` was truncated at the same time on the
same reasoning, so a key held in memory and the same key read back are equal.

**Guard against the next one.** `every_instant_that_crosses_the_storage_boundary_is_truncated`
walks the record components of `ErasureRecord`, `ErasureResult` and `DataKey` by reflection,
constructs each from a nanosecond instant, and fails if any `Instant` keeps sub-microsecond
precision. A new `Instant` field added to any of them without truncation now fails on every machine
instead of on Linux CI three commits later. The test also asserts the exact list of components it
checked, so adding a field silently is not possible either.

**Tests that would have caught it**, both RED before the fix:

- `ErasureRecordPrecisionTest` (core, no database, runs everywhere): the record holds only
  microsecond precision, two records differing below a microsecond hash identically, truncation
  never moves a timestamp forward, and `withChain`/`withSequence` preserve it.
- `CipherProbeJdbcTest.the_chain_survives_a_nanosecond_precision_clock`: drives the erasure with an
  **explicit nanosecond-precision `Clock`** rather than the system clock, so the CI condition is
  reproduced on every machine, and asserts the read-back record equals the written one field for
  field, not just that the verifier is happy.
- `CipherProbeErasureTest.the_result_and_the_record_agree_under_a_nanosecond_precision_clock`: the
  same explicit nanosecond clock one layer up, asserting the API's date and the proof's date are
  the same instant.

The lesson generalises: anything inside hashed material must survive its column type exactly, and a
test must not depend on the host clock's resolution to produce the interesting input.

## The one real bug the probes found

A write that was racing an erasure blocked on the key row's `FOR UPDATE`, then found the row gone,
concluded the subject simply had no key yet, and minted a new one. The erasure was undone within
milliseconds and nothing in the erasure log said so.

Fixed with a `shredding_erased_subject` tombstone holding no key material: the key rows are still
deleted outright, and `mint` refuses for a tombstoned subject. Recorded as QUESTIONS #3, because it
adds a table Cipher's section does not name.

## Dollar's rulings, 2026-09-08

All ten questions ruled on. What changed in the code:

| # | Ruling | Change |
|---|---|---|
| 1 | Converter per field accepted; an annotation processor is a later improvement | note in `docs/index.md` |
| 2 | Shared chain library after module D | none |
| 3 | Tombstone accepted in principle, Cipher verifies | `SECURITY-NOTES.md` section, one line in `SPEC.md` Threats |
| 4 | Ship the per-thread approach; Cipher picks the stricter design | both options written out in QUESTIONS with my recommendation (c); the gap stated as a residual |
| 5 | No fake sentinel values; WARN listing the fields that cannot carry one | `ShreddedConverter.carriesSentinel()`, `ShreddedModel.fieldsWithoutSentinel()`, WARN in `ShreddingStartupCheck`, one test |
| 8 | Local-only invalidation accepted for core; Pro gets cluster invalidation | `docs/index.md` section and a free-vs-Pro row |
| 9 | Add the startup check for records and generated renderings | `ShreddedModel.refuseGeneratedRendering`, one test; sample ArchUnit rule kept as the user reference |
| 10 | Odin verified the citations the same day; two were wrong | references replaced in `docs/index.md`, no `TODO-CITATION` left |
| 11 | Wording rule: pseudonymisation with key destruction, never an unqualified "erases" | `README.md`, `docs/index.md` (opening + new FAQ), `SECURITY-NOTES.md`, sample README, `SPEC.md` lines 6, 73, 78 |

## Open questions

Two are still genuinely open: **#4** (Cipher chooses between a shadow subject column and reading the
stored blob in `PreUpdate`; my recommendation is the latter) and **#12** (the ENISA pseudonymisation
report, which Odin could not pin to a section, so it is deliberately not cited). #10 closed the same
day it was raised: Odin found two of the three references wrong. Everything else is ruled and
applied.

## Regulatory position, corrected 2026-09-08

Odin's verification changed what the product is allowed to say. **EDPB Guidelines 5/2019 covers
search-engine delisting and says nothing about encryption**; the CNIL page previously cited is
algorithm guidance with nothing on key destruction. Both are removed. The sources that do support
the technique are GDPR Art. 17(1) and Art. 32(1)(a) with Recitals 26, 28, 29 and 83; A29WP Opinion
05/2014 (WP216) Section 4, which classifies encryption with key deletion as **pseudonymisation, not
anonymisation**; the CNIL's research-pseudonymisation page; and the ICO's "beyond use" test for
backups.

The wording rule follows: never "erases", "deletes", "anonymises" or "GDPR-compliant erasure" as an
unqualified claim. The public API keeps `ErasureService` and `ErasureRecord` (QUESTIONS #11).

## Deliberately not done

- No cross-node cache invalidation (QUESTIONS #8, ruled); the 60-second window is documented
  instead, and Pro gets invalidation with the KMS adapters.
- No batch migrator for existing plaintext columns; Pro only, per control 17.
- No `PostErasureHook` retry scheduler. A failed hook makes the erasure `PARTIAL` and the outcome is
  in the log; who retries it is the application's decision.
- The spec body's "100k encryptions, no nonce collision" property test is **not** written. Cipher
  replaced it: 100 000 draws from 2^96 collide with probability about 2^-64, so the test cannot fail
  even against a badly broken generator. What is tested instead is that the nonce comes from a
  `RandomSource` we control, that a narrow generator is detectable, and that the per-key counter
  refuses and rotates.
