# STATUS — GDPR Shredding free core

**Before going public: apply the public-repository convention**
(`15-regulated-spring/specs/SHARED-CONVENTIONS.md`, "Public repositories"). This repo is
still private, so `SPEC.md`/`STATUS.md`/`QUESTIONS.md`/security reviews/plans/`RELEASING.md`
are fine here for now — but before this repo is made public, move them to
`15-regulated-spring/internal/gdpr-shredding/` and scrub names from what stays (code,
tests, README, CHANGELOG, LICENSE/NOTICE, SECURITY.md, CONTRIBUTING.md, user docs, CI, the
probe script). See how `agent-guard` did it (2026-09-10).

**Eighth pass done (Cipher, 2026-09-10, `fa6f477`). NOT MERGEABLE: one HIGH.** S-13 - S-7b, the
general case of S-7, reproduced rather than argued: with no field declaring a tenant anywhere, the
blind index is derived under the ambient `TenantSupplier` while the erasure matches on the row's own
`tenant_id` value, so an application whose tenant column holds an owning company while the supplier
yields the acting organisation leaves an HMAC of the erased plaintext behind on every erasure, with
the proof reporting success (`CipherProbeBlindIndexAmbientTenantTest`, `src/test-pending/java`, RED;
the surviving bytes are recomputable from the index secret). Fixed by design addendum 3, which is
**APPROVED WITH CHANGES** - seven numbered, in `docs/plans/read-path-design.md` under "Cipher review
of addendum 3"; changes 1 and 4 are load-bearing and change 4 is the one that closes the probe, since
option (a) as recommended does not. Addendum 2 as built survived the attack: six changes all present,
nested entries three deep, brackets inside entries and entries inside brackets, discarded inner
entries and reused threads all behave. Two LOW seams in the region deque (S-14 `unwindTo` empties the
whole deque for a token it cannot find; S-15 the S-4a deviation, ruled: widen the sweep), four INFO
(S-16 ledger cap accepts 0/-1, S-17 the `BigDecimal` placeholder renders as a megabyte - Cipher's own
seventh-pass prescription, S-18 `#27`'s branch is still unreachable and now claims not to be, S-19
the read-region SPI is published as ordinary API). **S-11 is ruled an accepted residual** with exact
wording for `SECURITY-NOTES.md`, and its probe is to be rewritten green and moved out of
`src/test-pending/java` - no design stop. 236 tests green, core 85.3% / starter 88.4%. Full detail
and the eight-line fix list: `docs/SECURITY-REVIEW-feat-shredding-core.md`, "Eighth pass (fa6f477)".

**Seventh pass corrections, done (Isis, 2026-09-10).** S-7 (HIGH), S-8 (MEDIUM), S-9, S-10, S-11
(LOW), S-12 (INFO), and QUESTIONS #26/#27 all closed; see the CHANGELOG's "Fixed"/"Added"/"Changed"
entries for the seventh pass and #26/#27. S-8 is rebuilt on top of Thor's entry-epoch mechanism
(`95efeac`/`ff294bc`, pushed mid-session): `unwindTo` gained a `refuseUndrainedIntermediates` flag
rather than a second inline pop loop, per Dollar's instruction, and the branch was rebased onto
`95efeac` before S-8 landed. `CipherProbeSeventhPassTest` (S-8 + S-10) is promoted out of
`src/test-pending/java`, both green. #26 adds `shredding.write-verification.max-outstanding` (default
50 000), refusing rather than degrading; #27 makes `settle`'s "still outstanding at completion"
branch genuinely reachable by discharging each debt only once its own check passes. **One item not
closed: S-11's own probe, `CipherProbeSettlementListenerDisplacedTest`, stays red** - see
QUESTIONS.md S-11: position-of-our-own-listener checking is structurally unable to catch an
earlier-composed integrator's `setListeners()` wipe, since this module always composes itself last;
needs a design decision (per-type Hibernate-internal class hardcoding, or a new registration-time
snapshot mechanism), flagged rather than built. S-4 R1 and the general form of S-7 (S-7b) were
Thor's design stops, independent of this work - both since addressed: S-4 R1 closed (`ff294bc`),
S-7b's design stop taken (`95efeac`).

**Seventh pass done (Cipher, 2026-09-10, `e2c2bdd`). NOT MERGEABLE: one HIGH.** S-7 - a
`@BlindIndex` derived under a `@Shredded` field's *declared* tenant survives that tenant's erasure,
so a completed erasure leaves an HMAC of the erased plaintext in the table. Opened by S-2's own fix.
Four corrections beside it (S-8 MEDIUM, S-9/S-10/S-11 LOW, S-12 INFO), rulings on QUESTIONS #25-#27,
and five new probes in `src/test-pending/java`. **Design addendum 2 (region residue) is APPROVED WITH
CHANGES** - six numbered, in `docs/plans/read-path-design.md` under "Cipher review of addendum 2";
S-4 R1 is unblocked once those land, and is not counted as a finding this pass. Full detail:
`docs/SECURITY-REVIEW-feat-shredding-core.md`, "Seventh pass (e2c2bdd)".


**S-4 (region residue) — CLOSED, built (Thor, 2026-09-10).** Design addendum 2 was approved with six
changes and all six are built and marked "applied §2.x" in `docs/plans/read-path-design.md`: epochs
compared for equality only; a distinguished `NO_ENTRY` epoch that public `openRegion()` stamps
explicitly (and `enterRegion()` added for the two real entries); the entry-time sweep made
epoch-conditional and loud at `WARN`; the predicate moved into one private `currentRegion()` used by
`recordDecoded`, `drain`, `pendingKeysFor` and `closeRegion`; the close half built as a separate
method (`refuseIfClosedUnderAnotherEntry`, called last) so it merges cleanly with Isis's S-8 fix,
which had not landed at the agreed hour; and the two probes Cipher listed. `CipherProbeRegionResidueTest`
is promoted out of `src/test-pending` and green, `CipherProbeRegionEpochTest` adds six,
`CipherProbeReadScopeTest` two on the real read path, and `CipherProbeBracketUnwindTest` is unchanged
at 0/200. The one residual is stated in `SECURITY-NOTES.md` in Cipher's words: **a leaked region
costs a refusal, never a value.**

**S-7b (blind index tenant binding) — DESIGN STOP TAKEN, no code (Thor, 2026-09-10).**
`docs/plans/read-path-design.md`, "Design addendum 3", states the property, the general case where
the `tenantColumn` value differs from the ambient tenant, five options and the recommendation
(derive under the row's own `tenantColumn` value, with startup and write-time refusals as its
boundary), and the probe list. Cipher reviews before any code. S-7's own startup refusal is Isis's
and is not blocked on this.

Sixth pass corrections (2026-09-10): Cipher's `## Sixth pass (75af7ea)` review of the read-path
redesign found one HIGH design stop (S-1, `hibernate.jdbc.batch_size` silently switches off the
insert-side post-hoc header check) and five corrections, S-2 to S-6. Thor closed S-1 in a separate
worktree (settlement ledger, `WriteVerification`, `0e68fb1`/`623f86c`) and Isis closed S-2, S-3, S-5
and S-6 fully, and S-4 for its data-loss half (an ownerless region can now only ever serve this row's
own, current value, never a stale one); S-4's missing-refusal half needs a design stop of its own —
see QUESTIONS.md S-4. Isis's branch was rebased onto Thor's after the fact (unpushed work only, no
force-push); the rebase surfaced one real interaction, not a mechanical conflict: Thor's new
`WriteVerification.owe`/`verifyChunk` compared every field's stored header against one scope-wide
tenant, exactly the defect S-2 closed on the older per-row post-hoc check - `WriteVerification.Debt`
now carries the whole `Scope` and checks each field's own tenant via `Scope.tenantFor`. Per QUESTIONS
#25, `CipherProbeBatchedInsertCheckTest` (S-1's original probe) is rewritten from "the write is
refused" to "startup refuses the `@Access(PROPERTY)` mapping it used to reach", C-38-style, since
S-5's startup refusal now makes the original fixture unstartable; S-1's property stays independently
carried by `BatchedWriteVerificationTest`'s seventeen probes. See the CHANGELOG's "Fixed (sixth pass
corrections at `75af7ea`)" entry and QUESTIONS.md S-2/S-4/#25 for the deviations and the one item
still open (S-4's R1). Also applied: the #22 doc correction, stating the per-decrypt key-state cost
beside control 7 in `SECURITY-NOTES.md`. `./mvnw clean verify` green across all four modules
(`gdpr-shredding`, `-core`, `-spring-boot-starter`, `-sample`); coverage gates held; default build is
92 (core) + 110 (starter) + 17 (sample) = 219 tests, 0 failures. `src/test-pending/java` holds exactly
one file, `CipherProbeRegionResidueTest.java`, for the S-4 residual.

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

Sixth pass — read-path redesign (2026-09-10, Thor): Cipher's design review of
`docs/plans/read-path-design.md` returned APPROVED WITH CHANGES with fourteen mandatory items and
rulings D1-D6. **All fourteen applied, none disputed**; the design file marks each item with the
section that carries it. This closes the fifth pass's design stop - C-33, C-34, C-35, C-39, C-40,
C-41 - as one change. The converter no longer returns plaintext: it decrypts, files what it
decrypted in the open read region, and returns a placeholder, and `onPostLoad` verifies against the
row and installs. Stored format is `SH1` v2 with the row identifier in the header and the AAD; v1 is
refused. `withRead`, the read-scope stack and `clearAll()` are removed. See the CHANGELOG's
"Changed (read-path redesign, sixth pass at `faaafff`)" entry, the rewritten read-path section of
`SECURITY-NOTES.md`, and QUESTIONS.md #21-#23 for the three residuals recorded for Cipher.

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
| 18 | Read-path design (`docs/plans/read-path-design.md`), reviewed by Cipher: APPROVED WITH CHANGES, 14 items + D1-D6 | done |
| 19 | All 14 design items applied and indexed; the three that broke the design as written (prepend `POST_LOAD`, entity name in `require`, `refuseIfSubjectMoved` on insert and every update) reshaped §1.3, §2 and §5 | done |
| 20 | Format `SH1` v2: row identifier in the header and the AAD, v1 refused, `IDENTITY` rebind over raw JDBC | done |
| 21 | Framework matrix §2: one test per path, RED before the mechanism; the six pending fifth-pass probes moved into `src/test/java`, green | done |
| 22 | Startup refusals for the mappings loaded-state install cannot survive, read off the runtime persister | done |
| 23 | Cipher's next review of the built read path | not started — for Cipher |

## Tests

| Module | Tests | Notes |
|---|---|---|
| `gdpr-shredding-core` | 92 | includes the CIPHER-01/02/03/04/05/10/15 probes, the Testcontainers PostgreSQL suite, and the sixth pass's `RowIdTest` (7), `EncryptedValueV2Test` (4) and `FieldCipherRowBindingTest` (4) |
| `gdpr-shredding-spring-boot-starter` | 121 | includes the sixth pass's `FrameworkMatrixTest` (13, the §2 matrix), `LoadedStateHostileMappingsTest` (3, the D4 startup refusals), and the six promoted fifth-pass probes - `CipherProbeFifthPassTest` (3: C-33/C-34/C-35), `CipherProbeEvictionTest` (1: C-36), `CipherProbeBracketUnwindTest` (4); and `ShreddingIntegrationTest` (real Hibernate/Testcontainers coverage of the event listener, the context stack and the auto-configuration bean graph), `CipherProbeSpelTest`'s L12 probe, the third pass's `CipherProbeReadScopeTest` (C-17/18/22/23/C-30), `CipherProbeReverseScanTest` (C-19, isolated context), `CipherProbeMatrixTest`/`CipherProbeMatrix2Test` (the read-path and `@Immutable` sweeps, C-20/21/C-31), the fourth pass's `CipherProbeFrameTest` (C-26/C-27, six probes) and `CipherProbeEmbeddableScanTest` (C-29, two probes: `@Embedded` and `@ElementCollection`), and the fifth pass's `CipherProbeScanDepthTest` (C-37, four probes: two levels of `@Embeddable`, an `@ElementCollection` of basic values, and the map-key index descriptor) and `CipherProbeCompositeIdTest` (C-38, two probes); and the seventh pass's region-residue set - `CipherProbeRegionEpochTest` (6), `CipherProbeRegionResidueTest` (2, promoted from `src/test-pending`) and two more in `CipherProbeReadScopeTest` |
| `gdpr-shredding-sample` | 17 | includes the CIPHER-01 (moved-blob), QUESTIONS #4 (detached-merge, now wrapped in `ShreddingContext.withReadBracket`), CIPHER-08 (stale-scope), the live-actuator and the log-scan probes |
| **total** | **230** | |

Nothing is skipped and nothing is `@Disabled`.

## Coverage (`target/site/jacoco/jacoco.csv`, per module, LINE counter)

| Module | Covered / Total | % | Gate |
|---|---|---|---|
| `gdpr-shredding-core` | — | 85.3% | 80% |
| `gdpr-shredding-spring-boot-starter` | — | 88.1% | 80% |
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

Seventh pass - S-1, the write-side design stop (2026-09-10, Thor): Cipher's `## Sixth pass
(75af7ea)` returned NOT MERGEABLE on one HIGH: with `hibernate.jdbc.batch_size` set, design item
14's insert-side post-hoc header check read the row back before the JDBC batch had executed, found
nothing, and returned - and Cipher's probe committed three rows of plaintext personal data.
`docs/plans/read-path-design.md` carries the design addendum (the property, four options with their
cost, the recommendation, the paths, the probes); **option (a) with the fail-open closed** is built.
A bind now incurs a verification debt the transaction cannot commit without settling; a debt that
cannot be settled is `SHRED-UNVERIFIED-WRITE` before the commit, so a configuration knob can no
longer remove the control, only make it refuse. Seventeen probes in `BatchedWriteVerificationTest`,
framework matrix rows 24-27. The `StatelessSession` `EventSource` ClassCastException on every
shredded write is fixed in the same branch. **S-2 to S-6 are Isis's, in the main checkout, and were
not touched here.** Open: QUESTIONS #25 (S-1's own probe collides with S-5's startup refusal and is
therefore left in `src/test-pending`, green), #26 (ledger cost on a stateless import), #27 (three
deliberately unreachable lines).

Seventh pass - S-4, region residue (2026-09-10, Thor). Design addendum 2 was approved with six
changes; all six are built, each marked "applied §2.x" in `docs/plans/read-path-design.md`, with an
"Addendum 2 as built" section stating what each one became. One deviation is stated rather than
hidden: Cipher's sweep rule is applied literally, so a `NO_ENTRY` region left on a thread where
nothing is in force is not swept - it can serve nothing and the enclosing unwind pops it - and
QUESTIONS S-4 records the option of sweeping it too, for Cipher to rule on. The close half is built
as a separate method called last in `closeRegion`, because Isis's S-8 fix (which rewrites
`closeRegion`'s unwind inline) had not been pushed at the agreed hour; Dollar was told. The one line
this adds inside `unwindTo` - `restoreEpoch(region)` - carries the contract in javadoc, and two
nested probes fail immediately if a merge drops it. `./mvnw verify` green in the worktree and in a
fresh clone; coverage gates held; nothing skipped.

## Deliberately not done

- No cross-node cache invalidation (QUESTIONS #8, ruled); the 60-second window is documented
  instead, and Pro gets invalidation with the KMS adapters.
- No batch migrator for existing plaintext columns; Pro only, per control 17.
- Not settled per-row inside the flush that wrote the row: at any batch size the row is not there
  yet, which is S-1 itself. The per-row check stays only as the belt.
- No `PostErasureHook` retry scheduler. A failed hook makes the erasure `PARTIAL` and the outcome is
  in the log; who retries it is the application's decision.
- The spec body's "100k encryptions, no nonce collision" property test is **not** written. Cipher
  replaced it: 100 000 draws from 2^96 collide with probability about 2^-64, so the test cannot fail
  even against a badly broken generator. What is tested instead is that the nonce comes from a
  `RandomSource` we control, that a narrow generator is detectable, and that the per-key counter
  refuses and rotates.
