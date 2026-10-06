# Security review: feat/acknowledged-copies (PR 26, audit-table coverage PR 1b)

## Pass 1 (2026-10-06)

Reviewed head `7ee6c62`, diff against `5269b34` (main with PRs 24 and 25). Checklist: the design's
section 3c, 3c.6 and 3c.7 including rev 5 items 1-4, section 8, the rulings C3, C8, C11, C12 and the
rev 5 condition (append guard reads the latest record after the advisory lock, inside the READ
COMMITTED pin), the integration surface rows that 1b owns, and the attack list of the brief.

### Verdict: MERGE WITH FIXES

No HIGH. One MEDIUM (C-26-1), one LOW (C-26-2, which is #C-31), each with probes in the suite
that fail on `7ee6c62` (6 probe methods, 6 RED, run 2026-10-06). Every item is fixed before merge
(no allowance). Integration surface: rows 42 and 50 verified, row 49 missing until C-26-1 lands.

### Build and tests (PostgreSQL 16 by digest, Docker up, `CIPHER_PROBE_MAVEN=1 ./mvnw verify`)

| module | tests | failures | errors | skipped |
| --- | --- | --- | --- | --- |
| core | 531 | 0 | 0 | 0 |
| starter | 284 | 0 | 0 | 0 |
| sample | 22 | 0 | 0 | 0 |

Exit 0, licence check clean. Every existing `CipherProbe*` class ran unchanged and green, including
the re-enabled #C-30 probe and the RC-3 history-trigger WARN case. The builder's numbers match.

### Rulings on the open points

- **#C-31 (the `-009`/`-010` messages print identifiers without escaping control characters): in
  this PR, not a separate one.** Rev 5 item 3 is part of 1b's definition and says *every* WARN and
  exception message that prints an operator-chosen identifier escapes it. 1b edits the `-010`
  trigger, publication and slot messages and now prints the same identifier twice in one message,
  raw in the finding and escaped in the acknowledgement remedy. The helper (`LogText.escape`)
  exists; applying it is a correction, not a mechanism, so the one-mechanism rule does not move it
  out. A separate PR would cost two more passes for the same lines. Recorded as finding C-26-2
  below with a probe.
- **#C-32 (mechanism commit `727ce91` carries a `docs(...)` subject): accepted, closed without a
  code change.** It is pushed, and history on a pushed branch is never rewritten. The merge commit
  subject is the PR title, which is a correct `feat(jdbc)` line, so `main`'s first-parent history
  is right. Condition: the PR body names `727ce91` as the commit that carries the mechanism, so a
  reader of the branch history is not misled. Process note for the builder: when the hook refuses
  a subject for length, shorten the subject; never change its type.

### Findings

#### C-26-1 MEDIUM: one direct append launders an outstanding hook as `COMPLETE`

`OutstandingHooks.requireAnswered` (both stores, under the append lock) checks that the new record
holds *an* outcome for every name the latest record left pending or failed, and no name twice. It
never checks the record's own outcome against its outcomes. So `append(COMPLETE, [scrubber failed])`
or `append(COMPLETE, [scrubber "not registered; outstanding since record 1"])` is accepted in one
call; the subject's latest record is then `COMPLETE`, and `ErasureService.erase` on the
already-erased subject returns `COMPLETE` from the early branch without running or carrying
anything. Rev 3's store bullet required a *success* outcome for a `COMPLETE`; rev 5 item 1 replaced
the bullet with "an outcome (succeeded, failed or carried)" and the success requirement was lost in
the rewrite ("the outcome rule itself is unchanged" was true of the service only). This is the
single-call form of the laundering rev 5 item 1 closed for two calls, through the public port.

Repro (all RED on `7ee6c62`):
`CipherProbePr26Test.probe_complete_reporting_the_outstanding_hook_failed_is_appended`,
`probe_complete_carrying_the_outstanding_hook_as_not_registered_is_appended`,
`probe_retry_after_a_forged_complete_reports_complete_over_the_pending_copy` (retry answers
`COMPLETE`), `CipherProbePr26PostgresTest.probe_jdbc_append_accepts_complete_reporting_the_outstanding_hook_failed`
(row count and anchor asserted unchanged).

Fix (fix pass, correction inside the existing guard, no new mechanism):
`OutstandingHooks.requireAnswered` refuses, before the outstanding-name loop, any record whose
`outcome()` is `COMPLETE` and that holds an outcome with `succeeded() == false`, with
`SHRED-CONFIG-001` and `shredding: refused to append an erasure record for this subject: it is
COMPLETE and reports hook <name> as not succeeded.` (`<name>` through `LogText.escape`). It runs in
`JdbcErasureStore.appendInTransaction` (so `append` and the in-transaction record of `erase`) and in
`InMemoryErasureStore.appendLocked`, unchanged call sites. The service never builds such a record
(`allSucceeded` decides the outcome), so no honest path changes. Tests: the four probes green; add
the failed-outcome case to `y9_jdbc_append_refuses_complete_leaving_an_outstanding_name` and
`y9m_...`. Design: append one line to §3c.6 rev 5 item 1 restoring "a `COMPLETE` record holds only
succeeded outcomes". Mutation for the PR body: remove the new check, the four probes go red.

#### C-26-2 LOW (#C-31): `-009` and `-010` messages print a line break in an identifier raw

`CopyCatalogue` and `MappingAdmission` interpolate `quote_ident` output (`t.name()`, `root.name()`,
`on.name()`, publication and slot names, ancestor and relation names) straight into the message.
PostgreSQL accepts any UTF-8 in a quoted identifier, so a trigger named `"c262<LF>forged line"`
splits the `SHRED-SCHEMA-010` message, and every log line that prints it, in two; the same message
prints the same name escaped in the acknowledgement remedy 1b added. Same for a `SHRED-SCHEMA-009`
ancestor. Rev 5 item 3 requires every message that prints an operator-chosen identifier to escape
it. Attacker: a role that can create a trigger or a parent table, i.e. the schema owner; impact is
forged log lines, hence LOW.

Repro (RED on `7ee6c62`): `CipherProbePr26PostgresTest.probe_trigger_finding_prints_a_line_break_in_the_trigger_name_raw`,
`probe_ancestor_refusal_prints_a_line_break_in_the_parent_name_raw`.

Fix (fix pass): wrap every identifier interpolated into a `-009`, `-010` or `-005` message in
`LogText.escape` at the point of interpolation (`CopyCatalogue`: triggers, rules, views, foreign
keys, publications, slots, stale tables, function names; `MappingAdmission`: R-a to R-i and the
`Absent` message). Never escape a whole composed message: the parts already escaped would be
escaped twice (`\u000A`). Tests: the two probes green; one more each for a publication and a slot
name with U+2028, asserting one line and the `\u2028` text.

### Attacks that did not break (attempted, closed without a finding)

- Entry matching: exact `pg_catalog` text equality on `nspname`/`relname`/`tgname`/`pubname`/
  `slot_name`; case, quoting, a dotted name in one field and `%`/`*` all admit nothing and refuse
  as unused (A1, A2 green; read). Same object twice refused by `requireDistinct` on the quoted
  rendering, which is injective (doubled quotes). Disabled trigger, clone, unrelated table, physical
  or foreign-database slot, `pgoutput` slot, publication without `UPDATE`: each refuses with its own
  sentence; a publication without `UPDATE` is never matched against an entry (`pubupdate` checked
  before `entryFor`).
- Object dropped after boot refuses the erasure before the first statement and after the `UPDATE`
  (`refuseUnused` at both positions); re-created same name admitted (A7 green).
- Ancestor entry: R-i refuses `-009` before leg K, so no entry can lift it (A12 green).
- Hooks: unregistered, blank, null, duplicate and differently cased `cleared-by` refuse at startup
  (constructor and `MappingAdmissionCheck`, lazy init excluded). A hook whose `name()` changes at
  run time produces an outcome under another name: the guard or C12 refuses, fail closed.
- First record names every registered hook pending (Y7); `COMPLETE` only after the bound hook
  succeeds (A5, A6). A hook that throws an `Error` escapes after commit and leaves the pending record
  (retry answers it). What a hook clears is not checked, by design and stated in the WARN.
- Retry: outstanding names from the latest record (Y1-Y6); 0.1.x records (Y8); C11's 0.1.x weakness
  (hook removed after failing) closed by the carry. Duplicate names in a record refused (Y10).
- C12: a decorator hiding `acknowledgedCopies()` rolls back whole (W1); describe() sorts itself and
  is injective (W6). Tampered `hookOutcomes` by the owner role: detected by the chain verifier, the
  residual recorded at rev 3 (a), unchanged.
- Concurrency: the guard's latest-record read runs after `pg_advisory_xact_lock` inside the READ
  COMMITTED pin for `append` and for `erase` (`y10_append_runs_inside_the_read_committed_pin`
  green; read of `appendInTransaction`). Two racing retries both answer every name, so neither is
  refused; a stale service read can only make the record stricter. The `-008` path of PR 25 (pool in
  a transaction) refuses `append` too.
- Logs: WARN per entry, once per boot, at every boot (RC-3 probe counts 1 then 2 across two boots);
  hook-failure and carried WARNs escape the name; `LogText` covers C0, DEL, C1, U+2028/2029 and
  backslash. Bidi controls are not escaped; they reorder display but cannot add a line, and the
  design scoped the escape to line-breaking characters: not a finding.
- #C-30 probe re-enabled with an acknowledged trigger and green; RC-3 WARN case green.

### Deviations in the PR body

- In-memory "latest record" = last appended: accepted, it is the in-memory analogue of `seq`.
- No new `ErasureResult` field, carried names in `hookOutcomes` plus the WARN: accepted, the carried
  outcomes are in the returned list with their `outstanding since record <n>` text.
- Retention test store answers `acknowledgedCopies()`: accepted, test only.
- No starter W7 newline test: accepted, the starter logs the core's already-escaped string as is
  (`warnings.values().forEach(log::warn)`); W7 covers the text.

### Integration surface (1b rows)

| # | path | status |
| --- | --- | --- |
| 42 | acknowledgement abuse at the first erasure (false `COMPLETE`, ambiguous names, stale or unrelated entries) | verified (A1-A7, A12, Y11, read) |
| 49 | retry of an outstanding `PARTIAL` after configuration change, and the store-side append rule | **missing until C-26-1** (service side verified Y1-Y8; store accepts a `COMPLETE` with an unsucceeded outcome) |
| 50 | an `ErasureStore` other than `JdbcErasureStore` between service and catalogue leg | verified (W1-W6) |

Missing: 1 (49). MERGE requires 0; C-26-1 closes it.

### Test counts with this review's probes

core 531 + 6 probes (6 RED by design), starter 284, sample 22. Pass 2 confirms by the probes flipping
green and attacks only what the fixes add.

## Pass 2 (2026-10-06)

Reviewed head `0aa71f6` (`9e61aac` guard, `0aa71f6` escaping, `eb23f5d` probe layout). The two
probe files differ from `b5056a8` by layout only (`git diff -w`: line wraps, no assertion changed).

### Verdict: MERGE WITH FIXES

C-26-1 and C-26-2 are closed: their 6 probes are green. The fix added one new finding,
C-26-3 LOW, with a probe that fails on `0aa71f6`. The integration surface has 0 rows missing.
Fix C-26-3, then the PR is ready for merge with no third pass: the fix is a rendering
correction, and its probe is the check.

### Build and tests (`CIPHER_PROBE_MAVEN=1`, Docker up, per module under a 600 s limit per call)

| module | tests | failures | skipped | note |
| --- | --- | --- | --- | --- |
| core | 539 | 1 | 0 | 538 builder + 1 pass 2 probe, the one failure is that probe (RED by design) |
| starter | 285 | 0 | 0 | autoconfigure 263 + jpa 22, run separately |
| sample | 22 | - | - | not re-measured here (no sample file changed since pass 1, 22/22 then); builder's 22 |

### Prior findings

- C-26-1: closed. `OutstandingHooks.requireAnswered` refuses a `COMPLETE` holding any outcome not
  succeeded (failed, carried, pending), both stores, before the outstanding-name loop. The 4
  probes are green.
- C-26-2: closed. Identifiers in `-005`/`-009`/`-010` texts go through `JdbcSupport.printed`
  where they are inserted. Raw values used for matching and SQL are unchanged. The 2 probes are
  green.

### Attacks on the fixes

- A `COMPLETE` with an empty outcome list over an outstanding name is refused by the outstanding
  name rule (Y9 green; read). It is not a gap.
- Is `succeeded = true` trustworthy? The module does not check what a hook cleared. That is the
  meaning of an acknowledgement (§3c.4), and the startup WARN says so. A direct `append` that
  forges success sits at the same trust boundary as the hook reporting success. The append port
  is application code, not an attacker boundary. Not a finding.
- Hook names: the record keeps the raw text (`AcknowledgedCopy.object()`, `HookOutcome.hook()`).
  This is hashed material, and W7 asserts the raw identifier. All four WARN and message sites
  that print a hook name escape it. Verified by reading.
- The printed SQL fixes: C-26-3 below.

#### C-26-3 LOW: a printed remedy statement names a different object when the identifier holds a control character

Since `0aa71f6`, the `ALTER TABLE ... DISABLE TRIGGER` statement inside a `SHRED-SCHEMA-010`
message prints `"c263\u000Ax"`. Inside a plain quoted identifier, that is the literal text
backslash-u-000A. Run as printed, the statement fails with `trigger "c263\u000Ax" ... does not
exist`. Worse, it disables a decoy trigger if one has that literal name, while the real trigger
stays enabled. The failure is closed: the next boot still refuses. The impact is a misleading
remedy and DDL that can hit the wrong object, so LOW.

**Coordinator's question: is it safer to refuse to print the fix?** No. An operator without a
printed fix composes the statement from the same escaped prose and makes the same mistake.
PostgreSQL has an exact single-line form, so printing the correct statement is both safe and
usable.

Repro (RED on `0aa71f6`):
`CipherProbePr26PostgresTest.probe_printed_disable_trigger_statement_does_not_disable_the_trigger`.
It executes the printed statement as the owner and asserts the trigger is disabled.

Fix (fix pass): add one helper, `JdbcSupport.sqlIdentifier(String raw)`.
- If `raw` holds no character that `LogText` escapes, it returns today's `quote_ident` text.
- Otherwise it returns `U&"..."`: `"` doubled, `\` as `\\`, and every character `LogText`
  escapes as `\XXXX`. For string literals inside a statement (a slot name in
  `pg_drop_replication_slot('...')`), use the same rule in `U&'...'` form.
- Use it for every identifier inside a printed SQL statement (trigger, statistics, publication
  and slot remedies). Prose mentions keep `JdbcSupport.printed`.
- The output is one line and executes exactly. With `standard_conforming_strings=off`, PostgreSQL
  refuses `U&` loudly, which is acceptable.

Tests: the probe green, plus one probe executing a printed publication remedy for a name holding
U+2028. This replaces the PR body's note that the escaped fix is "not copy-paste safe".

### Integration surface (1b rows, final)

| # | status |
| --- | --- |
| 42 | verified (A1-A7, A12, Y11) |
| 49 | verified: service side Y1-Y8; store side Y9, Y9m, Y10, the C-26-1 probes, and a `COMPLETE` with an unsucceeded outcome refused |
| 50 | verified (W1-W6) |

Missing: 0.
