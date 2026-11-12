# Security review: whole-module pass for 0.2.1, second candidate

## 2026-10-27, release candidate, branch fix/fk-action-owner-context at 3e363e8

**Verdict: NOT TAG.** Two LOW findings. Every finding is fixed before the tag (no allowance).

Scope. The first candidate pass (2026-10-21, main at d6f88a6) covered the whole module. Since
then only two mechanisms changed: the key-write path refuses a caller's transaction (PR 50), and
the schema gate judges no-check slots and owner context (PR 51, PR 53). Domain, read path and
starter did not change (diff checked). This pass takes the threat model of the spec review as
the checklist and asks how those two mechanisms meet: a caller's transaction at startup, the
startup order, pooled connections, and the 0.2.1 release text.

### Numbers

| Item | Result |
|---|---|
| `CIPHER_PROBE_MAVEN=1 ./mvnw -B clean verify`, Docker up | BUILD SUCCESS |
| Tests run / failed / errored / skipped | core 1338, starter 319, sample 25: 1682 / 0 / 0 / 0 |
| JaCoCo gate | met in all three modules |
| Existing `CipherProbe*` tests | inside the 1682, all green, unchanged |
| PostgreSQL | both pins of the suite, 16 and 17 (the owner-context and function-grants suites run on each) |
| New probes | 2, both red on 3e363e8 (`CipherProbeRc021bTest`, core, package `adapter.jdbc`) |
| `tools/check-private-references.sh --tree` | clean |

The probe file is kept in the internal probes folder of the module. The fix pass adds it to the
suite before it touches production code.

### Findings

| Id | Severity | One line | Probe |
|---|---|---|---|
| C-RC021B-1 | LOW | the verify-only startup path, the default, still ends a caller's transaction | `probe_verify_schema_inside_a_caller_transaction_rolls_back_the_caller_rows`, `probe_verify_schema_at_the_start_of_a_caller_transaction_ends_it` |
| C-RC021B-2 | LOW | the CHANGELOG and the upgrade guide announce one of the four refusals no mode relaxes | text finding, checked by reading |

#### C-RC021B-1, LOW: the verify-only path has no caller-transaction refusal

Class: lock/window (transaction scope).

PR 50 made three entry points refuse a connection that arrives inside the caller's transaction
(auto-commit off), untouched, with `SHRED-SCHEMA-008`: the key writes, `initializeSchema` (R50-2)
and `initializeAndVerifySchema` (R50-4). A fourth entry point takes a `DataSource` and opens a
connection: `JdbcSupport.verifySchema(DataSource, boolean, List)`. It is the default startup path
of the starter (`initialize-schema=false`), and the call `docs/upgrading-0.2.1.md` gives to
callers without Spring. It has no such check. `SchemaVerification.verify` sets auto-commit off,
runs `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY`, and `restore()` always calls
`rollback()`.

Example 1 (first probe). The application inserts a row in its own transaction, then calls
`verifySchema` through `TransactionAwareDataSourceProxy` (a gate bean created lazily, or a caller
without Spring asserting inside its own transaction). `SET TRANSACTION` fails, because the
transaction has already run a query. The caller's transaction is aborted and rolled back. The
caller receives `SHRED-SCHEMA-005` ("unverifiable"), which names the wrong cause. It catches the
refusal and commits: its row is gone (0 rows where 1 is expected).

Example 2 (second probe). The verification is the first thing in the caller's transaction. It
runs inside that transaction, then calls `rollback()` and `setAutoCommit()` on a connection whose
transaction it did not begin. The other three entry points touch nothing but `getAutoCommit` and
`close`.

LOW, as R50-2 and R50-4: a startup inside an open transaction is unusual, and the verification is
refused or correct. But the module ends a transaction it did not begin, on its default path.

Fix (correction, fix pass). In `JdbcSupport.verifySchema(DataSource, boolean, List)`, right after
`getConnection()` and before `SchemaVerification.verify`, refuse a connection with auto-commit
off with `SHRED-SCHEMA-008`, before any statement, as `initializeAndVerifySchema` does. Use a
factory beside `schemaStepInCallerTransaction()` whose message says the verification runs in its
own transaction and that nothing was verified. Do not join the caller's transaction: the
verification needs a fresh read-only snapshot as its first statement. Text: a row for the verify
path in the M21 table of SECURITY-NOTES; the `SHRED-SCHEMA-008` paragraph of SECURITY-NOTES and
the `SHRED-SCHEMA-008` row of `docs/index.md` say it can be a startup condition on the verify-only
path too; one CHANGELOG line. Both probes turn green unchanged.

#### C-RC021B-2, LOW: the release text announces MAINTAIN only

Class: docs-vs-code.

PR 53 added three refusals that no mode relaxes, beside `MAINTAIN`: a `TRIGGER` grant on a
relation owned outside reach (C-PR53-1), a partitioned table or index the runtime role owns with
a partition owned outside reach (C-PR53-3), and a schema the runtime role owns that holds a
relation owned outside reach (C-PR53-6). It also extended O1 to extended statistics expressions
(C-PR53-2) and to `JSON_VALUE ... RETURNING` a domain on PostgreSQL 17 (C-PR53-5), and wrote the
second-hop limit (C-PR53-4, C-PR53-7). SECURITY-NOTES covers each of them. The CHANGELOG does not
name any of them: its O3 sentence says "no `MAINTAIN` on a relation owned outside reach". The
upgrade guide says "Three new refusals" and its step 3 is `MAINTAIN` only. The remedy sentence
of SECURITY-NOTES ("What to do when it refuses") says only "revoke `MAINTAIN` (O3)".

Example. The runtime role owns schema `app`; a migration role created `app.audit`. After the
upgrade, startup refuses with `SHRED-SCHEMA-004`, no mode relaxes it, and neither the CHANGELOG nor
the upgrade guide warned the operator.

Fix (correction, fix pass). CHANGELOG, Unreleased: one entry naming C-PR53-1, -2, -3, -5 and -6
with the limit C-PR53-4/-7, and the O3 sentence of the C-RC021-2c entry lists the four O3 cases.
`docs/upgrading-0.2.1.md`: step 3 lists the four O3 cases, each with a catalogue query that finds
it, and the heading count is corrected. SECURITY-NOTES: the remedy sentence gives the O3 remedy
per case (revoke `MAINTAIN` or `TRIGGER`; give the parent, or the schema, to the owner of what it
holds).

### Interactions checked, no finding

- **Key write against the schema gate.** Key writes take a `VerifiedSchema`, which only the gate
  produces. A key write in a caller's transaction is refused before any statement and any lock
  (`every_key_write_is_refused_before_any_statement_and_lock`, green). The gate's own path in a
  caller's transaction: `initializeAndVerifySchema` refuses untouched (green); `verifySchema` is
  C-RC021B-1.
- **Startup order, both pins.** The starter did not change since 10-21. `JdbcKeyProvider` and
  `JdbcErasureStore` take the gate's schema; the gate verifies in its constructor and throws on a
  refusal, so no key write can run before the owner-context legs have run. `OwnerContext.check`
  runs inside `checkRole`, so both the verify and the initialize path run it, in the same pinned
  window. The owner-context, call-site and function-grants suites are green on 16 and 17.
- **O1 and O3 are not relaxed.** `SchemaVerification.run` adds the strict lines to the problems
  whatever `allow-privileged-runtime-role` says; O2 lines go through the privileged leg and WARN
  at every start. Covered by `owned_schema_rule_is_not_relaxed_by_allow_privileged_runtime_role`
  and the O3 tests, green.
- **PgBouncer and pooled connections.** The caller-transaction refusal reads the client's
  auto-commit flag before any statement, so a pooler plays no part in it. The owner-context
  statement runs on the verification's connection, inside its one transaction, so a
  transaction-mode pooler cannot split it across server sessions. Checked by reading; there is no
  pooler in the suite.
- **Lazy proxy limit.** R50-1 stays a documented limit (row M21x of SECURITY-NOTES and the upgrade
  guide), by the owner's decision of 2026-10-21. It applies to `verifySchema` as it does to the
  other paths; the fix of C-RC021B-1 does not change that.
- **Closed rows have their notes.** C-RC021-1, R50-2, R50-4, R50-5, C-RC021-2, -2a to -2h and
  C-PR51-1 are in the CHANGELOG. C-RC021-2i and -2j (the RESTRICT check folding and reading the
  stored expression trees) are in the SECURITY-NOTES section "Code that runs as another role".
  C-PR51-2 and R50-3 were test and comment corrections with no user-facing change. The PR 53 rows
  are C-RC021B-2.
- **Public text.** The reference guard is clean on the tree. No person or agent name in the
  CHANGELOG, SECURITY-NOTES, README or docs. Older CHANGELOG entries carry finding ids that use
  the review's prefix; finding ids are allowed in public text.

### Not covered in this pass

- A real PgBouncer: by reading only.
- The shell probe suite `tools/cipher-probe-*.sh` was not run here; CI runs it as a required
  check.
