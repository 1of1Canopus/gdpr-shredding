# Security review: fix/key-write-refuses-open-transaction (PR 50)

## Pass 1, 2026-10-21

Head reviewed: 827f068. Base: main d6f88a6. Scope: the C-RC021-1 fix.
`JdbcSupport.inTransaction` now refuses a connection that arrives with
auto-commit off (inside the caller's transaction), with `SHRED-SCHEMA-008`,
before any statement.

**Verdict: MERGE WITH FIXES.** Fix R50-2 and R50-3 on this branch.
R50-1 is a DESIGN STOP (design page first). It gets its own PR and blocks
the 0.2.1 tag, not this PR: the gap it describes is on main already for
the read and erasure paths, and this PR does not widen it.

### Build

| Run | Result |
|---|---|
| `./mvnw -q clean verify` on 827f068 (Docker up) | exit 0; 1,397 tests (core 1,053, starter 319, sample 25), 0 failed, 0 skipped |
| `CipherProbeRc021Test` (fix pass, unchanged) | 2 run, 0 failed |
| `CipherProbePr50Test` (this pass, kept internal) | 5 run, 2 green, 3 red |

### What was checked, with probes

1. **Every key write goes through the refusal.** The write paths in core
   and starter are `JdbcKeyProvider.currentForWrite`, `recordEncryptions`
   and `rotate` (all `JdbcSupport.inTransaction`), and the erasure
   (`inReadCommittedTransaction`, already refused). There is no reseal and
   no bucket move in this module. `every_key_write_is_refused_before_any_statement_and_lock`
   runs the three writes inside a caller transaction through
   `TransactionAwareDataSourceProxy`: each is refused with
   `SHRED-SCHEMA-008`; green. One more path opens its own transaction on
   whatever connection arrives: `JdbcSupport.initializeSchema`. See R50-2.
2. **A read on a caller transaction still works.**
   `a_read_inside_the_caller_transaction_still_works`: `forRead` inside
   `@Transactional` returns the key; green.
3. **The refusal comes before any statement.** A recording connection
   proxy shows the only calls before the refusal are `getAutoCommit` and
   `close`: no statement, no `setAutoCommit`, no commit, no rollback.
   `pg_locks` shows no advisory lock while the caller transaction is still
   open. The caller's insert is still pending and rolls back. Green.
4. **Code and message are stable and documented.** `SHRED-SCHEMA-008`
   (`ErrorCodes.SCHEMA_NAME_ISOLATION`), the existing code. The
   `docs/index.md` row, SECURITY-NOTES row M21w, `upgrading-0.2.1.md` and
   the CHANGELOG all say the same thing, with an example. The message
   holds no secret and no caller data.
5. **Strictness of the original probe.** My probe
   `probe_key_write_inside_a_caller_transaction_commits_the_caller_rows`
   accepts any exception; the row count decides. The fix pass added
   `key_write_inside_a_caller_transaction_is_refused_with_schema_008`,
   which pins the code and the row count, but only for `currentForWrite`
   and without the "before any statement" property. Not enough: see R50-3.

### Findings

| Id | Severity | Finding | Probe (red on 827f068) | Fix |
|---|---|---|---|---|
| R50-1 | LOW | The refusal trusts the JDBC auto-commit flag. A `LazyConnectionDataSourceProxy` over a `TransactionAwareDataSourceProxy` reports the pool default (`true`) before it fetches its target. The target it fetches later is the caller's connection. The module then commits the caller's transaction. Same on the read path (`readVerified` begins and commits its own read transaction), against row M21. LOW because Spring's own javadoc asks for the opposite wrapper order. | `probe_lazy_proxy_hides_the_caller_transaction_and_the_key_write_commits_it`, `probe_lazy_proxy_hides_the_caller_transaction_and_a_read_commits_it` | DESIGN STOP, below |
| R50-2 | LOW | `JdbcSupport.initializeSchema(DataSource)` runs `inUncheckedTransaction`, which sets auto-commit off and commits, on a connection that may already be in the caller's transaction. Called inside `@Transactional` through `TransactionAwareDataSourceProxy`, it commits the caller's rows. | `probe_initialize_schema_inside_a_caller_transaction_commits_the_caller_rows` | Correction, below |
| R50-3 | INFO | The tests pin the refusal for `currentForWrite` only, and never pin "before any statement". A later change that moves `rotate` or `recordEncryptions` off `inTransaction`, or that runs `DatabaseIdentity.require` before the check, stays green. | (coverage gap; my green test shows the property holds today) | Correction, below |

Example for R50-1. A team configures
`new LazyConnectionDataSourceProxy(new TransactionAwareDataSourceProxy(pool))`
for the module. Its service inserts an order, asks for a key, then fails and
rolls back. The order row stays in the database.

Example for R50-2. A one-off job runs `JdbcSupport.initializeSchema(ds)`
inside a transaction that also writes a migration marker. The job then fails
and rolls back. The marker stays.

#### R50-1, DESIGN STOP (builder writes a one-page design, security review reviews it before code)

Property that must hold: the module never commits or rolls back a server
transaction it did not begin, whatever a JDBC wrapper reports about
auto-commit. A refusal leaves the caller's transaction as it was.

Paths the design must cover, one test each:
`JdbcSupport.inTransaction` (three key writes),
`inReadCommittedTransaction` (erasure; same code shape, suspected, not
probed in this pass), the auto-commit branch of `readVerified` (probed red),
and `inUncheckedTransaction` (schema step). The design states what
server-side fact it reads, whether that read is a statement inside the
caller's transaction, and how it reconciles that with "before any
statement" in SECURITY-NOTES M21w.

#### R50-2, correction (fix pass)

- Class `JdbcSupport`, method `inUncheckedTransaction`: after
  `ds.getConnection()`, if `!c.getAutoCommit()` throw a
  `ShreddingException` with `ErrorCodes.SCHEMA_NAME_ISOLATION` before
  `inTransaction(c, work)`, message in the style of
  `keyWriteInCallerTransaction` ("the schema step runs in its own
  transaction ... nothing was created").
- `docs/index.md`, `SHRED-SCHEMA-008` row: add the schema step; the row
  says -008 is never a startup condition, so say that this one case can
  appear when `shredding.jdbc.initialize-schema=true`.
- Test: `probe_initialize_schema_inside_a_caller_transaction_commits_the_caller_rows`
  from `internal/gdpr-shredding/probes/CipherProbePr50Test.java`, plus an
  assertion on the code.

#### R50-3, correction (fix pass)

Add `every_key_write_is_refused_before_any_statement_and_lock` and
`a_read_inside_the_caller_transaction_still_works` from the same probe file
to `CipherProbeRc021Test` (or a new test class). Keep my original probe as
it is: it must stay green whatever form the refusal takes.

Attempt closed without a finding: a server transaction opened by a raw
`BEGIN` on a connection in auto-commit. No Spring path hands such a
connection to a second caller on the same thread; only a pool that leaks
an open transaction does, and that is outside this module.

## Pass 2, 2026-10-21

Head reviewed: 186748f. **Verdict: MERGE WITH FIXES** (R50-4, R50-5).

| Id | Status | Evidence |
|---|---|---|
| R50-1 | open LOW, written limit for 0.2.1 by the owner's decision | lazy proxy probes stay red; the register row stays open |
| R50-2 | fixed | `probe_initialize_schema_inside_a_caller_transaction_commits_the_caller_rows` green 3 runs of 3; code `SHRED-SCHEMA-008` asserted |
| R50-3 | fixed | `every_key_write_is_refused_before_any_statement_and_lock`, `a_read_inside_the_caller_transaction_still_works` green 3 of 3 |
| R50-4 | new, LOW | red 3 of 3, below |
| R50-5 | new, INFO | below |

**R50-4 (LOW): `initializeAndVerifySchema` commits the caller's transaction.**
Same control, one more path; not part of R50-1, because a plain
`TransactionAwareDataSourceProxy` reaches it. Example: startup with
`shredding.jdbc.initialize-schema=true` inside a caller transaction that
already inserted a row; the method turns auto-commit off, runs the DDL and
verification, and commits that row. Probe:
`probe_initialize_and_verify_schema_inside_a_caller_transaction_commits_the_caller_rows`
(internal probe file `CipherProbePr50bTest`, red on 186748f: 1 row
committed, expected 0). Fix, in `JdbcSupport.initializeAndVerifySchema(DataSource, boolean, List)`,
right after `ds.getConnection()` and before `getAutoCommit` is saved:
`if (!c.getAutoCommit()) { throw schemaStepInCallerTransaction(); }`.
Add the probe to `CipherProbePr50Test`. A failed verification there also
calls `c.rollback()`; the same check stops that rolling back the caller's work.

**R50-5 (INFO): the R50-1 limit is not written where users read it.**
SECURITY-NOTES row M13 says the lazy proxy is "accepted", and M21/M21w say
the caller's transaction is never committed. Example: a team reads M13,
puts the lazy proxy outside the transaction-aware one, and loses its
rollback. Fix: add row M21x to SECURITY-NOTES: "`LazyConnectionDataSourceProxy`
around `TransactionAwareDataSourceProxy` (wrong order per Spring's javadoc):
not detected in 0.2.1; key writes, reads and the schema step can commit the
caller's transaction. Put the transaction-aware proxy outermost (C-R50-1)."
Same sentence in `upgrading-0.2.1.md` next to the key-write paragraph.

Tests run: `CipherProbePr50Test` (branch) plus `CipherProbePr50bTest`
(mine), three runs, results identical each run.
