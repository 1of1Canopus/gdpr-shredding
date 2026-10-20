# Security review: whole-module pass for 0.2.1

## 2026-10-21, release candidate, main at d6f88a6

**Verdict: NOT TAG.** Two MEDIUM findings. Every finding is fixed before the tag (no allowance).

Scope: one adversarial pass over the whole module, every mechanism interacting. The checklist is
the threat model of the spec review (2026-09-08). Changes since v0.2.0: per-call database
fingerprint (C-PR-1b, PR 42), login-role and reach check with the login marker (C-PR-1c, PR 45),
function-grants audit with pinned baselines and the caller-objects leg (C-PR45-3, PR 46 and 47),
deterministic probe rewrites (PR 43), CI renames.

### Numbers

| Item | Result |
|---|---|
| `./mvnw -q clean verify`, reactor root | exit 0 |
| Tests run / failed / errored / skipped | 1395 / 0 / 0 / 0 |
| Existing `CipherProbe*` tests | inside the 1395, all green, unchanged |
| New probes | 2, both red on d6f88a6 |
| Postgres image | Testcontainers, PostgreSQL 16 pin of the suite |

### Findings

| Id | Severity | One line | Probe |
|---|---|---|---|
| C-RC021-1 | MEDIUM | a key write inside the application's own transaction commits that transaction | `probe_key_write_inside_a_caller_transaction_commits_the_caller_rows` |
| C-RC021-2 | MEDIUM | the caller-objects leg does not judge trigger slots, so hand-made native code refused by leg 4 stays reachable as a trigger | `probe_hand_made_native_function_reachable_as_a_trigger_passes_the_gate` |

Both probes are in `CipherProbeRc021Test` (core, package `adapter.jdbc`). The file is kept in
the internal probes folder of the module. The fix pass adds it to the suite before it touches
production code.

#### C-RC021-1, MEDIUM: the write path commits a transaction it did not begin

Class: lock/window (transaction scope).

0.2.1 documents path M21: a call through `TransactionAwareDataSourceProxy` inside the
application's `@Transactional`. `JdbcSupport.readVerified` handles it: the check and the read run
inside the caller's transaction, and nothing is committed. `inReadCommittedTransaction` (erasure)
refuses such a connection untouched. The third entry point, `JdbcSupport.inTransaction(VerifiedSchema,
SqlWork)`, does neither. It keeps auto-commit off, runs the work, and calls `commit()` on the
caller's transaction. It was like this in v0.2.0 (line 223); 0.2.1 makes the configuration a
documented one for reads and leaves the write half unhandled.

Example. The application inserts an order row, then the first encrypted write for a new subject
calls `JdbcKeyProvider.currentForWrite`. The module commits. The application then fails
validation and rolls back. The order row stays. The probe shows it: 1 row where 0 is expected.
The same holds for `recordEncryptions` and `rotate`. On a refusal inside the work, the module
also rolls back the caller's work itself, which is the caller's decision to make.

Fix (correction, fix pass): in `JdbcSupport.inTransaction(VerifiedSchema, SqlWork)`, refuse a
connection that arrives with auto-commit off, before any statement, with a typed
`ShreddingException` and a stable code, as `inReadCommittedTransaction` does. The message says
that key writes run in their own transaction and names `TransactionAwareDataSourceProxy` as the
cause. Do not join the caller's transaction: a key row that commits or rolls back with the
application's row changes the C-PR-1c and erasure-race reasoning, which is a design question.
Document the refusal next to M21 in `docs/upgrading-0.2.1.md` and in the M21 row of
SECURITY-NOTES. The probe accepts a refusal and asserts the caller's row did not commit.

#### C-RC021-2, MEDIUM: trigger slots are outside the caller-objects leg

Class: restricted-role visibility.

The property of C-PR45-3 covers native code made by hand, and R6 covers "objects that call a
function with no EXECUTE check". Statement 3 judges three kinds of caller object: aggregates,
operators and languages. Design row G1 put triggers and event triggers aside as "refused by
signature" and also measured that a revoked trigger function still fires. The signature argument
holds for the functions the server ships withheld. It does not hold for native code made by hand:
whoever creates it chooses its signature, including `RETURNS trigger`.

Example (the probe, with a harmless built-in symbol and no payload). A superuser creates
`public.rc021_t() RETURNS trigger LANGUAGE internal`. While PUBLIC may execute it, the gate
refuses with `SHRED-SCHEMA-004` (leg 4). The probe checks that first. Then EXECUTE is revoked
from PUBLIC and the function is attached as a `BEFORE UPDATE` trigger on a table the runtime
role may update. The runtime role's update fires it (the no-op update is suppressed, so the
function ran). The gate now verifies clean. The same native code is reachable; only the path
changed.

DESIGN STOP (builder, design addendum to the C-PR45-3 page, reviewed before code). Property to
hold: no native function that legs 1 to 6 would refuse for reach or PUBLIC is reachable by reach
or PUBLIC through a trigger or an event trigger, whatever its ACL and whoever owns it. Paths the
addendum must cover, one test each:

- `pg_trigger.tgfoid` on a table, partition or view where reach holds INSERT, UPDATE, DELETE or
  TRUNCATE, including column-level UPDATE and grants through a group;
- the same on a table reach can write only through a view, a rule, or a foreign key action;
- `pg_event_trigger.evtfoid`, which any role that can run DDL fires (for example
  `CREATE TEMP TABLE`). Suspected, not reproduced in this pass;
- disabled triggers (`tgenabled = 'D'`) and `ALTER TABLE ... ENABLE ALWAYS` or `REPLICA`.

The design states which identity runs the function in each case and whether a SECURITY DEFINER
wrapper in SQL stays under limit L19.

### Interactions checked, no finding

- **Moving-target fingerprint and function grants agree on "the connection".** Verification runs
  in one transaction, so one server backend judges both the login and the grants. Every store call
  runs the fingerprint and the work in one transaction. Under a transaction-mode pooler a backend
  serves one login only, so a marker set on it cannot be reused by another login. Checked by
  reading; there is no pooler in the suite, so this is not tested.
- **Startup order.** `JdbcKeyProvider`, `JdbcErasureStore` and every bean that reaches the
  database take the `ShreddingSchemaGate` bean by constructor. The gate verifies in its
  constructor and throws on refusal, so no key operation can run before verification ends.
- **Weaker modes WARN at every start.** A non-empty accepted-extensions list logs a WARN at every
  verification, on both the verify and the initialize path (`JdbcSupport.acceptedExtensions`).
  `allow-privileged-runtime-role` and a privileged verdict WARN at every start
  (`logVerdict`, `ShreddingSchemaGate.warn`). Checked by reading and by the green suite.
- **Tool probes run real code.** The release-pipeline probe runs step bodies. The split-package
  probe compiles and runs a planted class against the built jar. None of the four only greps YAML.

### Not covered in this pass

- PostgreSQL 17: the probes ran on the 16 pin only.
- Event triggers: suspected under C-RC021-2, not reproduced.
