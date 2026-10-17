# Security review: fix/moving-target-datasource (C-PR-1b)

## Pass 1, 2026-10-17

Head reviewed: `f530955` ("chore(core): merge main a9e80c3 into the moving-target branch").
Finding under verification: C-PR-1b (MEDIUM, framework path). One `DataSource` object was
verified at boot. Later it could reach another database (routing pool, refreshed proxy, new URL,
failover), and the stores wrote there.

### Verdict: MERGE WITH FIXES

C-PR-1b is fixed. Its probe is green. Every item of the round-2 design review is met by a test or
a mutation, with one exception that was accepted before this pass (reads cost two statements,
decision C-48). This pass found two LOW gaps, both in tests and rules around the fix, not in the
check itself. Under the no-allowance rule both are fixed before merge. One round-2 condition is
still open: the managed-service facts (item 6) must be in the PR body before merge.

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -B -ntp clean verify`, Docker up | green: core 629, starter 312, sample 25; 0 failures, 0 errors, 0 skipped; JaCoCo gate met; 284 s |
| `StandbyIdentityTest` (real `pg_basebackup -R` standby, then `pg_promote()`) | ran, 3 tests, 13 s; not skipped |
| Earlier `CipherProbe*` classes on this head | all green (core and starter) |
| `tools/cipher-probe-c-pr-1-split-package.sh` | GREEN by a sealing violation (the planted class compiles, the JVM refuses it) |
| `tools/cipher-probe-c-pr-1-starter-scope.sh` | GREEN: two architecture rules refuse the planted class |
| `tools/cipher-probe-c-pr38-p2-changelog-codespans.sh` | GREEN |
| `tools/cipher-probe-release-pipeline.sh` | 77 fixed, 3 weak (M1, N1, post-release sources jar), the same three as on `main`; this PR touches no release file |
| The builder's 12 mutations, re-run | all 12 caught (RED counts 24, 2, 9, 2, 1, 1, 1, 1, 1, 1, 2, 2) |
| This review's 7 mutations, whole core suite | 4 caught by the PR's tests (C, D, E, F); 3 survive (A, B, G): C-PR42-2 |
| New probes from this pass | 6 tests: 1 RED (C-PR42-1), 3 witnesses for C-PR42-2 (green on this head, red under A, B, G), 2 confirmations |

### Round-2 items, checked one by one

| Item | Check | Result |
| --- | --- | --- |
| 1 statement order, no `setReadOnly` | `each_entry_point_runs_the_check_before_the_work`; the 008 tests; mutation 10 | holds. The erasure path runs `PIN_SQL`, the isolation read-back, then the check |
| 2 standby in recovery refused | `standby_in_recovery_refuses_reads_and_writes`; mutation 6; review mutation F (verification accepts recovery) | holds, at runtime and at boot |
| 3 qualified operators, exactly one row | mutations 7 and 8 | holds |
| 4 caller's transaction not ended | `transaction_aware_proxy_inside_a_caller_transaction_reads_without_committing_it`; mutation 9 | holds. The check inside that branch has no killing test: C-PR42-2 |
| 5 M16 stated honestly | SECURITY-NOTES "Backups" and path table read | holds |
| 6 managed-service facts | not in the PR yet | open condition, see below |
| 7 cost counted in statements | `each_store_call_adds_one_fingerprint_statement` | writes and erasures: one statement. Reads: fingerprint plus `COMMIT`, on every decrypt. Accepted by decision C-48; not reopened |
| 8 basebackup standby in `verify` | ran, 13 s | holds |
| 9 `getConnection` only in `JdbcSupport` | both architecture tests; mutation 11 | the rule holds for the three names it lists. It misses other ways to open a connection: C-PR42-1 |

### Adapted earlier probes: weakening or not

- **C-13-4** now reads the server's `transaction_read_only` instead of the driver flag
  `isReadOnly()`. Not a weakening. The driver flag is a client claim; the server setting is the
  real witness. Review mutation E (drop `READ ONLY` from the verification's `SET TRANSACTION`)
  turns it red.
- **C-13-3** now looks up the three-argument constructor and asserts it is not public. Not a
  weakening. `VerifiedSchemaCapabilityTest` still asserts exactly one constructor.
- **Split-package and starter-scope release probes** plant a class that calls the
  three-argument constructor. Not a weakening. Both still turn green for the right reason (a
  sealing violation; two architecture rules), not because the planted class fails to compile.

### What was checked and holds

- **The original probe is green.**
  `probe_datasource_whose_target_changes_after_verification_writes_unverified` passes. Under
  mutation 1 it goes red with 23 other tests.
- **Same physical connection for check and work.** Each entry point takes one `Connection` and
  hands that object to the check and to the work. `check_and_work_share_one_transaction_on_every_entry_point`
  compares `pg_backend_pid()` and the transaction start time. Mutations 4 and 4b turn it red.
- **A connection cannot be open on another database inside the same transaction.** PostgreSQL
  binds a session to one database at connection start; there is no statement that switches it.
  So a check on a session covers every later statement of that session.
- **`search_path` cannot move the schema bind.** The fingerprint binds the schema by its name,
  qualifies every catalogue name, and every module statement qualifies its relations.
  Confirmation `confirm_search_path_on_the_moved_connection_cannot_redirect_the_schema_bind`: a
  connection whose path puts a role-owned schema with a `shredding_data_key` table first passes
  the check, and the row lands in `public`, not in the role's schema. Green.
- **`pg_control_system()` denied.** At boot: `SHRED-SCHEMA-005` with the `GRANT` (M17 test). After
  boot: confirmation `confirm_pg_control_system_revoked_after_startup_refuses_every_call`. Every
  write and read refuses with 012, health is DOWN, nothing is written. Fail closed both times.
- **The read `COMMIT` never ends a caller's work.** A connection that arrives with auto-commit
  off takes a branch that neither commits nor rolls back nor sets read-only (M21 test; mutation 9).
- **Cost is per call.** Each store call takes its own connection and runs one fingerprint. A
  decrypt calls `forRead` on every cache hit too, so each decrypt pays the read cost. This is
  stated in SECURITY-NOTES and accepted by decision C-48.
- **`SET ROLE` between check and write.** No module code runs between the check and the work. A
  startup option `-c role=...` on a moved connection is refused by the `current_user` leg (witness
  below). The judgement of a role switched inside the session stays with C-PR-1c.
- **Considered, not a finding.** On a pool configured with auto-commit off, the read path takes
  the caller branch, so the read is not made read-only and is not committed. The pool's own reset
  rolls it back at `close()`. `main` read the same way, and the erasure path already refuses such
  a pool with `SHRED-SCHEMA-008`. No change.

### Findings

**C-PR42-1 (LOW, framework path). The "only `JdbcSupport` takes a connection" rule misses four
ways to open one.**

Both architecture rules match `getConnection` on a `DataSource` type, `DriverManager.getConnection`
and `Driver.connect`. SECURITY-NOTES says "`JdbcSupport` is the only class that takes a connection,
in core and in the starter". The JDK and Spring offer other ways, and the starter has spring-jdbc
on its compile path through spring-boot-starter-data-jpa. No production class uses them today.
The rule is the control that keeps it so, and it does not.

Example. A later starter change reads the erasure log with
`new JdbcTemplate(gate.dataSource()).query(...)`. The template opens its own connection. No
fingerprint runs, so after a routing switch the read comes from the wrong database. Both
architecture tests stay green.

Repro: `CipherProbePr42ArchTest.probe_connection_rule_misses_builder_pooled_and_spring_paths`
evaluates the rule's own predicate on five planted classes. RED on `f530955`: the rule reports
none of `ByConnectionBuilder` (`ds.createConnectionBuilder().build()`), `BySpringUtils`
(`DataSourceUtils.getConnection(ds)`), `ByJdbcTemplate` (`new JdbcTemplate(ds).queryForObject`)
and `ByPooledConnection` (`getPooledConnection().getConnection()`, `getXAConnection().getConnection()`).
The control class (`ds::getConnection` as a method reference) is reported.

Fix (fix pass, core and starter test trees, no production change):
1. Extend `HexagonalArchitectureTest.ConnectionAccess.TAKES_A_CONNECTION`, and the starter copy in
   `StarterArchitectureTest.getConnection_is_called_only_inside_JdbcSupport`, to also match:
   `createConnectionBuilder` on a `DataSource` type; `build` on `java.sql.ConnectionBuilder`;
   `getConnection` on `javax.sql.PooledConnection`; `getPooledConnection` on
   `javax.sql.ConnectionPoolDataSource`; `getXAConnection` on `javax.sql.XADataSource`; any
   access to `org.springframework.jdbc.datasource.DataSourceUtils`; any access to a class in
   `org.springframework.jdbc.core..` (templates, `JdbcClient`, `SimpleJdbcInsert`,
   `SimpleJdbcCall`).
2. Make the starter predicate a named constant and add a starter twin of the probe, so both
   copies are tested.
3. SECURITY-NOTES, "Which database each connection reaches": list what the rule covers, in one
   line, instead of "the only class that takes a connection".
4. Copy `CipherProbePr42ArchTest` from the internal probes folder into
   `gdpr-shredding-core/src/test/java/com/housedevinci/shredding/architecture/` first. It must
   turn green.

**C-PR42-2 (LOW, framework path). Three legs of the check can be removed and the PR's suite stays
green.**

The check compares the schema oid and `current_user`, and it runs inside a caller's transaction.
The CHANGELOG and SECURITY-NOTES state all three. No PR test fails when one of them is removed.
A later refactor could drop any of them in silence.

Example. A delegate moves to a data source on the same database, same login, with the startup
option `-c role=shadow`. Only `current_user` differs. Today the store call refuses with
`(different: current role; verified "shredding_app", got "shadow")`. Remove that comparison and
every PR test still passes.

Repro, mutations run on the whole core suite of `f530955` (635 tests with this pass's probes):

| Mutation | PR tests red | Killed only by |
| --- | --- | --- |
| A: drop the schema oid comparison | 0 | `probe_schema_recreated_under_the_verified_name_is_refused_only_by_the_schema_leg` |
| B: drop the `current_user` comparison | 0 | `probe_current_role_moved_by_a_startup_option_is_refused_only_by_the_current_user_leg` |
| G: no check in the caller-transaction branch of `readVerified` | 0 | `probe_read_inside_a_caller_transaction_on_a_moved_target_is_refused` |

For contrast, the review's mutation C (drop `session_user`) is caught by the starter's M10 test.

Fix (fix pass, core test tree only):
1. Move the three witnesses from `internal/gdpr-shredding/probes/CipherProbePr42Test.java` into
   `DatabaseIdentityCheckTest`, as `current_role_moved_by_a_startup_option_refuses`,
   `schema_recreated_under_the_verified_name_refuses` and
   `read_inside_a_caller_transaction_on_a_moved_target_refuses`.
2. Add mutations A, B and G to the builder's mutation table
   (`internal/gdpr-shredding/probes/cipher-mutations-pr42.py` has the exact patterns) and show
   each RED in the PR body, then restored.

### Open condition from round 2 (not a finding)

**Item 6, managed services.** The round-2 ruling asked the PR to record, for RDS PostgreSQL,
Aurora PostgreSQL, Cloud SQL and Azure Flexible Server, whether a non-superuser runtime role can
run `pg_control_system()` and gets a value unique to the cluster. The facts are not in the PR.
They must be in the PR body, cited (a vendor document or a real try), before merge. If any service
denies the call or returns a shared value, that is a design page and its own PR before the 0.2.1
tag. This review did not try any managed service.

### Decisions not reopened

- C-48: a read pays the fingerprint and a `COMMIT` for 0.2.1. Not reopened.
- C-49: a failed check keeps code `SHRED-SCHEMA-012`. Not reopened.

### Second pass

The second pass checks that `CipherProbePr42ArchTest` is green in both modules, that mutations A,
B and G are red, and attacks only what the fix pass changes.
