# Security review: fix/verify-schema-logs-privileged-mode (C-PR-1d)

## Pass 1, 2026-10-17

Head reviewed: `b27015d` ("fix(core): log one line per schema verification at every call").
Finding under re-verification: C-PR-1d (LOW). Core `JdbcSupport.verifySchema(ds, true)` and
`initializeAndVerifySchema(ds, true)` accepted a privileged runtime role and logged nothing.

### Verdict: MERGE WITH FIXES

C-PR-1d is closed: its probe is green, and the mutations are caught. The fix pass opened one gap.
The privileged-mode WARN no longer names the property that put the application in that mode
(C-PR41-1, LOW). One older text gap on the same path is also listed (C-PR41-2, INFO). Neither
needs a new mechanism. Under the no-allowance rule both are fixed before merge.

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -B clean verify`, Docker up | green: core 578, starter 303, sample 25; 0 failures, 0 errors, 0 skipped; JaCoCo gate passed |
| First `verify` run | 1 error: `CipherProbePr25Pass2StarterTest` container start (SSL handshake to the fresh container, `ContainerLaunchException`). Rerun alone: 2/2 green. Second full run: green. Not an assertion |
| Earlier `CipherProbe*` classes on this head | 33 in core, 56 in the starter, 4 in the sample, all green |
| The three starter tests the fix pass edited, run as they are on `main` | 3 RED: `CipherProbeRc020StartupTest` case [5] and `CipherProbeSchemaGateTest` t13 (property name missing, see C-PR41-1); `StoreDataSourceBindingStarterTest` (expects an INFO line; the test role is privileged, so the line is now a WARN: an expected change, not a finding) |
| Mutation M1 (fix pass's own): core WARN to `debug` | caught: 3 of 4 new core tests red, plus Rc020 [5], Rc020 `c_pr_1d...`, SchemaGate t13 and t14, StoreDataSourceBinding |
| Mutation M2 (this review): log once per database, schema and role, then stay silent | caught: 2 of 4 new core tests red (they share one pool), Rc020 [5], Rc020 `c_pr_1d...`, SchemaGate t13, StoreDataSourceBinding |
| New probes from this pass | 4 tests: 2 RED (C-PR41-1, C-PR41-2), 2 GREEN confirmations |

### What was checked and holds

- **The original probe is green.** `probe_core_privileged_mode_mints_a_verified_schema_without_any_warn`
  in `SchemaVerificationLoggingTest` passes. Under M1 it goes red.
- **One line per call, never cached.** `logVerdict` runs on every return of `verifySchema` and
  `initializeAndVerifySchema`. These are the only two paths that return a `SchemaVerdict`
  (`SchemaVerification` has one constructor call). Probe
  `probe_second_verification_on_the_same_pool_is_silent` makes three calls on one pool and counts
  three WARN lines: green. Under M2 it goes red.
- **One line on the starter path.** The gate no longer prints the summary. The health indicator
  reads `gate.verdict()` and never verifies again, so health polls do not flood the log.
- **The level cannot be lowered by a starter default.** The starter ships no `logging.*` property,
  no `EnvironmentPostProcessor`, no logback file and no `LoggingSystem` call. Only the operator's
  own logging configuration can hide the WARN.
- **No secret in the line.** The line holds `current_user`, `current_schema()`,
  `current_database()` and the leg texts. It never reads the URL. Probe
  `probe_verification_line_leaks_the_password_or_the_url` puts the password in the JDBC URL
  (`?user=...&password=...`) and finds neither the password nor `jdbc:` nor `password=` in the
  output: green.
- **Considered, not a finding.** Role, schema and database names are printed raw. A quoted name
  with a newline could forge a log line. Only the database administrator chooses these names, and
  `main` printed the same fields. No change.

### Findings

**C-PR41-1 (LOW, weaker mode not named). The privileged-mode WARN no longer names
`shredding.jdbc.allow-privileged-runtime-role`.**

Before PR 41 the starter WARN began with `shredding.jdbc.allow-privileged-runtime-role=true`. It
was removed, and core's WARN replaces it. Core's WARN names the role and the legs. It does not say
which switch let a privileged role boot. It does not say that setting the switch back to `false`
makes the same start refuse. Every other weaker mode of the starter names its property in its
WARN (`shredding.dev-mode`, `shredding.allow-second-level-cache`, `shredding.erasure-log.unkeyed`,
`shredding.jdbc.initialize-schema`). The fix pass also rewrote two earlier review probes
(`CipherProbeRc020StartupTest` [5], `CipherProbeSchemaGateTest` t13) so they no longer assert the
property name. Run as they are on `main`, both are red on this head.

Example. An operator sets `shredding.jdbc.initialize-schema=false` and
`shredding.jdbc.allow-privileged-runtime-role=true`, and logs in as the owner. The boot log says:
"the runtime role test is privileged over the shredding objects ... move the application to a
non-privileged role". Nothing in the log says which line of `application.yml` allowed this. Remove
the property and the same start refuses with SHRED-SCHEMA-004.

The `initialize-schema=true` path is not affected: its own starter WARN names
`shredding.jdbc.initialize-schema=true`.

Probe: `CipherProbePr41Test.probe_privileged_mode_startup_never_names_the_property_that_allows_it`
(starter). Boot 0 creates the schema. A control boot in strict mode refuses. Boots 1 and 2 with the
property on: core WARN present, no WARN names the property. RED on `b27015d`. With a scratch
starter WARN (below, applied in the review's own worktree and reverted) the probe is green, and the
branch's Rc020 (8) and SchemaGate (12) stay green.

Fix (fix pass):
- `ShreddingSchemaGate.warn(JdbcProperties)`: when `initialize-schema` is false,
  `allow-privileged-runtime-role` is true and `!verdict.runtimeRoleIsUnprivileged()`, log one WARN
  that names `shredding.jdbc.allow-privileged-runtime-role=true` and says that setting it to
  `false` (the default) makes this start refuse with SHRED-SCHEMA-004. It must not repeat core's
  text: the probe asserts exactly one "is privileged over the shredding objects" line.
- Restore the property assertion in `CipherProbeRc020StartupTest` case [5]
  (`shredding.jdbc.allow-privileged-runtime-role=true`). In `CipherProbeSchemaGateTest` t13 add a
  separate `anyMatch` on a WARN naming the property, and keep the new core-line assertions (the
  legs stay in core's line, the property in the starter's line).
- Add `CipherProbePr41Test` to the starter suite.
- CHANGELOG entry: replace "The privileged WARN no longer names the starter property" with the
  two-line split (core names role and legs; the starter names the property).

**C-PR41-2 (INFO, core-only caller sent to a Spring property).** The SHRED-SCHEMA-004 refusal
from core ends with "set shredding.jdbc.allow-privileged-runtime-role=true, which warns at every
startup". Core never reads that property. A caller without Spring switches the mode with the
second argument of `verifySchema`. Present on `main` too. It is on the path this PR fixes: the
core-only user of the privileged mode.

Example. A plain Java service calls `JdbcSupport.verifySchema(ds)` as the owner. The exception
tells it to set `shredding.jdbc.allow-privileged-runtime-role=true`. It adds that line to a file
nobody reads, and the start still refuses. The words `verifySchema(ds, true)` appear nowhere.

Probe: `CipherProbePr41CoreTest.probe_core_refusal_points_a_core_only_caller_at_a_property_core_never_reads`
(core). RED on `b27015d`.

Fix (fix pass): `SchemaVerification.privilegedRemedy()`: name both switches. Starter:
`shredding.jdbc.allow-privileged-runtime-role=true`. Core: `JdbcSupport.verifySchema(ds, true)` or
`initializeAndVerifySchema(ds, true)`. Both warn at every call. Add `CipherProbePr41CoreTest` to the
core suite.

### Close condition

Both probes green, the two restored probe assertions green, full `verify` green. C-PR41-2 is text
only and closes on its probe going green. C-PR41-1 changes a log line; it closes at pass 2.
