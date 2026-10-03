# Security review: feat/read-back-bracket (PR 18)

## Pass 1, 2026-10-03

Head reviewed: `f3fc861` (the builder's work plus the merged PR 13, via `main` at `415fa62`).
Scope: `git diff 415fa62...f3fc861`. There are two mechanisms, both from the name-resolution design page,
revision 2.4:

1. the framework-rendered blind-index read-back runs inside a one-statement window that replaces
   `search_path` with `pg_catalog, pg_temp` and restores the captured bytes;
2. startup refuses a `@Shredded` or `@BlindIndex` entity whose table names no schema.

The checklist was the design page's threat model (N-1, N-2, M2, M3, M8, M9, T7, T10, T15b, T19) and its
integration surface. This PR touches no release, CI or packaging file, so the release hygiene
checklist does not apply.

Method: the branch was built and run. Every attack below was run against PostgreSQL 16 on the
digest the module's tests pin, through `JdbcSupport.inOneStatementWindow` directly or through a
live Spring Boot context and `ErasureService`. Each finding has a probe that fails on this head.
Following this lane's rule, the probe sources are kept outside the public tree. The fix pass adds them
to the suite before it changes any production code, under the class names given per finding.

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -B clean verify` | green, exit 0, Docker up |
| Tests | 495 run, 0 failures, 0 errors, 0 skipped (core 254, starter 224, sample 17), same as the verifier's count |
| Earlier review probes (`CipherProbe*`, 61 classes) | unchanged and green |
| New probe tests from this pass | 5, all RED on `f3fc861` (core 4, starter 1) |
| Attacks reclassified after a repro attempt | 2 findings attempted and closed (C-18-1, and the renamed-entity branch), plus the two open mutation rows |

### Verdict: MERGE WITH FIXES

There is no HIGH and no MEDIUM. Under the no-allowance rule, the two LOWs and the three INFOs below are
fixed before merge.

What the mechanism gets right, confirmed by execution:

- The window replaces the path; it does not prefix it.
- The restore is bound, so quote and statement-terminator shapes round-trip.
- An auto-commit connection is refused before anything changes.
- A failure inside the window surfaces as itself. This holds under pgjdbc `autosave=always` too: the
  real `42P01` propagates, the restore succeeds, nothing is suppressed, and the path is the arrived
  one before and after commit.
- A transaction-local or a session-level `SET search_path` issued by code inside the window is
  overwritten by the restore in both cases, and the session leaves the transaction carrying the
  bytes it arrived with.
- The rendered read-back is one statement with a two-part relation and no type name:
  `select count(*) from public.pr18_restricted_note prn1_0 where (...) and prn1_0.owner_id=? and prn1_0.tenant_id=? and prn1_0.email_idx is not null`.

### Findings

| id | severity | one line |
| --- | --- | --- |
| C-18-2 | LOW | a mapping's own SQL fragments (`@SQLRestriction`, auto-enabled `@Filter`) are rendered into the window; an unqualified name in them fails every erasure of that entity, and neither SECURITY-NOTES nor the upgrade page says so |
| C-18-3 | LOW | three texts tell operators that a `LANGUAGE sql` function body is immune inside the window; a string-body SQL function fails there exactly like plpgsql |
| C-18-4 | INFO | a failure to establish the pin (steps 1 to 3) is reported as `SHRED-KEY-UNAVAILABLE`, not `SHRED-SCHEMA-008` as the design (section 4.4) and the window's own javadoc state |
| C-18-5 | INFO | the public `BlindIndexResidual` SPI now always runs inside the window, and its "strict contract" does not mention the window |
| C-18-6 | INFO | ruling on the PR's QUESTION 2: the cross-tenant WARN count is module-written and fully qualified, and the window around it is a control no test can show working; take it out |

#### C-18-2 (LOW): the mapping's own SQL fragments run inside the window, undocumented

**Repro.** An entity `@Table(name = "pr18_restricted_note", schema = "public")` carries
`@SQLRestriction("pr18_visible(owner_id)")`, and `public.pr18_visible(varchar)` exists. The
application reads and writes the entity normally. Hibernate renders the restriction into the
independent read-back, so inside the window the call does not resolve, and `ErasureService.erase`
fails:

```
SQLGrammarException: ERROR: function pr18_visible(character varying) does not exist
[select count(*) from public.pr18_restricted_note prn1_0 where (pr18_visible(prn1_0.owner_id)) and ...]
```

The failure is fail-closed: the transaction rolls back whole and the subject's data key is still
present after it. Every erasure of that entity fails, though, and the application booted green. The
paragraph "What a `SELECT` can still run inside the window" in SECURITY-NOTES, and the matching
paragraph in `docs/upgrading-0.2.0.md`, name row-level-security policy functions and view functions
only. A mapping fragment is the more common case.

**Fix.**

- In SECURITY-NOTES (the paragraph above) and in `docs/upgrading-0.2.0.md` ("One consequence worth
  knowing"), state that `@SQLRestriction` text and auto-enabled `@Filter` conditions on a
  `@BlindIndex` entity are rendered into the windowed read-back.
- Give the remedy: schema-qualify every function, relation and non-keyword type those fragments
  name, for example `@SQLRestriction("public.pr18_visible(owner_id)")`. A qualified function whose
  body resolves names at run time also needs C-18-3's remedy.
- Add one line saying the failure is loud and the erasure rolls back whole.

**Probe:** `CipherProbePr18StarterTest.probe_a_mapping_restriction_rendered_into_the_window_is_documented_and_fails_closed`,
with its fixture package `cipherpr18restricted`. It asserts both halves: the fail-closed behaviour,
which must stay, and the two documents, which are red now.

#### C-18-3 (LOW): "a `LANGUAGE sql` body is immune" is false for the ordinary string body

**Repro.** Inside `inOneStatementWindow`, on PostgreSQL 16, with `public.pr18_allow` present:

| function | inside the window |
| --- | --- |
| `CREATE FUNCTION public.pr18_string_body() RETURNS bigint AS $$ SELECT count(*) FROM pr18_allow $$ LANGUAGE sql` | `42P01 relation "pr18_allow" does not exist` |
| `CREATE FUNCTION public.pr18_atomic_body() RETURNS bigint LANGUAGE sql BEGIN ATOMIC SELECT count(*) FROM pr18_allow; END` | `1` |

A string body is parsed again when it runs, using the `search_path` in force at that moment. Only
a SQL-standard body (`BEGIN ATOMIC` or `RETURN`, PostgreSQL 14 and later) is bound when the
function is created. The design's evidence for "immune" was an error raised at creation time,
which is body validation and does not bind names.

Three texts make the false claim:

- `SECURITY-NOTES.md`: "A `LANGUAGE sql` body resolves its names at creation time and is immune."
- `docs/upgrading-0.2.0.md`: "... and is unaffected."
- the javadoc of `JdbcSupport.inOneStatementWindow`: "... resolves at creation time and is immune."

An operator who reads them leaves a string-body SQL function without the remedy, and every erasure
then fails.

**Fix.** Correct all three texts:

- A string-body `LANGUAGE sql` function resolves its names at run time and behaves like plpgsql
  inside the window.
- Only a SQL-standard body (`BEGIN ATOMIC ... END` or `RETURN ...`) binds its names at creation.
- The remedy for either is `ALTER FUNCTION ... SET search_path = <schema>, pg_catalog`, or
  rewriting the function with a SQL-standard body.

Correct the design page's residual R1 and section 4.2 item 4 the same way, so the next revision
does not reintroduce the claim.

**Probe:** `CipherProbePr18Test.probe_a_string_body_sql_function_is_not_immune_inside_the_window`.
It measures both bodies first, then requires every sentence calling a `LANGUAGE sql` body immune,
unaffected or creation-time-bound to name the SQL-standard form.

#### C-18-4 (INFO): a pin that cannot be established is reported as a key-store outage

**Repro.** The probe hands the window a connection that is in a transaction, answers the step-1
capture, and fails the step-2 `set_config` with SQLState `08006`. `inOneStatementWindow` rethrows
the raw `SQLException`, and `JdbcSupport.inTransaction` maps it to
`KeyUnavailableException` ("shredding key store is unavailable"). Two texts say otherwise:

- Design section 4.4: "a `SQLException` on any of the six is `SHRED-SCHEMA-008`".
- The window's javadoc: "-008 when the replacement cannot be established".

A step-1 failure (the capture, which sits outside the `try`) behaves the same way. M3 rightly
exempts only step 4: the statement the window exists for surfaces its own failure.

**Fix.** In `JdbcSupport.inOneStatementWindow`, raise `isolationFailed(..., cause)`
(`SHRED-SCHEMA-008`) for a `SQLException` from step 1 (capture), step 2 (pin) or step 3 (pin
read-back). Attach any restore failure as suppressed. Keep M3 unchanged for `work.run()`: mark the
point where the unit of work begins, and let only exceptions thrown after it propagate as
themselves.

**Probe:** `CipherProbePr18Test.probe_a_failure_to_establish_the_pin_is_reported_as_the_isolation_code`.

#### C-18-5 (INFO): the residual SPI does not state the window it runs in

`BlindIndexResidual` is public. `JdbcErasureStore` is `@ConditionalOnMissingBean` and accepts any
implementation. From this PR on, every call to `count` runs inside the window. The interface's
"strict contract" lists three rules (no second connection, no transaction control, no flush) and
mentions none of the following:

- the path is `pg_catalog, pg_temp`;
- the unit of work is exactly one statement;
- an unqualified relation, function or type fails;
- the implementation must not change `search_path`.

**Fix.** Add a fourth item to the contract in `BlindIndexResidual`'s javadoc stating those four
points, with a link to `JdbcSupport#inOneStatementWindow`.

**Probe:** `CipherProbePr18Test.probe_the_residual_spi_states_the_window_it_runs_in`.

#### C-18-6 (INFO): no statement this module writes belongs inside the window (ruling on QUESTION 2)

The window was put around the cross-tenant WARN count (M9) because that statement then contained
`IS DISTINCT FROM`, which has no qualified spelling. C-A-6 removed that construct. The statement is
now `OPERATOR(pg_catalog.=)` throughout, its relation is two-part under mechanism 2, and the name
gate verifies it with the window's relaxation off. Mutation row 12 (window removed, gate green)
measures this.

Inside the window the statement therefore changes no answer that any test can observe. It also
brings text this module writes under the gate's keyword-operator relaxation, which exists only for
text the module cannot qualify. The availability cost the builder raised is not incremental: the
framework read-back runs first, on the same table, in its own window, and any row-level-security
function fails there first. The window is still a control that cannot be shown to work, and the
gate is weaker where it covers module-written text.

**Fix.**

- In its own commit, take the `elsewhere` count out of `inOneStatementWindow` in
  `JdbcErasureStore.verifyCleared`.
- Remove the keyword-operator relaxation from the gate: `SqlNameLexer.refusals(String, boolean)`,
  `refuseKeywordOperator`'s window branch, and the `Site#window` admission. Once no module
  statement sits in a window, the relaxation admits text no statement uses.
- Replace `every_window_holds_at_most_one_statement_of_this_modules_own` with an assertion that
  every window holds zero statements of this module's own.
- Update the comment in `JdbcErasureStore`, the paragraph "The two statements a session still
  resolves" in SECURITY-NOTES, the CHANGELOG entry, and close the module's open question on it.

The starter case `probe_the_cross_tenant_warn_counts_only_the_rows_under_other_tenants` must stay
green.

**Probe:** `CipherProbePr18Test.probe_no_statement_this_module_writes_sits_inside_the_window`.

### Attempted and reclassified (no code change)

- **C-18-1, a JOINED subclass whose superclass table names no schema.** Section 3.2's refusal checks
  only the mapped table, and the design review's "attacked, clean" list wrongly says `@Inheritance`
  hierarchies are refused (S-23 refuses only a `@Shredded` field inherited from an entity ancestor).
  The test case: a leaf `@Table(schema = "public")` extending a JOINED root `@Table(name =
  "pr18_joined_root")` with no schema anywhere else. It booted and the erasure **completed**. Hibernate 7
  prunes the superclass join from a count that references no superclass column, so the windowed
  read-back never names the root table. If a future Hibernate stops pruning, the statement fails
  inside the window with `42P01` and rolls back, which is fail-closed. Not a finding.
- **An `@Entity(name)` that differs from the class name.** This takes `ShreddedModel.resolveTables`'
  `primary == null` branch, which skips the schema requirement and keeps the provisional one-part
  `TableRef` that the gate now trusts through `QUALIFYING_RECEIVERS`. Startup refuses it anyway, with
  `SHRED-CONFIG-001` from the reverse converter check (the converter names `Pr18Renamed.email` and
  the persister `Pr18RenamedNote.email`). Not a finding.

### The builder's two deviations, ruled

- **Deviation 1: the restore uses `is_local = false`.** Accepted. The measurement agrees with the
  PR: a local restore loses to a non-local `SET` issued inside the window, and the session keeps
  that `SET` after commit (mutation row 10). One consequence was checked. If code earlier in the
  same transaction had set the path transaction-locally, the non-local restore writes that
  local value back as the session value. The only code that can do this is code running in the
  module's session, such as an application trigger fired by the erasure's own `UPDATE`, and that code
  can already set a session-level path itself. No capability is gained. The module issues no
  transaction-local path change before the window.
- **Deviation 2: the cross-tenant count's wrong answer is not reachable end to end.** Accepted, and
  moot since C-A-6: the statement no longer contains the construct that T3c measured. See C-18-6.

### The two open mutation rows, ruled

- **Row A (design section 9, row 11): dropping `pg_temp` from both pinned literals turns nothing red.**
  Reclassified, not a finding. `pg_temp` is never consulted for operator, function or aggregate
  names. The rendered read-back above contains no type name, and its only relation is two-part.
  The cross-tenant count and every catalogue read in `SchemaVerification` are fully qualified,
  which the gate verifies. So the position of `pg_temp` decides no name in any statement under
  either pin. The one place it could matter is a non-keyword type or a catalogue-named relation in
  application text inside the window (C-18-2's fragments). Putting a temporary object there requires
  code already running in the module's session, which can fail the erasure or move the path more
  directly. The hardened posture also revokes `TEMPORARY`. The constant stays as the design states
  it. The design's expectation that N26 goes red under row 11 cannot hold once Property B holds, and
  the design page should say so.
- **Row B (design section 9, row 12): deleting the step-6 read-back turns nothing red.**
  Reclassified, not a finding. The following were measured inside the window on a transaction with
  arrived path `"$user", public, pg_catalog`:
  - a `set_config('search_path', 'evil, public', true)`;
  - the same call with `false`;
  - every quote shape the PR's probe uses.

  In every case the restore is the last writer: step 6 reads the arrived bytes, and the session
  carries them after commit. Under `autosave=always` the restore also succeeds after a failure
  inside the window. No route makes the restore succeed and read back different bytes, because
  nothing runs between steps 5 and 6. The leg is an unreachable assertion that fails closed if it
  ever fires. Keeping it is correct; it is not a control that needs a red test.

### QUESTION 1 and QUESTION 2 of the PR

- QUESTION 1 (restore locality): ruled under deviation 1. Keep the non-local restore. No line is
  needed in SECURITY-NOTES.
- QUESTION 2 (the cross-tenant window): ruled as C-18-6. Remove it, in its own commit on this PR.

### Integration surface: every path to the protected count, verified or refused

| path | status |
| --- | --- |
| HQL selection query on a `StatelessSession` over the erasure's connection (`HibernateBlindIndexResidual.count`) | the only framework-rendered statement in main sources; its one caller is inside the window (`JdbcErasureStore.verifyCleared`); rendered text captured above |
| entity load, `find`, `getReference`, lazy attributes, derived query, Criteria, native query, projection | not used by the read-back (a `count` with no entity materialised); a search of both modules' main sources finds no other `createQuery`, `createNativeQuery`, `find` or Criteria use |
| first-level cache, flush | none: a stateless session has no persistence context and cannot flush |
| second-level and query cache | the count is never marked cacheable; `use_query_cache=true` is refused at startup without the explicit allow property |
| `@SQLRestriction`, auto-enabled `@Filter` | rendered into the window: C-18-2 |
| JDBC driver statements around the window, server-side prepared statements | one statement per window. A statement parsed inside the window only ever runs inside it, and PostgreSQL re-analyses a cached plan when `search_path` changes, so nothing parsed under one path runs under the other |
| pgjdbc `autosave` | measured: failure surfaces as itself, path restored |
| an auto-commit connection | refused with `SHRED-SCHEMA-008` before anything changes (the PR's probe) |
| a third-party `BlindIndexResidual` | runs inside the window; contract undocumented: C-18-5 |
| JOINED, SINGLE_TABLE, TABLE_PER_CLASS | JOINED leaf measured (pruned, clean); an inherited `@Shredded` field is refused by S-23 under every strategy, so a TABLE_PER_CLASS union cannot carry a blind index |
| the erasure's `UPDATE` and same-text read-back | outside the window by design, every name qualified (the gate) |
| the cross-tenant WARN count | inside its own window, fully qualified: C-18-6 |

### Attacked, clean

- **Gate keying of `sql()`.** `ColumnRef.sql()` is not taken as qualified, and `table().sql()` /
  `tableName().sql()` are, only on receivers that come from checked persisters. The one provisional
  `TableRef.of` path is refused at startup, as shown above.
- **Log injection through the `-008` messages.** They embed the arrived and restored paths, which a
  role can fill with newlines, but the only message reachable with role-controlled bytes is the
  step-6 mismatch, and row B shows it cannot fire.
- **Restore under a quoted, empty or `"$user"` path.** Byte-equal: the PR's probes were re-run and
  the reasoning re-checked.
- **Public text.** The diff's README, CHANGELOG, SECURITY-NOTES and docs contain no agent or person
  names.

### What the fix pass must not do

Do not weaken, rename or disable any of the five probes. C-18-6's gate change must not remove the
existing negative cases for keyword operators outside a window. After the fixes, the PR body
records the five probes going green and the mutation table re-run with row 12 removed.

## Second pass, 2026-10-03

Head reviewed: `1bf1d52`. Scope: `git diff 8636b83..1bf1d52`, which is the five probes (`daed686`),
the five fixes (`d001d4e`, `98386c4`, `bad250b`, `9356cb6`, `b4074a3`), the CHANGELOG (`9834812`), a
formatting commit (`3d08811`) and one comment edit (`1bf1d52`). This is the last pass on this PR.

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -B clean verify` | green, exit 0, Docker up |
| Tests | 500 run, 0 failures, 0 errors, 0 skipped (core 258, starter 225, sample 17), same as the PR body |
| `CipherProbe*` classes | 63, all green, none changed except as noted below |
| The five pass-1 probes | green: `CipherProbePr18Test` 4/4, `CipherProbePr18StarterTest` 1/1 |
| Pass-1 probes compared with the copies kept outside the tree | identical once whitespace is ignored. `3d08811` re-wrapped two comment blocks and changed no assertion |
| CI at `1bf1d52` | 6 of 6 green: Build & test, Cipher probes, DCO sign-off, Reference guard, Release dry run, Vulnerability scan |
| New findings | 1 INFO (C-18-7), its probe RED on `1bf1d52` |

### Pass-1 findings, closed by their probes

| id | probe | result at `1bf1d52` |
| --- | --- | --- |
| C-18-2 | `CipherProbePr18StarterTest.probe_a_mapping_restriction_rendered_into_the_window_is_documented_and_fails_closed` | green. Fail-closed behaviour kept, both documents state it |
| C-18-3 | `CipherProbePr18Test.probe_a_string_body_sql_function_is_not_immune_inside_the_window` | green. The three texts are corrected and the two bodies measure as before |
| C-18-4 | `CipherProbePr18Test.probe_a_failure_to_establish_the_pin_is_reported_as_the_isolation_code` | green |
| C-18-5 | `CipherProbePr18Test.probe_the_residual_spi_states_the_window_it_runs_in` | green |
| C-18-6 | `CipherProbePr18Test.probe_no_statement_this_module_writes_sits_inside_the_window` | green |

### Regressions checked in the C-18-4 and C-18-6 changes

**The nested try in `inOneStatementWindow` (C-18-4).** Every exit path was run against a scripted
connection. The test sat in the tree only for the run, and the tree was clean afterwards.

| case | outcome |
| --- | --- |
| capture (step 1) fails | `-008` with the cause attached; the connection sees only the one read, and nothing is pinned or restored |
| pin (step 2) fails, restore then refused | `-008` with the pin failure as cause and the restore failure as suppressed; the restore was attempted |
| pin read-back (step 3) throws | `-008`; restore and its read-back both ran |
| pin read-back mismatches | `-008`, the statement is not run, restore and read-back both ran |
| statement fails (`SQLException` or `RuntimeException`), restore succeeds | the statement's own exception, the same instance (M3 unchanged) |
| statement fails, restore refused | the statement's own exception, with the restore failure suppressed |
| statement succeeds, restore throws (`SQLException` or `RuntimeException`) | `-008` with the restore failure as cause |
| statement succeeds, restore read-back throws | `-008` with that failure as cause |
| restore throws an `Error` | the `Error` replaces the primary. This is ordinary Java for `OutOfMemoryError` or `StackOverflowError`, and no JDBC call throws an `Error` on a normal path. Not a finding |

The restore runs on every exit that is entered after step 1. When step 1 fails nothing has changed,
so there is nothing to restore.

End to end, one more case. When the pin fails because the connection is dead (`08006`), the error
the caller sees is still `SHRED-KEY-UNAVAILABLE`. `JdbcSupport.inTransaction`'s `rollback()` fails
on the dead connection and replaces the `-008`. That code is older than this PR, and for a dead
connection "key store unavailable" is the right answer. A pin failure on a live connection, such as
`57014` (statement timeout), reaches the caller as `-008`. Not a finding.

**Taking the cross-tenant count out of the window (C-18-6).** Every name in the statement belongs to
`pg_catalog`: `pg_catalog.count`, and `OPERATOR(pg_catalog.=)` on both legs. `IS NULL`, `NOT`, `AND`
and `OR` are grammar, not name lookups. The relation is two-part under section 3.2's startup
refusal, and the bind parameters are values, not names. A role-owned schema placed first on the
path, or a `pg_temp` object, therefore decides nothing in it. A row-level-security function on the
table now runs on the arrived path, as it already does for the erasure's `UPDATE` and the same-text
count on the same table. That removes a failure point and opens nothing.
`probe_the_cross_tenant_warn_counts_only_the_rows_under_other_tenants` is green.

**Removing the gate relaxation.** `refusals(String, boolean)`, the window branch of
`refuseKeywordOperator` and `Site#window` are gone. The negative cases for keyword operators outside a
window remain: there are 9 `keyword operator` assertions in `NameQualificationGateTest`, the same
count as before. `COLLATE` is still refused. The two-statement synthetic negative still counts 2.
Nothing is admitted anywhere any more, so the change can only refuse more text.

### Re-targeted mutation rows, re-run here

| row | mutation as applied at `1bf1d52` | result |
| --- | --- | --- |
| 1 | the nested try's pin and step-3 read-back deleted | RED, 7/15 `CipherProbeWindowPr14Test` (decoy relation, shadowed `=`, shadowed `LIKE`, lying `count`, quoted-path restore x2, keyword-operator shape) |
| 2 | prefix pin `pg_catalog, <arrived>, pg_temp`, bound, with the read-back compared against it | RED, 6/15 |
| 7 | a module-written `SELECT` added inside the framework read-back's window | RED, 2: `every_window_holds_zero_statements_of_this_modules_own`, `probe_no_statement_this_module_writes_sits_inside_the_window` |
| 11 | pin for the whole transaction in `inTransaction`, window turned into a pass-through | RED, 1 error of 3: trigger case, `SHRED-KEY-UNAVAILABLE` over `42P01` |

All four are the same mutation as before, moved to the new code. Row 7 now mutates the invariant
C-18-6 tightened (zero module statements per window instead of at most one), and that is the right
target. Rows 3 and 4 stay open under the pass-1 rulings, and row 12 is correctly retired. After
every row the tree was restored and `git status --porcelain` was empty. Row 11 needed the core jar
installed locally, so the clean head was installed again afterwards.

### Public text

SECURITY-NOTES, `docs/upgrading-0.2.0.md`, CHANGELOG, README, main sources and the PR body contain
no agent or person name in this PR's diff. They also contain no internal question number now that
`1bf1d52` has landed. This review's own pass-1 text cited one; it is replaced above by "the
module's open question". The `CIPHER-nn` ids in SECURITY-NOTES and CHANGELOG are finding ids that
were already on `main`. The documentation example `public.pr18_visible` is a technical
illustration, not an id. Not a finding.

### New finding

| id | severity | one line |
| --- | --- | --- |
| C-18-7 | INFO | two window probes still describe the removed cross-tenant window, and the `IS DISTINCT FROM` spelling, as current production |

#### C-18-7 (INFO): the window probes' documentation describes a statement that no longer exists

**Repro.** `CipherProbeWindowPr14Test`'s javadoc on
`probe_the_cross_tenant_shape_is_only_correct_inside_the_window` says "the cross-tenant WARN count's
`IS DISTINCT FROM` reaches the type's own `=` ... The shape below is the one `verifyCleared`
builds". `CipherProbeWindowPr14StarterTest`'s javadoc on
`probe_the_cross_tenant_warn_counts_only_the_rows_under_other_tenants` says the count "gets its own
window (M9)", that it is "the one statement this module builds that contains a name qualification
cannot reach", and that "the second window must not change the erasure's behaviour". Since C-A-6
and C-18-6 none of these is true. `verifyCleared` spells the leg with `OPERATOR(pg_catalog.=)` and
runs it outside any window. The tests are public, and a reader of the suite is told that a
production statement is covered by a control it no longer runs under. The pass-1 prescription for
C-18-6 listed the comments in production and docs to update, and it missed these two. The
assertions are still correct: the core case measures a window property on a historical statement,
and the starter case measures the WARN's content.

**Fix (test documentation only, no assertion and no production change).**

- `CipherProbeWindowPr14Test`: reword the javadoc on
  `probe_the_cross_tenant_shape_is_only_correct_inside_the_window`. The `IS DISTINCT FROM` shape is
  the statement `verifyCleared` built before C-A-6, kept as a measurement of the window's own
  property (a keyword operator inside the window resolves only from `pg_catalog`). Production no
  longer builds it, and since C-18-6 it no longer runs any module statement in a window.
- `CipherProbeWindowPr14StarterTest`: reword the javadoc on
  `probe_the_cross_tenant_warn_counts_only_the_rows_under_other_tenants`. The count is fully
  qualified and runs outside the window (C-A-6, C-18-6). This case holds the WARN's content and the
  erasure's behaviour. Drop "own window" and "second window".

This is an INFO correction to test text, so the fix needs no third pass. The probe turning green in
CI is the confirmation.

**Probe:**
`CipherProbePr18SecondPassTest.probe_no_window_probe_describes_the_removed_cross_tenant_window_as_current`
(core, `adapter/jdbc`). It is kept outside the public tree like the pass-1 probes, and the fix pass
adds it to the suite before it edits the two javadocs. RED on `1bf1d52` on the first assertion.

### Verdict: MERGE WITH FIXES

There is no HIGH, MEDIUM or LOW. All five pass-1 findings are closed by their probes, and neither
mechanism change introduced a regression. Under the no-allowance rule, the one remaining item is
C-18-7, a test-documentation correction gated by its probe. Once that probe is green in CI with the
six checks green, the branch is mergeable without another security pass.
