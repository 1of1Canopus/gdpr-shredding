# Security review: release candidate 0.2.0 (whole module)

## Pass 1, 2026-10-05

Head reviewed: `5345c51` on `main` ("feat(jdbc): refuse a mapping the erasure cannot be trusted on
(#19)"). Scope: the whole module end to end, with the three 0.2.0 mechanisms interacting (no DDL at
runtime, name resolution with the pinned read-back window, mapping admission), plus what a release
reader meets: the release notes, `docs/upgrading-0.2.0.md`, `SECURITY-NOTES.md`. This is the
release-candidate pass required before the first tag of a version; it is not a per-PR pass, and
the per-PR findings of PR 13, 14, 18 and 19 are not re-reported. The checklist was the threat models
of the three design pages (no-DDL, name resolution with its mapping-admission addendum and section
check S-1 to S-8, read path), plus five mandatory leads: audit tables (Envers and the trigger
pattern), seams between the mechanisms, partitioned and inherited tables, the upgrade path from
0.1.1, and the startup-WARN rule. This pass touches no release, CI or packaging file, so the release
hygiene checklist was not run line by line; the release-pipeline probe suite was.

Method: the head was built and run. Every attack ran on PostgreSQL 16 (the digest the module's
tests pin) through a live Spring Boot context or through `JdbcErasureStore` directly. Each finding
has a probe test that fails on this head. The probes are committed on the review branch; the
fix pass keeps them in the suite and turns them green.

### Numbers on this head

| What | Result |
| --- | --- |
| `CIPHER_PROBE_MAVEN=1 ./mvnw -B verify`, Docker up | green, exit 0 |
| Tests | 576 run, 0 failures, 0 errors, 0 skipped (core 320, starter 239, sample 17) |
| Earlier review probes (`CipherProbe*` classes in the suite) | unchanged and green in that run |
| Release-pipeline probe script (`CIPHER_PROBE_MAVEN=1`) | run 1 in the review tree: 66 fixed / 1 weak (`probe_sources_jar_differs_from_a_test_run`). The probe body re-run alone on a fresh clone: all three builds green, both sources jars byte-equal to the recorded checksums. Run 2, whole suite on an isolated clone of the same head: 67 fixed / 0 weak. See RC-8 |
| New probe tests from this pass | 15: 8 RED (one or two per finding RC-1 to RC-7) and 7 GREEN confirmations (the real 0.1.1 upgrade path, six weaker modes WARNing at every startup) |
| Review branch, full verify with the new probes | see "Branch numbers" below |

### Verdict: TAG WITH FIXES

No HIGH. One MEDIUM, five LOWs and two INFOs; under the no-allowance rule every one is closed
before the tag. RC-1 and RC-3 need a new mechanism and go through a design page first (design
stop); the others are corrections.

What holds, confirmed by execution:

- **A real 0.1.1 install upgrades cleanly.** The schema script that the 0.1.1 jar shipped
  (extracted from tag `v0.1.1`), applied the way 0.1.1 applied it (by the application role, at
  boot), with live key and tombstone rows, then the guide's steps 2 to 5 verbatim: 0.2.0's
  verification passes with the unprivileged role and the rows survive
  (`CipherProbeRc020UpgradeTest.rc_a_real_0_1_1_install_upgraded_by_the_guide_verifies_clean`).
  The existing upgrade test (`SchemaVerificationTest.t30`) starts from the 0.2.0 script; this one
  closes that gap.
- **Every weaker mode WARNs at every startup.** Six properties enumerated from
  `ShreddingProperties`: `shredding.dev-mode`, `shredding.allow-second-level-cache`,
  `shredding.erased-value.policy=null`, `shredding.erasure-log.unkeyed`,
  `shredding.jdbc.initialize-schema`, `shredding.jdbc.allow-privileged-runtime-role`. Each was
  switched on and the context booted twice; each boot printed a WARN naming the property
  (`CipherProbeRc020StartupTest`, 6 green tests). No other property weakens a control by itself;
  `shredding.erasure.backup-retention` makes the proof state something false, which is RC-5.
- **Envers in its default shapes fails closed.** An `@Audited` `@Shredded` entity is refused at
  startup (the audit entity maps the module's converter with no `@Shredded` field); with the
  ciphertext `@NotAudited`, Envers' listeners take the last position and the listener-order check
  refuses. Neither boots. The messages are RC-2.
- **The mechanisms do not undo each other.** The name gate, the read-back window and admission all
  address the persister's `TableRef`; admission's lock and verdict run on the erasure's own
  connection before the window, and the per-PR passes' interleavings (rename plus view, attach and
  detach, inheritance added during the check) stay green in the suite. No shape was found where
  admission and the name gate resolve different relations.
- **Partitioned, inherited, `JOINED`, `SINGLE_TABLE` and `TABLE_PER_CLASS` tables:** the suite's
  admission and erasure tests for each pass on this head; no new shape was found.

### Findings

| Id | Severity | What | Fix owner |
| --- | --- | --- | --- |
| RC-1 | MEDIUM | Envers composed the way the module's own refusal advises keeps the erased subject's blind index in the audit table, under a `COMPLETE` record | design page (design stop), then the builder |
| RC-2 | LOW | Both Envers refusals send the developer elsewhere: one blames causes the application does not have, the other points at the composition that produces RC-1 | fix pass, text from RC-1's design |
| RC-3 | LOW | A history trigger on a blind-indexed table copies the erased index during the erasure's own `UPDATE`; admission never mentions triggers | inside RC-1's design page |
| RC-4 | LOW | "Rolling back to 0.1.1 is safe with nothing to undo" is false after the upgrade steps: 0.1.1's boot DDL fails as the runtime role | fix pass (text) |
| RC-5 | LOW | A negative `shredding.erasure.backup-retention` boots silently; every record then says backups were clear a month before the erasure | fix pass |
| RC-6 | INFO | The upgrade guide's step 7 table, the one read when the first 0.2.0 boot refuses, has no row for `SHRED-SCHEMA-009` | fix pass (text) |
| RC-7 | LOW | A `lock_timeout` the guide recommends is reported as `SHRED-KEY-UNAVAILABLE`, "key store is unavailable" | fix pass |
| RC-8 | INFO | The sources-jar reproducibility probe reports any build failure as WEAK and discards the log; it has now gone WEAK in two suite runs and green when re-run alone | fix pass (script) |

#### RC-1 (MEDIUM): Envers, composed as advised, keeps the erased subject's blind index

Repro (`CipherProbeRc020EnversTest.probe_envers_composed_as_advised_keeps_the_erased_subjects_blind_index`):
an entity `@Audited`, its `@Shredded` field `@NotAudited`, its `@BlindIndex` column audited (the
default for a plain column). Default composition is refused (listener order, see RC-2), and that
refusal says "see ShreddingAutoConfiguration.shreddingHibernateCustomizer for how to compose
instead of displacing it". Doing that: Envers' documented manual mode
(`hibernate.envers.autoRegisterListeners=false`) with its listeners registered by an integrator
supplied through `hibernate.integrator_provider`, ordered before the module's customizer, which
composes it first and itself last. The context boots. Persist one row, erase the subject:

```
outcome=COMPLETE  main-table index left=0  audit rows with the index: before=1 after=1
```

The erasure, both read-backs and the record agree on `COMPLETE`; `rc_composed_note_aud` still holds
the subject's blind index next to the subject id, matchable with the application's own index
secret. `SECURITY-NOTES.md` says of exactly this: "an index that survives an erasure keeps the
erased subject searchable and linkable for ever, which defeats the product." MEDIUM rather than HIGH
because both default shapes fail closed and the leak needs a deliberate, if advised, composition;
the ciphertext copy is not at issue (`@NotAudited`, and an audited ciphertext would be unreadable
once the key is gone).

**Design stop.** The property that must hold: *no relation that the application's own persistence
unit maps, other than the admitted table, holds a copy of a blind-index column, unless the erasure
clears it too; otherwise startup refuses, naming the column and the remedy.* Paths the design must
cover, each verified or refused: Envers with auto-registered listeners, Envers in manual mode,
`@Audited` on the class, on the field, inherited through `@AuditOverride` or a `@MappedSuperclass`,
`@AuditTable` with its own schema, the validity audit strategy (`REVEND` updates), Envers disabled
by property while the `_aud` tables still exist from an earlier run, and RC-3's database-side
trigger. Whether the answer is a refusal (blind index must be `@NotAudited`) or an erasure that
reaches the audit table is the design's choice; a refusal is the smaller one.

#### RC-2 (LOW): the Envers refusals misdirect

Repro (`CipherProbeRc020EnversTest.probe_envers_audited_shredded_entity_is_refused_with_a_message_naming_other_causes`,
`...probe_envers_audited_blind_index_is_refused_without_naming_the_index`). Whole entity audited:

```
SHRED-CONFIG-001 the attribute RcAuditedNote_AUD.email is mapped by ...$EmailConverter ..., but has
no field-level @Shredded annotation of its own. This happens when @Convert is declared at the class
level (@Converts on the entity), through an orm.xml mapping, or on a field nested inside an
@Embeddable ...
```

None of the three named causes exists in the application; Envers is not named. Ciphertext
`@NotAudited`: "this module's listener is registered on post-insert but is not last
(org.hibernate.envers...EnversPostInsertEventListenerImpl is) ... see ...shreddingHibernateCustomizer
for how to compose instead of displacing it", which is the road to RC-1. Fix: when the offending
persister is an Envers audit entity, or the displacing listener is an Envers listener, say so, and
give the remedy RC-1's design settles on. Neither the README nor the release notes say whether
Envers is supported; one sentence in each, from the same design.

#### RC-3 (LOW): a history trigger copies the index during the erasure

Repro (`CipherProbeRc020HistoryTriggerTest`): a row-level `AFTER UPDATE` trigger on the blind-indexed
table that inserts `OLD` into a history table, the usual audit-trigger shape. The erasure's own
`UPDATE ... SET email_idx = NULL` fires it:

```
outcome=COMPLETE  history rows with the erased subject's index=1
```

The erasure manufactures the copy and then records `COMPLETE`. Admission reads the relation, its
descendants and its columns, never `pg_trigger`, so no startup line mentions it. The module cannot
know where a trigger writes, so the honest floor is that it says the trigger exists: the probe
asserts a startup WARN from mapping admission naming each non-internal, enabled trigger that fires
on `UPDATE` of the table (or of the blind-index column) or of a descendant, plus a
`SECURITY-NOTES.md` residual. It belongs in RC-1's design page because it is the same property
(copies outside the admitted table) and the same catalogue leg.

#### RC-4 (LOW): rollback to 0.1.1 does not boot after the upgrade

Repro (`CipherProbeRc020UpgradeTest.probe_rollback_to_0_1_1_after_the_upgrade_does_not_boot_but_the_guide_says_it_is_safe`):
after steps 2 to 5, the 0.1.1 jar's unconditional boot step (its bundled script, run with the
application's credentials) fails with `permission denied for schema public`, so the rolled-back
application does not start. `upgrading-0.2.0.md` ("Rolling back": "a rollback is an application
rollback with nothing to undo in the database") and the release notes ("Rolling back to 0.1.1 is
safe with nothing to undo") both promise the opposite. Fix: state that 0.1.1 cannot run against a
hardened schema, and give the exact statements that undo steps 2 and 4 for an emergency rollback
(ownership of the four tables and three functions back to the application role, `CREATE` on the
schema), with the warning that this returns the guards to advisory. The probe's second half
asserts the guide no longer says "nothing to undo".

#### RC-5 (LOW): a negative backup retention is accepted

Repro (`CipherProbeRc020StartupTest.probe_negative_backup_retention_boots_and_records_backups_clear_before_the_erasure`):
`shredding.erasure.backup-retention=-30d` boots with no WARN, and the erasure reports

```
erasedAt=2026-10-05T09:23:48.982452Z  backupsClearAt=2026-09-05T09:23:48.982452Z
```

That date is chained into the record and printed in the proof of erasure as the day the erasure is
complete in backups. Fix: refuse a negative value at startup with `SHRED-CONFIG-001` naming
`shredding.erasure.backup-retention` (in `ShreddingStartupCheck`, beside the ledger-cap check), and
refuse it in the `ErasureService` constructor for core users. Zero stays legal (no backups).

#### RC-6 (INFO): step 7 of the upgrade guide has no row for SHRED-SCHEMA-009

Repro (`CipherProbeRc020UpgradeTest.probe_upgrade_guide_step_7_omits_the_mapping_admission_refusal`):
step 7's table lists `SHRED-SCHEMA-001` to `-007` and `SHRED-CONFIG-001`. The release notes call the
`SHRED-SCHEMA-009` column rule "the one change most installations will meet", and the guide quotes
the exact message only for `SHRED-CONFIG-001`. Fix: one row for `SHRED-SCHEMA-009` pointing at the
section "what your entity tables must be", with the exact message of the C-i refusal for a `uuid`
subject, and the `ALTER COLUMN ... TYPE text` statement the release notes already carry.

#### RC-7 (LOW): a lock timeout is reported as a key-store outage

Repro (`CipherProbeRc020LockTimeoutTest`): the guide and the release notes say "set a `lock_timeout`
on the erasure's connection if that wait must be bounded". With `lock_timeout = 300ms` and another
session holding `SHARE UPDATE EXCLUSIVE` on the table (another erasure, a manual `VACUUM`):

```
KeyUnavailableException[SHRED-KEY-UNAVAILABLE] shredding key store is unavailable (SQLState 55P03)
```

`JdbcErasureStore.lock` maps `42P01`, `42809` and `42501` and rethrows everything else, and
`JdbcSupport.inTransaction` turns any `SQLException` into "key store unavailable". Nothing is
destroyed (the transaction rolls back), so this is misdirection, the class C-18-4 and C-19-3 closed
for other causes. Fix: in `JdbcErasureStore.lock`, map `55P03` (and `40P01`, deadlock detected) to
a retryable refusal with its own stable code, naming the table and the lock mode it waited for, and
add the code to the release notes' table.

#### RC-8 (INFO): the sources-jar reproducibility probe hides its own failures

`probe_sources_jar_differs_from_a_test_run` sends three full builds to `/dev/null` and treats any
non-zero exit, a build failure included, as WEAK. It went WEAK in this pass's suite run and in PR
19's first pass; the probe body re-run alone on a fresh clone of the same head was green with
byte-equal sources jars both times. A probe that cannot tell "not reproducible" from "a test flaked
in the third build" either cries wolf on the required check or trains readers to ignore it. Fix in
`tools/cipher-probe-release-pipeline.sh`: keep the three build logs in the temporary directory,
report a build failure as ERROR with the failing module and test, and keep WEAK for a checksum
mismatch or a missing jar. The verification is the probe distinguishing the two on a synthetic
input (a clone with a deliberately failing test must print ERROR, not WEAK).

### Branch numbers

`CIPHER_PROBE_MAVEN=1 ./mvnw -B verify -Dmaven.test.failure.ignore=true` on the review branch,
Docker up: core 324 run (3 red: RC-4, RC-6, RC-7), starter 246 run (1 red: RC-5), sample 21 run
(4 red: RC-1, RC-2 twice, RC-3), 0 errors, 0 skipped. Every other test, the earlier review probes
included, green. The sample module gains `hibernate-envers` in test scope only (version from the
Spring Boot bill of materials), for RC-1 and RC-2; the probe fixtures live outside the sample
application's package so its own context does not scan them.

### Leads attacked and closed without a finding

- **Admission versus the name gate resolving different relations.** Both take the persister's
  `TableRef`; admission's relation leg resolves through `parse_ident` and `pg_namespace`, never
  `search_path`, and the `LOCK` uses the same text. No divergent shape found.
- **Restricted runtime role and the read-back.** RLS that applies to the role is refused (R-g);
  a descendant's policies do not apply through the parent (section check D2b, D3, still green). No
  false `COMPLETE` found. A role holding only column-level `UPDATE` is refused by R-h with a message
  saying it holds neither privilege; the same role could not write its own entities through
  Hibernate, so this is not reachable in a working deployment and is not counted.
- **Schema changes between boot and erasure** (retype, rename plus view, attach, inherit): covered
  by the never-cached erasure-time verdict under two locks; the suite's interleavings are green.
- **`TABLE_PER_CLASS` with the shredded field on an entity ancestor:** refused at startup (S-23);
  a leaf with its own fields erases on its own table (green).

## Pass 2 (PR 21), 2026-10-05

Branch `fix/rc-0.2.0-s`, head `3edb37a`, base `5345c51`. Scope: RC-4 to RC-8 and the
`SHRED-SCHEMA-009` pointer. RC-1 to RC-3 are not in this PR. This file did not exist on the PR
branch; pass 1 is copied verbatim from `cipher/rc-0.2.0` (`fb5c4b3`) so that this section has its
context.

### Numbers on this head

`CIPHER_PROBE_MAVEN=1 ./mvnw -B verify`, Docker up, before any pass-2 probe was added: BUILD
SUCCESS in 3:32. Core 328 run, starter 246, sample 17; 0 failures, 0 errors, 0 skipped. The pass-1
probes on this branch are green: `CipherProbeRc020UpgradeTest` 3/3, `CipherProbeRc020LockTimeoutTest`
1/1, `CipherProbeRc020StartupTest` 7/7; the fix pass's own `RollbackTo011ProcedureTest` 2/2 and
`ErasureServiceRetentionTest` 2/2. The sample count is 17, not pass 1's 21, because the Envers and
history-trigger probes (RC-1 to RC-3) are not on this branch.

Pass-2 probes: 8 tests in 4 classes, 6 red (the findings below) and 2 green (confirmations of RC-7),
plus one script probe, red.

### Verdict: MERGE WITH FIXES

No HIGH. RC-4, RC-5, RC-6, RC-7 and RC-8 are closed as prescribed, each probe green. Four new
findings on the surfaces the fixes introduced, all below HIGH; every one is fixed before merge.

| Id | Sev | Finding | Probe |
|---|---|---|---|
| RC-9 | LOW | The RC-5 check has no upper bound: a retention past `Instant.MAX` or past PostgreSQL's `timestamptz` range boots, then refuses every erasure with an uncoded `DateTimeException` or as `SHRED-KEY-UNAVAILABLE` | `CipherProbeRc020Pass2RetentionTest` (core, 2), `CipherProbeRc020Pass2Test` (starter, 2) |
| RC-10 | LOW | The new code covers only the table lock; the same `lock_timeout` firing on the erasure's row `UPDATE` (or advisory, key-row, chain lock) is still "key store is unavailable", while all three documents now promise `SHRED-ERASURE-LOCK-WAIT` "when that bound fires" | `CipherProbeRc020Pass2LockTest.probe_a_lock_timeout_on_the_subjects_row_is_still_reported_as_key_store_unavailable` |
| RC-11 | LOW | Rollback variant A runs the whole application as the owner of the guards and the schema, but the guide says A "does not have that cost" and keeps the guards "out of the application role's reach" | `CipherProbeRc020Pass2RollbackTest` |
| RC-12 | INFO | The RC-8 fix reports a non-reproducible build as ERROR "build failed", the inverse of RC-8, and labels a step that runs tests "two -DskipTests builds" | `internal/gdpr-shredding/probes/cipher-probe-rc020-pass2-rc12.sh` |

### Prior findings, re-verified

- **RC-4, closed.** `RollbackTo011ProcedureTest` builds a real 0.1.1 install (the 0.1.1 script as
  the application role), applies steps 2 to 5, then runs both variants and the 0.1.1 script to
  completion. Checked against `v0.1.1`: its boot runs `JdbcSupport.initializeSchema` on the one
  application `DataSource` (`ShreddingAutoConfiguration` lines 123 and 171), so running the script
  is what its boot does. `CipherProbeRc020UpgradeTest`'s "nothing to undo" half is green. The text of
  variant A's cost is wrong: RC-11. The parenthetical `ALTER SCHEMA ... OWNER TO` alternative in
  variant B is not executed by the test, while the guide says "both variants were executed"; RC-11's
  fix covers that sentence.
- **RC-5, closed for the negative side.** `-30d` refused at startup with `SHRED-CONFIG-001` naming the
  property (pass-1 probe green); the core constructor refuses `Duration.ofDays(-30)`; zero legal in
  both. `Duration.isNegative` refuses any value below zero to the nanosecond, in either binding
  format. An empty value binds to the documented default (measured: backups clear `PT720H` after the
  erasure): not a finding. The positive side has no bound: RC-9.
- **RC-6, closed.** The step 7 row's quoted message is character-for-character the C-i refusal built
  in `MappingAdmission` (who + ": the " + `SUBJECT` = "subject column" + " is of type uuid. This
  module compares ... A UUID or numeric subject id is stored in a text column."). The new
  `MappingAdmissionCheck` pointer names `### Every installation: what your entity tables must be`,
  which exists at line 111 of `docs/upgrading-0.2.0.md`.
- **RC-7, closed for the table lock.** Measured on PostgreSQL 16:
  `55P03` on `SHARE UPDATE EXCLUSIVE` and a forced `40P01` on `ROW EXCLUSIVE` (holder takes `SHARE`,
  then the subject's advisory lock; the erasure's deadlock check fires first) both surface as exactly
  `ShreddingException[SHRED-ERASURE-LOCK-WAIT]`, the message naming the table, the mode and the
  SQLState (`CipherProbeRc020Pass2LockTest.rc_a_lock_timeout_on_the_table_lock_is_exactly_lock_wait`,
  `rc_a_deadlock_on_the_table_lock_is_exactly_lock_wait`, green). No key-store failure is mapped to
  the new code: the mapping lives only in `JdbcErasureStore.lock`. Additive only: no code renamed,
  `ErasureOutcome` untouched, no caller in main code catches `KeyUnavailableException`. The text is
  in `docs/index.md` (code table), `docs/upgrading-0.2.0.md` and `SECURITY-NOTES.md`. No test in the
  fix pass asserted the new code value or `40P01` (removing `"40P01"` stayed green); the two
  confirmation tests above now do. The other waits the same `lock_timeout` bounds: RC-10.
- **RC-8, closed.** The probe body, extracted from `tools/cipher-probe-release-pipeline.sh` and run
  alone: on this head `FIXED`, exit 0 (three real builds, sources jars byte-equal); on a clone with a
  deliberately failing test `ERROR`, exit 1, the tail printed with
  `Rc8DeliberateFailureTest.fails:4 rc8 deliberate failure` and `Tests run: 329, Failures: 1`, the
  log kept. Suite exit is non-zero on any ERROR. The inverse case is RC-12.

### Findings

#### RC-9 (LOW): a backup retention the record cannot date boots and refuses every erasure

Repro, starter (`CipherProbeRc020Pass2Test`), each boots cleanly and then:

```
shredding.erasure.backup-retention=PT9000000000000H -> java.time.DateTimeException: Instant exceeds minimum or maximum instant
shredding.erasure.backup-retention=PT3000000000H   -> KeyUnavailableException[SHRED-KEY-UNAVAILABLE] shredding key store is unavailable (SQLState 22008)
                                                     | PSQLException: ERROR: timestamp out of range: "344265-02-19 ..."
```

The first fails in `ErasureService.erase` at `now.plus(backupRetention)`, before any statement,
uncoded. The second reaches the database: `backup_clear_at` is `timestamptz` (max year 294276), the
transaction rolls back, and the operator is sent to the key store. Every erasure is refused for as
long as the property stays, and startup said nothing. Core users get the same through the
constructor (`CipherProbeRc020Pass2RetentionTest`, `Duration.ofSeconds(Long.MAX_VALUE)` and
`Duration.ofHours(3_000_000_000L)` accepted).

Fix (fix pass): one upper bound, `Duration.ofDays(36_500)` (100 years; any smaller documented ceiling
is acceptable), refused with `SHRED-CONFIG-001` naming `shredding.erasure.backup-retention` in both
places RC-5 touched: `ShreddingStartupCheck.refuseIfBackupRetentionNegative` (rename to
`refuseIfBackupRetentionOutOfRange`) and the `ErasureService` constructor. Add the ceiling to the
`docs/index.md` property row and the CHANGELOG RC-5 line. The four probes flip green.

#### RC-10 (LOW): a lock_timeout on any wait but the table lock is still a key-store outage

Repro (`CipherProbeRc020Pass2LockTest.probe_a_lock_timeout_on_the_subjects_row_is_still_reported_as_key_store_unavailable`):
`lock_timeout = 300ms` on the erasure's connection, an application transaction has updated the
subject's row and not committed. The erasure passes both table locks (neither conflicts with the
application's `ROW EXCLUSIVE`), its blind-index `UPDATE` waits on the row lock, and:

```
KeyUnavailableException[SHRED-KEY-UNAVAILABLE] shredding key store is unavailable (SHRED-KEY-UNAVAILABLE, SQLState 55P03)
```

This is the commonest wait of all (an application transaction open on the user's row), and it is
the same bound the documents tell the operator to set. All three documents now say, without
restriction to the table lock: "When that bound fires, or the database picks the erasure as a
deadlock victim, the erasure is refused with `SHRED-ERASURE-LOCK-WAIT` ... It is not a key-store
outage." The same applies, by reading, to the subject's advisory lock (two erasures of one subject),
the key-row `FOR UPDATE` (a write racing the erasure) and the chain lock in `appendInTransaction`
(any concurrent append); a `55P03` or `40P01` there is a lock wait, not an unreachable store, and the
transaction has rolled back whole, so "nothing was destroyed, cleared or recorded" is true at every
one of them.

Fix (fix pass, correction of the RC-7 mapping, no new mechanism): in `JdbcErasureStore.erase` and
`JdbcErasureStore.append`, map a `SQLException` with SQLState `55P03` or `40P01` raised by any
statement of the transaction to `ShreddingException(ErrorCodes.ERASURE_LOCK_WAIT, ...)` naming the
step that waited (subject lock, key rows, table lock with mode, blind-index update, erasure-log
append); keep `lock`'s table-and-mode message for the table step. Every other SQLState keeps its
current mapping. Tests: the probe above flips green; add one test per step (advisory lock held by a
second session, key rows held `FOR UPDATE`, chain lock held), each asserting exactly
`SHRED-ERASURE-LOCK-WAIT`, and a `40P01` on a step other than the table lock. Update the
`ErrorCodes.ERASURE_LOCK_WAIT` javadoc ("the table lock mapping admission needs") and the
`docs/index.md` row to name every step.

#### RC-11 (LOW): rollback variant A is presented as cost-free, and it is not

Repro (`CipherProbeRc020Pass2RollbackTest`): after steps 2 to 5, with the owner role's credentials,
which is what variant A gives the application:

```
CIPHER-RC11 variant A: the application's credentials disabled the erasure-log trigger and replaced its guard function
```

0.1.1 has one `DataSource` (`v0.1.1` `ShreddingAutoConfiguration`), and the guide's variant A sets
`spring.datasource.username` / `password` to the owner role and requires that role to "read and
write your own business tables". Every query the application runs, and anything that can make it
run SQL, then runs as the owner of the four tables, the three guard functions and the schema. The
guide says the opposite: "the append-only guards stay out of the application role's reach" and
"Variant A does not have that cost, because the role that holds the guards is not the one the
application's own code and queries run as". A reader choosing A because of that sentence keeps
presenting the log as append-only while it is not.

Fix (fix pass, text only, `docs/upgrading-0.2.0.md` "Rolling back"): state that under A the whole
application runs as the role that owns the guards and the schema, so the erasure log and tombstone
are advisory for as long as 0.1.1 runs, exactly as under B; move the "Record that in your
processing documentation ... do not present the log as append-only" paragraph so it governs both
variants; keep A's real advantage (no statement to undo, back to 0.2.0 by switching credentials).
Either execute the `ALTER SCHEMA ... OWNER TO` alternative of B in `RollbackTo011ProcedureTest` or
drop "Both variants were executed" for it. The probe flips green when neither quoted phrase remains.

#### RC-12 (INFO): the RC-8 fix reports a non-reproducible build as a build failure

Repro (`internal/gdpr-shredding/probes/cipher-probe-rc020-pass2-rc12.sh <checkout>`, the real
probe body against a clone whose `verify-reproducible.sh` prints one `DIFFERS` line and exits 1, as
the real script does on a mismatch, line 162):

```
        build failed in: scripts/verify-reproducible.sh (two -DskipTests builds); last 40 lines of the log:
        | gdpr-shredding-core-0.1.0-SNAPSHOT.jar                   DIFFERS  aa vs bb
ERROR   rc12                                                 the probe could not reach a verdict (see above)
```

`verify-reproducible.sh` exits 1 for a Maven failure and for a `DIFFERS`/`MISSING` artifact alike,
and the probe calls any non-zero exit of that step a build failure. Fail-closed (the suite still
exits non-zero), but the label is the inverse of RC-8's: "not reproducible" is reported as "could not
reach a verdict". The step label is also wrong: the run with the deliberately failing test shows the
failure inside this step, because the script's second build runs tests.

Fix (fix pass, script): `scripts/verify-reproducible.sh` exits a distinct status (e.g. `3`) when an
enforced artifact differs or is missing, and keeps its other non-zero exits for a failed build;
grep its callers (`release.yml`, `ci.yml`, RELEASING) and confirm each still fails on any non-zero.
In `probe_sources_jar_differs_from_a_build_that_actually_ran_tests`, map that status to WEAK with the
`DIFFERS`/`MISSING` lines printed, any other non-zero to ERROR; relabel the step "build 1 skips
tests, build 2 runs them". Add the internal probe to the fixer's probe set; it flips when the verdict
is WEAK.

### Leads attacked and closed without a finding

- An empty `shredding.erasure.backup-retention=` binds to the documented default 30d, not null and not
  zero.
- The `lock` message builds its mode with `sql.indexOf(" IN ")`; every caller passes a literal with
  `" IN "`, and the table name is the mapped `TableRef`, already validated by admission's relation
  leg. No injection or crash path.
- RC-8: the kept log sits in a `mktemp -d` directory with no secrets in the probe job; the success
  path removes it.
