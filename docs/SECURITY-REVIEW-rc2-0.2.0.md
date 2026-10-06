# Security review: release candidate 0.2.0, whole-module pass 2

## Pass, 2026-10-06

Head reviewed: `333a4a1` on `main` ("feat(jdbc): acknowledge a copy of a protected column with a
clearing hook (#26)"). Pass 1 ran at `5345c51`, before PRs 22 to
26. This pass is the interaction of the final head, not a re-review of each PR; per-PR findings are
not re-reported. Method: the head was built and run, and a real 0.1.1 install (the jars on Central,
PostgreSQL 16 at the digest the tests pin) was upgraded to this head end to end.

### Verdict: TAG WITH FIXES

No HIGH, no MEDIUM. Two LOWs (RC2-1 documentation, RC2-2 the open point of PR 26) and one INFO
(RC2-3, release notes outside this repository). Under the no-allowance rule all three are closed
before the tag. Neither needs a new mechanism.

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -B -pl gdpr-shredding-core verify`, Docker up | green: 544 run, 0 failures, 0 errors, 0 skipped |
| `-pl gdpr-shredding-spring-boot-starter install` | green: 285 run, 0 / 0 / 0 |
| `-pl gdpr-shredding-sample verify` | green: 22 run, 0 / 0 / 0 |
| Total | 851 run, 0 failures, 0 errors, 0 skipped (pass 1 head: 576) |
| Earlier `CipherProbe*` classes | 31 in core, 53 in the starter, 3 in the sample (report files), unchanged, all green |
| Release-pipeline probes (`CIPHER_PROBE_MAVEN=1`) | run 1: 66 fixed / 0 weak / 1 error (`probe_sources_jar_differs_from_a_test_run`: a Testcontainers container failed to start inside the probe's nested build, `ContainerLaunch`, not an assertion). Run 2, same tree, unchanged: 67 fixed / 0 weak / 0 error |
| Reference guard | `--tree` clean, `--jars` core and starter clean, `--self-test` all cases correct |
| Licence gate | runs inside each module's `verify` (exec-maven-plugin), green; `--self-test` all cases correct |
| New probes from this pass | 4 tests: 3 RED (RC2-1 x2, RC2-2), 1 GREEN confirmation |

### Findings

**RC2-1 (LOW, docs). The upgrade guide's Envers refusal order is not the order a 0.1.1 install
meets.** `docs/upgrading-0.2.0.md` ("A 0.1.x installation with Hibernate Envers meets these
refusals in this order, one per startup") lists five positions. Executed on a running 0.1.1 install:

- Positions 1 and 3 cannot occur. 0.1.1 itself refuses an audited `@Shredded` field
  (`SHRED-CONFIG-001 the attribute Patient_AUD.email is mapped by ... but has no field-level
  @Shredded`) and Envers' auto-registered listeners (`SHRED-CONFIG-001 ... listener is registered on
  post-insert but is not last`); a 0.1.1 install that runs already has both remedies.
- The schema-less mapping is `SHRED-CONFIG-001`, and it is the **first** code refusal, ahead of the
  audited blind index. The guide puts "a schema-less mapping" under `SHRED-SCHEMA-009` at position 4.
- Position 5 is one message, as promised, but it also names triggers on the table and a
  `<table>_history` table holding the column, not only `_aud` and statistics.

Effect: an operator plans five startups and meets a different sequence; every refusal fails
closed, so no data effect. Repro: the 0.1.1 half outside the suite (table below); the 0.2.0 half
`gdpr-shredding-sample/.../cipherrc2/CipherProbeRc2UpgradeOrderTest`:
`rc2_first_refusal_of_a_0_1_1_envers_shape_is_the_missing_schema` (GREEN, the code's order),
`probe_upgrade_guide_orders_the_schema_less_mapping_after_the_audited_blind_index` (RED),
`probe_upgrade_guide_promises_refusals_a_running_0_1_1_install_cannot_meet` (RED).
Fix (fix pass): rewrite that paragraph from the table below: 1. `SHRED-CONFIG-001` names no schema;
2. `SHRED-SCHEMA-010` from the mapping (audited `@BlindIndex`); 3. `SHRED-SCHEMA-009` admission (column
type, a table with a parent); 4. `SHRED-SCHEMA-010` from the catalogue, one message (triggers,
publications, slots, `_aud`/`_history` columns, statistics). State that the two Envers shapes 0.1.1
already refused cannot be present. Keep the probes; flip the RED ones by the text change.

**RC2-2 (LOW, BV). The starter's printed "clear and drop" statement escapes a mapping name as log
text.** Item 4 of the brief, PR 26's open point. `HibernateCopyCheck.clear` prints
`LogText.escape(name)`; for a quoted mapping name with a line break it prints
`UPDATE public."a\u000Ab_aud" ... DROP COLUMN ...`, which PostgreSQL reads as a different
identifier (the literal backslash sequence): run as printed it fails, or addresses a decoy of that
name. The real audit table keeps the copies; the next startup refuses again, so no erasure runs over
them. Same class as C-26-3, which fixed the core's printed statements and not this one.
**Ruling: fix before the tag, LOW, fix pass**, not a residual: the fix is the existing helper, not a
mechanism. Fix: expose the core's `JdbcSupport.sqlIdentifier` rendering for a `TableRef` and a
column (one public static in `com.housedevinci.shredding.adapter.jdbc`, or a `sql()` that already
uses it), and build `HibernateCopyCheck.clear` from it for both table parts and the column; prose
around it keeps `LogText`. Probe:
`gdpr-shredding-spring-boot-starter/.../autoconfigure/CipherProbeRc2PrintedStatementTest.probe_mapping_leg_clear_statement_prints_a_quoted_name_as_log_text` (RED).

**RC2-3 (INFO, release notes, Work repository).** `internal/gdpr-shredding/releases/RELEASE_NOTES_0.2.0.md`
repeats the RC2-1 order (line 179, "meets five refusals, one per startup, in this order") and still
carries four "(PR 26, pending merge: confirm sha at tag)" marks (lines 244, 497, 557, 570) and a
test count from `0aa71f6` (core 538) where the merged head runs core 544. Fix (maintainer, no
code): align line 179 with the RC2-1 text, replace the marks with `333a4a1`, update the numbers.
Probe: none in the module; the RC2-1 probes cover the shared text.

### Item 5: the 0.1.1 to 0.2.0 upgrade, executed

Start: 0.1.1 from Central, Spring Boot 4.1.1, PostgreSQL 16; role `app` owning database `shop`;
`patient` partitioned by `LIST (tenant_id)` with two partitions and a plain index on `email_idx`;
Envers (`@Audited`, ciphertext `@NotAudited`, manual registration, all forced by 0.1.1); an
`AFTER UPDATE` history trigger copying `OLD.email_idx` into `patient_history`; `ANALYZE` run (rows
in `pg_stats` on the root and both partitions); hook `crmNotifier`. 0.1.1 erased `p-2` with the hook
failing: records 1 and 2 `PARTIAL`, and the trigger had copied `p-2`'s index into `patient_history`
(nothing in 0.1.1 says so).

| # | Action | Refusal at the next start (first one, code) | Remedy taken |
| --- | --- | --- | --- |
| 0 | swap the jar only | `SHRED-SCHEMA-003`, 72 problems in one message | guide steps 2, 3, 4, 5, 6 verbatim (owner `shred_owner`) |
| 1 | after steps 2 to 6 | `SHRED-CONFIG-001` table "patient" names no schema | `hibernate.default_schema=public` |
| 2 | | `SHRED-SCHEMA-010` from the mapping: Envers copies `email_idx` into `public.patient_aud` | `@NotAudited` on the `@BlindIndex` field |
| 3 | | `SHRED-SCHEMA-010` from the catalogue, one message: trigger `patient_history_trg` (cloned to 2 partitions); `patient_aud.email_idx`; `patient_history.email_idx` (named as Hibernate's history table); statistics target -1 and stored rows on root and both partitions, with the exact statements | aud: UPDATE + DROP COLUMN; history column renamed and trigger function rewritten (needs the owner: step 4 took CREATE from `app`); step 3a statements as printed, as the table owner |
| 4 | | `SHRED-SCHEMA-010`: the trigger alone | `shredding.jdbc.acknowledged-copies[0]` kind=trigger, cleared-by=`historyScrubber` (a hook clearing `patient_history.idx_copy` by subject) |
| 5 | | none: boots, one WARN naming the acknowledged trigger and its hook | |
| 6 | statistics target set back to -1 on one partition, acknowledgement kept | `SHRED-SCHEMA-010` statistics on partition `patient_rest` | target 0 again |

Then, on 0.2.0: retry of the 0.1.1 `PARTIAL` for `p-2` with `historyScrubber` failing: record 3
`PARTIAL`, `crmNotifier` succeeded, `historyScrubber` failed, "leaves trigger ... patient_history_trg";
`patient_history` still holds `p-2`'s index. Retry with the hook succeeding: record 4 `COMPLETE`,
`SCRUBBED 2` (both `p-2` copies, the 0.1.1 one included). Fresh erasure of `p-1`: record 5
`PARTIAL` naming both hooks `pending` (the trigger named on `historyScrubber`), record 6 `COMPLETE`;
the trigger's new copy of `p-1` cleared. The upgrade path holds; RC2-1 is its only defect.

### Items 2 and 3: leads attacked and closed without a finding

- **Several refusals at once.** Each startup reports the first failing stage in full; inside a stage
  every problem is listed (row 3). Acknowledging the trigger never hid the statistics refusal (row 6),
  and the acknowledgement does not cover `_aud`/`_history` tables (row 3 lists them separately).
- **Acknowledged copy x recheck x record.** `clearBlindIndexes` requires every entry to admit
  something before the first statement (`refuseUnused`), so the record names every entry's hook
  (`requireNamed`); the post-UPDATE recheck refuses any copy not admitted and any entry no longer in
  use. A publication `FOR ALL TABLES` or a materialized view created after the UPDATE is refused by
  the recheck (PR 25 probes); `CREATE TRIGGER`, `ENABLE TRIGGER`, `ALTER PUBLICATION ADD TABLE` and
  `SET STATISTICS` take locks that conflict with the erasure's `SHARE UPDATE EXCLUSIVE` and wait.
  A logical slot created during the erasure does not decode it (transactions running at slot
  creation are before its consistent point). The window recheck-to-commit is the documented residual.
- **Retry after PARTIAL x append guard.** A retry reads the latest record, runs the hooks, and the
  append re-reads the latest under the global append lock (`requireAnswered`). Two concurrent runs of
  the same subject: the later append must answer what the earlier left pending or failed, so a
  `COMPLETE` can only follow a run in which the clearing hook succeeded after the copy was written
  (the copy is written by the erasure's own committed UPDATE; a retry's UPDATE matches no row and
  fires no row trigger). No route to `COMPLETE` with an acknowledged copy still holding the value was
  found. Not a finding: a retry re-runs hooks that the latest record already reports succeeded
  (record 4 re-ran `crmNotifier`); harmless for an idempotent hook, noted for the docs' wording.
- **Ancestor refusal at erasure time** was not re-attacked here (per-PR passes on PRs 22 and 24
  cover it); at startup it sits in the admission stage (row table, position 3 of RC2-1's fix).

### Item 6: docs against code

CHANGELOG names `SHRED-SCHEMA-008`, `-009` (R-i included), `-010`, `SHRED-ERASURE-LOCK-WAIT`,
`SHRED-CONFIG-001`, and the breaking changes (text-typed ids, statistics off, no ancestor, no copies
unless acknowledged, READ COMMITTED pin, first record names every hook). SECURITY-NOTES carries the
residuals for statistics, former-parent values, copies outside the table (acknowledged copies
included) and the log text. Mismatches: RC2-1 (guide), RC2-3 (release notes).
