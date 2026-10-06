# Security review: feat/audit-table-coverage (PR 25, audit-table coverage PR 1a)

## Pass 1 (2026-10-06)

Reviewed head `fd2fbd8`, diff against `bf06920` (PR 24 at the time of the back-merge). Checklist:
the design's integration surface (section 3, rows 1-51), 1a rows only, plus the attack list of
the brief.

### Verdict: MERGE WITH FIXES

No HIGH. One MEDIUM, one LOW, one INFO, each with a probe in the suite that fails on `fd2fbd8`;
three conditions on the deviation rulings and the merge sequence. Every item is fixed before
merge (no allowance).

### Build and tests (PostgreSQL 16 by digest, Docker up, `CIPHER_PROBE_MAVEN=1 ./mvnw verify`)

| module | tests | failures | skipped | note |
| --- | --- | --- | --- | --- |
| core | 443 | 0 | 2 | skipped = PR 24 probes under #C-29 (enabled on PR 24's later head) |
| starter | 270 | 0 | 1 | skipped = #C-30 probe, accepted for 1b (ruling 7) |
| sample | 21 | 0 | 0 | includes the release-candidate probes Envers 3/3, history trigger |

Every existing `CipherProbe*` class ran unchanged and green, except the three skipped above.
With this review's probes added: core 446 (3 new, all RED), starter 272 (2 new, both RED).

### Findings

#### C-25-1 MEDIUM: the catalogue leg is blind under REPEATABLE READ and SERIALIZABLE

`JdbcSupport.inTransaction` never sets an isolation level, so the erasure transaction runs at
whatever the pool or the role says (`spring.datasource.hikari.transaction-isolation`,
`ALTER ROLE ... SET default_transaction_isolation`). Every leg of `MappingAdmission.verdict` reads
`pg_catalog` with plain SQL, which under REPEATABLE READ or SERIALIZABLE uses the transaction
snapshot. That snapshot is taken by the first `SELECT` of the erasure, the subject's
`pg_advisory_xact_lock`, before the table locks. So:

1. A trigger whose `CREATE TRIGGER` is uncommitted when the erasure starts makes the erasure wait
   for its lock; once it commits, the erasure gets the lock, the verdict reads `pg_trigger` from
   the earlier snapshot and admits, and the `UPDATE` fires the trigger (relcache is current). The
   trigger copied the erased subject's index into a history table and the erasure was recorded.
2. The post-`UPDATE` run (C5) reads the same snapshot, so a materialized view committed during
   the erasure (the k4 scenario) is never seen: the erasure commits and records. C5 is void.

The same blindness applies to every earlier admission leg (relation, columns, statistics, R-i)
at the erasure position; the fix below closes all of them.

Repro (`gdpr-shredding-core/.../adapter/jdbc/CipherProbePr25Test`), each the READ COMMITTED
k4/t6 scenario with only the pool's isolation changed:
- `probe_repeatable_read_erasure_fires_a_trigger_its_verdicts_cannot_see`: RED, 1 index value
  copied by the trigger, erasure not refused.
- `probe_repeatable_read_erasure_misses_a_matview_created_between_update_and_recheck`: RED, the
  erasure returns normally.
- `probe_serializable_erasure_misses_a_matview_created_between_update_and_recheck`: RED, same.

Fix (the builder, in the run that built C5; a correction, not a new mechanism: `SchemaVerification`
already pins and restores an isolation level):
- `JdbcErasureStore.erase` runs in a transaction pinned to `READ COMMITTED`: set
  `Connection.setTransactionIsolation(TRANSACTION_READ_COMMITTED)` before the first statement,
  restore the arrived level on success and on failure, and refuse with `SHRED-SCHEMA-008` when it
  cannot be set or reads back as anything else. Pinning, not refusing a non-RC pool, because the
  application's own transactions may need RR and the erasure does not.
- Tests: the three probes above flip green unchanged; `k4` and `t6` become parameterised over the
  three levels; one test that the pool's level is restored after an erasure (success and refusal).
- SECURITY-NOTES, "Copies of the blind index outside the table": the erasure always runs READ
  COMMITTED, and why (catalogue reads use the transaction snapshot). The "Concurrency, stated as
  intent" paragraph keeps its claim; re-run its tests under the pin.

#### C-25-2 LOW: Envers off, a leftover audit table with a configured suffix and revision field is admitted

Design row 10: "K refuses: relation named by Envers' default (or configured prefix/suffix ...)".
`EnversCopyCheck.check` returns early when `EnversService` is absent, disabled or uninitialised,
so with `hibernate.integration.envers.enabled=false` the catalogue leg gets only
`CopySignatures.defaults()`. An audit table written earlier under
`org.hibernate.envers.audit_table_suffix=_log` and `revision_field_name=rev_id` (both still in the
application's configuration) is neither named nor matched by shape, and still holds the index.

Repro: `gdpr-shredding-spring-boot-starter/.../CipherProbePr25StarterTest`
`probe_envers_off_leftover_audit_table_with_configured_suffix_and_revision_field_is_admitted`:
RED, the context boots over `public.env_idx_note_log(email_idx)`.

Fix (the builder, same run): in `HibernateCopyCheck.check`, whenever Envers is not read through
`EnversService` (jar absent, disabled, uninitialised), read from
`SessionFactoryImplementor.getProperties()` the string keys `org.hibernate.envers.audit_table_prefix`,
`audit_table_suffix`, `default_schema`, `revision_field_name`, `revision_type_field_name` (Envers'
defaults when absent). For every admitted table add a `NamedCopy` (schema from `default_schema`
or the table's own, name prefix + table + suffix) and a `RevisionSignature`
(`stored(rev)`, `stored(revtype)`). Plain strings: no Envers import outside `EnversCopyCheck`.
Test `e19_envers_off_configured_names_leftover_audit_table_is_refused`; the probe flips green.

#### C-25-3 INFO: the upgrade guide does not give the refusal sequence an Envers installation meets

A 0.1.1 installation with Envers on a shredded entity meets, one boot each: the audited ciphertext
(`SHRED-CONFIG-001`, model scan), the audited index (`SHRED-SCHEMA-010`, mapping leg, end of the
model scan, before the listener-order check per e1), the listener order (`SHRED-CONFIG-001`), then
the catalogue (`SHRED-SCHEMA-010`: the index column its `_aud` table still holds after
`@NotAudited`, in one message with the planner statistics). `docs/upgrading-0.2.0.md` names
Envers only as "supported when ...", so the operator learns the sequence one refused deploy at a
time.

Repro: `CipherProbePr25StarterTest` `probe_upgrade_guide_names_the_envers_refusal_sequence`: RED,
no paragraph names Envers with both codes and the `_aud` column.

Fix (fix pass): an "Installations using Hibernate Envers" step in the upgrade guide
listing the four refusals in the order measured by a test, each with the one change that clears
it (the `UPDATE ... SET <idx> = NULL; ALTER TABLE ... DROP COLUMN` for the `_aud` table before
the deploy, so three of the four never fire). Test in the sample or starter:
`envers_0_1_1_installation_meets_refusals_in_the_documented_order`, which boots a 0.1.1-shaped
Envers application and asserts the sequence the guide prints.

### Rulings on the builder's deviations

1. `@Temporal` with a blind index refused in every form: **accepted.** Stricter than the design,
   backed by N6's measurement on 7.4.5; remedy text and docs match.
2. Mapping leg compares tables by parsed name, catalogue leg by catalogue: **accepted.** Attempt:
   a second entity mapping the admitted table under a different qualification (`public.note` vs
   `note`) escapes leg M's key, but its Envers or native audit table is still found by leg K, by
   the default name in the same schema or by the revision-column signature, which leg M adds
   whenever Envers is enabled (`EnversCopyCheck` adds the configured signature before walking
   entities). Not reproduced as an admission; closed without a change. C-25-2 is the Envers-off
   case of the same backstop.
3. Whole-row read by a materialized view found from the stored rule tree: **accepted**, fails
   closed (a whole-row reference to any table refuses).
4. Disabled rules admitted like disabled triggers: **accepted.** `ALTER TABLE ... ENABLE RULE`
   takes `SHARE ROW EXCLUSIVE`, blocked by the erasure's `ROW EXCLUSIVE`, and the next verdict
   refuses; under REPEATABLE READ this holds only after C-25-1.
5. No acknowledgement wording in 1a remedies: **accepted**, it is the 1a condition.
6. N7 not written: **accepted** (unreachable when compiled against 7.4.5; the `LinkageError`
   path is e12/n8). **N5 not written: rejected.** Row 33's secondary-table case is the only place
   `AuditMapping.resolveTableName` is called with a table other than the primary, and the named
   copy handed to leg K is built from the primary only. Write N5 as designed
   (`n5_native_audited_secondary_table_index_is_refused`), plus its stale twin (index excluded,
   column left in the secondary audit table, refused by leg K).
7. Fixture changes (LateRow in place of `BEFORE UPDATE` / `pg_sleep` triggers; n28/n50 count two
   verdicts) and `@Disabled` #C-30 for 1b: **accepted.** Read-back assertions unchanged; the
   disabled probe has no subject in 1a (no trigger can be admitted) and its question is open.

### Merge-sequence conditions

- **DCO:** `bf90358` (unsigned) is a trivial back-merge: its tree equals
  `git merge-tree --write-tree ccf5a11 33599c2` (`fe31156`), and its second parent is on PR 24.
  Once PR 24 is on `main`, the DCO job's trivial back-merge rule exempts it. **Acceptable, not to
  be redone**: redoing it means rewriting a pushed branch. The DCO check must be green on the run
  after PR 24 merges; if it is not, report, do not force-push.
- **Back-merge PR 24's final head before merge.** This branch carries PR 24 at `bf06920`; PR 24
  has since gained R-i (`951bad6`, refuse a blind-indexed table with an ancestor). The catalogue
  leg's coverage of ancestors depends on R-i: on `fd2fbd8` a table mapped on a partition is
  admitted while a publication `publish_via_partition_root = true`, a materialized view or a
  foreign key on the parent carries its index column (`pg_get_publication_tables` returns the
  root, `conparentid <> 0` drops the partition's FK clone, `pg_depend` records the parent's
  column), and none of them is in the family. After the back-merge, R-i refuses the shape first.
  The second pass runs on the merged head.

### Integration surface, 1a rows (design section 3)

Verified = a named test ran green in the full verify above (the builder's or a release-candidate probe).

| rows | status |
| --- | --- |
| 1-8, 35 | verified (e1-e8, e14, e16, RC Envers probes 3/3) |
| 10 | **open: C-25-2** (default names and default signatures verified by e9, e15, e17) |
| 11, 45 | verified (e10, e15, e17, e18) |
| 12 | verified (e11, ninth-pass probe) |
| 13, 44 | verified (e12/n8) |
| 14 | verified (e13, ArchUnit) |
| 15, 16, 18, 20 | verified at READ COMMITTED (t1, t3, t5, t8, RC history probe) |
| 17, 19 | **open: C-25-1** (t4, t6, t7 green at READ COMMITTED only) |
| 21 | **open: C-25-1** for a rule enabled after boot (r1 green) |
| 22 | verified (g1) |
| 23 | **open: C-25-1** for the erasure positions (m1, m2 green; k4 at READ COMMITTED only) |
| 24 | verified (f1) |
| 25 | **open: C-25-1** for k5 (p1-p3, NULL column list green) |
| 26, 31 | verified (existing N34/N35; existing cache control) |
| 27b | verified (l1-l4, restricted role) |
| 32 | verified (k1-k3; cost 53-56 ms per erasure measured by the builder, not re-measured) |
| 33 | **open: N5 missing** (ruling 6); n1, n4 verified |
| 34, 43 | verified (n2, n6, n3) |
| 36 | verified (f2, f3) |
| 41 | verified (t3) |
| 9, 27a, 28, 29, 38, 39, 40, 46 | out of scope or not a path (unchanged) |
| 30, 37, 47, 48 | PR 24, not re-reviewed here; nothing in 1a changes the statistics leg (same verdict, one message) |
| 42, 49, 50 | PR 1b |

Counts for 1a: in-scope rows 40, verified 33, out of scope or not a path 8, PR 24 4, PR 1b 3.
**Missing 7** (10, 17, 19, 21, 23, 25, 33). MERGE requires 0: C-25-1 closes 17, 19, 21, 23, 25;
C-25-2 closes 10; N5 closes 33.

### Other attacks, closed without a finding

- Restricted runtime role: every catalogue the leg reads (`pg_trigger`, `pg_rewrite`, `pg_depend`,
  `pg_constraint`, `pg_publication` + `pg_get_publication_tables`, `pg_replication_slots`,
  `pg_attribute` of other schemas) is read by the non-owner role in the builder's tests; green.
- Trigger modes: `ENABLE REPLICA` and `ENABLE ALWAYS` refused (t3); a clone enabled on a
  partition while the parent trigger is disabled is reported alone (the parent row is filtered,
  the clone has no reported ancestor).
- Window between the third run and commit: a materialized view created by a transaction whose
  snapshot predates the erasure's commit holds the old values whatever any check does; that is
  `CREATE TABLE AS` with a catalogue entry (row 28), and the next erasure refuses it. Documented in
  SECURITY-NOTES. `CREATE PUBLICATION ... FOR ALL TABLES` committed in that window does not
  decode the erasure's already-written changes; slot creation waits for running transactions.
- Statistics: one message, copies first then statistics, code unchanged; PR 24's checks untouched
  in 1a (only the call site in `MappingAdmission.verdict` moved).
- Messages against design section 4: the Envers, native, temporal, stale-by-name, stale-by-shape,
  matview, FK, publication, slot and association frames match, with deviations 1 and 5 and the
  temporal remedy of deviation 6.
