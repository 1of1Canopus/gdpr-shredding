# Security review: feat/mapping-admission (PR 19)

## Pass 1, 2026-10-04

Head reviewed: `6d34cd5`. Scope: `git diff 2085552...6d34cd5`, one mechanism: mapping admission (the
name-resolution design page's addendum, revision 2.5, rules R-a to R-h and C-a to C-h with the
section check's S-1 to S-8 folded in), new code `SHRED-SCHEMA-009`. The checklist was the addendum's
threat model (§A.1) and the hostile-path fixture of the section check, re-run against the code. This
PR touches no release, CI or packaging file, so the release hygiene checklist does not apply.

Method: the branch was built and run. Every attack ran on PostgreSQL 16 (`postgres:16-alpine`, the
digest the module's tests pin, and 16.15 in a scratch container), as the runtime role
`NOSUPERUSER NOCREATEDB NOCREATEROLE` that owns the application schema, through
`MappingAdmission.verdict` and `JdbcErasureStore.erase` directly or through a live Spring Boot
context. Each finding has a probe that fails on this head; following this lane's rule the probe
sources are kept outside the public tree, and the fix pass adds them to the suite before it changes
production code.

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -B clean verify` | green, exit 0, Docker up |
| Tests | 559 run, 0 failures, 0 errors, 0 skipped (core 307, starter 235, sample 17), same as the verifier's count |
| Earlier review probes (`CipherProbe*` classes in the suite) | 289 tests, unchanged and green |
| Release-pipeline probe script (`CIPHER_PROBE_MAVEN=1`) | first run 66 fixed / 1 weak (`probe_sources_jar_differs_from_a_test_run`); the probe body re-run alone: both builds green, both sources jars byte-equal to the recorded checksums. A transient build failure, not reproduced; not a finding |
| New probe tests from this pass | 6, all RED on `6d34cd5` (`CipherProbePr19Test`, core) |
| Mutation rows re-run | 25 (red on `n31b` alone, confirmed), 29 (no test red, reclassified below) |

### Verdict: MERGE WITH FIXES

No HIGH. Two MEDIUMs, two LOWs and two INFOs, all fixed before merge under the no-allowance rule.
None needs a new mechanism: C-19-1, C-19-2, C-19-3 and C-19-5 close with one clause at the column
leg the addendum already owns. No design stop.

What the mechanism gets right, confirmed by execution:

- Every rule of §A.3 decides as written on the section check's fixture, including the hostile path.
- The two locks pin what the verdict describes. With `ROW EXCLUSIVE` plus `SHARE UPDATE EXCLUSIVE`
  held on a parent, a second session times out on `ATTACH PARTITION` and `CREATE TABLE ... PARTITION
  OF` against an intermediate partition, `CREATE TABLE ... INHERITS` a child, `ALTER TABLE ...
  INHERIT` a child, `ALTER TABLE ... NO INHERIT`, `ANALYZE`, `VACUUM` of a child and `CREATE INDEX
  CONCURRENTLY`: `LOCK TABLE` without `ONLY` takes the mode on every descendant. A child owned by
  another role with no grant is locked and cleared through the parent without a privilege error.
- The verdict is not cached: with mutation 25 applied, `n31b` alone goes red.
- `JdbcSupport.inTransaction` keeps the work's exception when rollback and reset fail.

### Findings

| id | severity | one line |
| --- | --- | --- |
| C-19-1 | MEDIUM | an enum tenant is admitted; the runtime role may give its own enum an implicit cast to `text` with its own function, and the erasure, both read-backs and the record then agree on `COMPLETE` with 0 cleared over a populated index |
| C-19-2 | MEDIUM | a `name` (or `"char"`) tenant or subject is admitted; the type truncates its input, so a subject id longer than 63 bytes is never matched, and the erasure is recorded `COMPLETE` with 0 cleared over a populated index |
| C-19-3 | LOW | admitted mappings no erasure can execute (`uuid` or enum under the driver's default, a domain over an enum under any setting) fail every erasure with 42883, reported as `SHRED-KEY-UNAVAILABLE`; the docs' driver note is wrong for both |
| C-19-4 | INFO | the descendant walk calls the inheritance set a tree; it is a DAG, a relation is visited once per path, and twelve stacked diamonds of plain tables make an admissible table `SHRED-SCHEMA-005` |
| C-19-5 | LOW | a `uuid` or numeric subject canonicalises the bound text under `stringtype=unspecified`: an erasure requested for `A0EEBC99-...` or `0042` clears the blind index of subject `a0eebc99-...` or 42, whose key survives |
| C-19-6 | INFO | the cost statement of step 1b omits the wraparound autovacuum, which does not yield; the PR and the design page say autovacuum yields |

#### C-19-1 (MEDIUM): an enum's role-owned implicit cast makes the three legs agree on a falsehood

**Repro.** As the runtime role:

```
CREATE TYPE app.c191_e AS ENUM ('T1','T2');
CREATE FUNCTION app.c191_lie(app.c191_e) RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT 'nope'::text $$;
CREATE CAST (app.c191_e AS text) WITH FUNCTION app.c191_lie(app.c191_e) AS IMPLICIT;
CREATE TABLE app.c191 (id bigint, tenant app.c191_e, subject varchar(64), email_idx varchar(64));
INSERT INTO app.c191 VALUES (1, 'T1', 's-c191', 'HMAC-RESIDUE');
```

`CREATE CAST` needs ownership of one of the two types, which the role has. `tenant
OPERATOR(pg_catalog.=) ?` bound as `varchar` (the driver's default) now resolves to
`pg_catalog.=(text, text)` through `app.c191_lie`: no 42883 any more. A cast is not looked up through
`search_path`, so the bracketed framework read-back resolves the same way. Measured end to end
through `JdbcErasureStore.erase`: the verdict is `Admitted`, the erasure records `COMPLETE` with
`blind_index_cleared = 0`, and `enum_eq(tenant, 'T1')` still finds the populated row. The same cast
also turns an unknown-typed parameter (`stringtype=unspecified`) away from `enum_eq`.

C-h looks for an operator named `=`; C-d admits the enum; nothing reads `pg_cast`. A clause on
`pg_cast` alone would not hold: `pg_cast` is not pinned by the table lock, so a cast created between
the type leg and the `UPDATE` changes the operator the `UPDATE` resolves.

**Fix, clause C-i at the column leg.** For a column whose role is tenant or subject (the two
the module compares against a bound `String`), refuse unless the base type, after the domain chase,
is one of `pg_catalog.text`, `pg_catalog.varchar` or `pg_catalog.bpchar`, identified by the type
leg's oid and namespace (fixed built-in oids 25, 1043, 1042), not by a spelling. The runtime role
cannot create a cast or an operator between two built-in types, and casts on a domain are ignored,
so nothing unpinned can change what the `UPDATE` resolves. Message: the column, its type, and the
remedy "map the tenant and subject columns as text, varchar or char(n)". The identifier column keeps
C-b to C-h (it is compared with Hibernate's own typed binds). Admitting `uuid`, enum or numeric
tenant and subject columns again would need the comparison to go through the type's canonical text
form, which is a new mechanism: a design page if the maintainer wants it, not part of this fix.
Update `n43` (the enum row becomes a refusal), the judge's remedy text ("or a numeric type" applies to
the identifier only), SECURITY-NOTES "Mapping admission", `docs/upgrading-0.2.0.md` and the
CHANGELOG. Probe: `CipherProbePr19Test.probe_an_enum_with_a_role_owned_implicit_cast_is_admitted_and_its_erasure_clears_nothing`.

#### C-19-2 (MEDIUM): `name` and `"char"` truncate on input, so a long subject is never matched

**Repro.** `CREATE TABLE app.c192 (id bigint, tenant varchar(64), subject name, email_idx
varchar(64))`; the application writes subject `auth0:user-0123...-tail` (64 bytes, valid under the
module's 255-byte identifier rule) as a bound `String`. PostgreSQL stores 63 bytes. The erasure for
that subject id compares the stored value with the full one through `pg_catalog.=(name, text)`:
`UPDATE 0`, same-text read-back 0, framework read-back 0, record `COMPLETE` with 0 cleared, index
still populated (measured end to end). `name` passes every clause: own equality in `pg_catalog`,
collation `C`. `"char"` keeps one byte of its input the same way (`'sx'` stored as `'s'`, measured).

**Fix.** C-i above refuses both. Probe:
`CipherProbePr19Test.probe_a_name_typed_subject_is_admitted_and_a_long_subject_is_never_erased`.

#### C-19-3 (LOW): admitted mappings that no erasure can execute, reported as a key-store outage

**Repro.** A `uuid` tenant column under the driver's default: the verdict is `Admitted` with no WARN,
and every erasure fails `uuid = character varying` (42883), surfaced by `JdbcSupport.unavailable` as
`SHRED-KEY-UNAVAILABLE`. A domain over an enum fails the same way under `stringtype=unspecified` as
well (`operator does not exist: <domain> pg_catalog.= unknown`, measured). Fail-closed: nothing is
recorded. But the boot log is green, the code sends the operator to the key store, and a retry can
never succeed. SECURITY-NOTES' driver note says "an application that writes a String property into
such a column already needs that setting": a JPA application maps a `uuid` column as
`java.util.UUID` and writes it with no setting at all, and the note's promise that the setting
erases is false for a domain over an enum.

**Fix.** C-i refuses every shape here at startup and at the erasure leg, with `-009` and the
remedy. Replace the driver note with C-i's rule. Probe:
`CipherProbePr19Test.probe_an_admitted_mapping_the_erasure_cannot_execute_is_reported_as_a_key_store_outage`.

#### C-19-4 (INFO): the descendant walk visits a relation once per path

**Repro.** `CREATE TABLE app.dm_ab () INHERITS (app.dm_a, app.dm_b)` under two children of one root
gives `dm_ab` two `pg_inherits` rows; `MappingAdmission.descendants` queues it twice. Twelve stacked
diamonds (36 plain tables, 48 `pg_inherits` rows) pass `MAX_DESCENDANTS` and the admissible table is
`SHRED-SCHEMA-005` at startup and at every erasure. Fail-closed; the javadoc's "the set is a tree
(PostgreSQL refuses an inheritance cycle), so nothing is visited twice" is the wrong statement.

**Fix.** A visited set keyed by oid in `MappingAdmission.descendants`; the bound counts
distinct relations; javadoc corrected to "a DAG: legacy inheritance allows several parents". Probe:
`CipherProbePr19Test.probe_a_diamond_inheritance_is_walked_once_per_relation`.

#### C-19-5 (LOW): a canonicalising subject type lets one subject id clear another's index

**Repro.** Under `stringtype=unspecified` (the setting the docs prescribe for `uuid`) the bound text
is an unknown literal, parsed by the column type's input function. `subject uuid`:
`'A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11'` matches the row stored as `a0eebc99-...`; `subject bigint`:
`'0042'` and `'+42'` match 42 (measured). The module keys data by the exact `SubjectId` string, so the
erasure for the other spelling destroys no key, tombstones a subject that never existed, and clears
the blind index of a subject whose data key survives. This is C-e's harm, one subject's erasure
clearing another subject's row, through an input function instead of a collation.

**Fix.** C-i refuses both. Probe:
`CipherProbePr19Test.probe_a_uuid_subject_lets_an_erasure_for_another_spelling_clear_this_subjects_index`.

#### C-19-6 (INFO): the cost statement of step 1b omits the wraparound autovacuum

**Repro.** PostgreSQL 16.15, `autovacuum_freeze_max_age = 100000`, a 300 000-row table, 120 000
burned transaction ids, autovacuum cost-limited. While `autovacuum: VACUUM ANALYZE public.big (to
prevent wraparound)` ran, `LOCK TABLE big IN ROW EXCLUSIVE MODE` succeeded and `... IN SHARE UPDATE
EXCLUSIVE MODE` hit a 6 s lock timeout with `deadlock_timeout` at 1 s: the wraparound worker is not
cancelled. Before step 1b the erasure's `ROW EXCLUSIVE` did not conflict with any vacuum. While it
waits the erasure holds the subject's advisory lock and its key rows `FOR UPDATE`, and later erasures
of the same table queue behind it.

**Fix.** One sentence in the step-1b cost paragraph of SECURITY-NOTES and
`docs/upgrading-0.2.0.md`: an erasure also waits behind an autovacuum run to prevent wraparound,
which does not yield, for as long as that run takes. Correct the PR body and design row 2 ("autovacuum
yields" holds only for an ordinary autovacuum). Probe:
`CipherProbePr19Test.probe_the_lock_cost_statement_names_the_wraparound_autovacuum`.

### Rulings on the stated deviations

1. **Step 1b on every table: accepted.** This is the lock-mode resolution S-2 named, applied to the
   whole set its acceptance property covers, not a new mechanism. Measured above: the property holds
   for every descendant through `LOCK TABLE`'s recursion. Cost: application DML takes `ROW EXCLUSIVE`
   and is never blocked. Two erasures take the tables in the store's one order, and `ROW EXCLUSIVE`
   then `SHARE UPDATE EXCLUSIVE` inside one transaction do not conflict with each other, so there is
   no upgrade deadlock. The only new cycle needs an application transaction that holds `SHARE UPDATE
   EXCLUSIVE` or stronger on the table (`ANALYZE` inside a transaction, `CREATE STATISTICS`, `VALIDATE
   CONSTRAINT`, `ATTACH`) and then writes a shredded row for the subject being erased. A schema-changing
   transaction that also writes shredded rows is not a shape worth a control, so no finding. The one
   cost the text omits is C-19-6.
2. **Four flat statements and a Java walk: accepted, with C-19-4.** The facts are the design's:
   relation, privileges, `bypassrls`, RLS flags, kind and persistence per descendant, columns in
   request order with the all-NULL row for an absent column, and type facts per distinct type with
   the domain chase. Under READ COMMITTED each statement takes a new snapshot. Every fact they read is
   pinned by the two locks: rename, drop, column type, collation, `NOT NULL`, generated, RLS
   enable/force, policies, and the descendant set all need `SHARE UPDATE EXCLUSIVE` or stronger on
   the table or a descendant. The unpinned catalogues are `pg_operator` and `pg_cast`. An operator
   created mid-erasure does not change `OPERATOR(pg_catalog.=)`. A cast does (C-19-1), and C-i
   closes it by admitting only types the role cannot create a cast for.
3. **Enum columns admitted: not accepted.** The default-driver outcome is fail-safe in effect but
   reported as the wrong code (C-19-3). Under the cast vector it is a silent falsehood (C-19-1). A
   domain over an enum never erases, and under `stringtype=unspecified` the neighbouring `uuid` and
   numeric types collide spellings (C-19-5). C-i replaces it, and the driver note goes.
4. **Inheritance, `TABLE_PER_CLASS`: attacked, clean.** A concrete `TABLE_PER_CLASS` root with its
   own table and a leaf that declares its own `@Shredded` and `@BlindIndex` fields boots. Admission
   targets exactly `public.c19_tpc_leaf`, the erasure clears the leaf's index, and the root's table
   holds nothing. A field the leaf inherits from an entity ancestor is still refused by S-23. The
   test (`CipherProbePr19StarterTest.probe_a_table_per_class_leaf_is_checked_on_its_own_table_and_erases`
   with its two entities) is green on this head. The fix pass should adopt it and drop "`TABLE_PER_CLASS`
   is not" from SECURITY-NOTES. Not a finding.

### Open mutation rows

- **Row 25 (cache the verdict): confirmed.** Applied as a per-table map in `JdbcErasureStore.admit`.
  `n31b` goes red and nothing else does. Restored.
- **Row 29 (R-b passes at erasure): reclassified, no finding.** Applied by making the `Absent` branch
  of `admit` a no-op: all 48 admission tests stay green. Reachability attempted: the `LOCK` and the
  relation leg receive the same `TableRef.sql()` text, blanket-quoted and two-part. `parse_ident` and
  the parser resolve it identically. Renaming or dropping the locked relation needs `ACCESS
  EXCLUSIVE`, which waits behind step 1. An absent relation therefore never reaches the verdict
  (`42P01` at the `LOCK`), and the branch is defence in depth for a state the lock makes unreachable.

### Framework paths to the mapped relation

The PR's table was checked row by row. Verified by execution: the blind-index `UPDATE` and both
module read-backs (every probe above), the framework-shaped read-back under the cast and truncation
vectors (it agrees with the `UPDATE`, which is why C-19-1 and C-19-2 are silent), partitions and
inheritance children (DDL list above), the second-session swap (`n31b`, `n49`), JOINED, SINGLE_TABLE
and TABLE_PER_CLASS leaves. Read, not executed: `@Subselect` (refused by `TableRef`'s pattern before
any statement exists), `@Embeddable`, `@ElementCollection` and `@SecondaryTable` (refused at startup
by earlier controls). One lead outside this PR's scope, not reproduced and not counted: an
`@Audited` (Envers) entity copies the blind-index column into its audit table, a relation no erasure
statement addresses. It belongs to the release-candidate whole-module pass.

## Second pass (2026-10-04), head af95483

**Verdict: MERGE WITH FIXES (C-19-7).** This is the last pass on this PR. One new LOW finding:
the startup check skips clause C-i for a tenant or subject column that is also the entity's
identifier column. The erasure leg still refuses that column, so nothing is destroyed or
misrecorded, but the context starts green. This is the same startup-versus-erasure disagreement as
C-19-3. Its fix is the one-line correction below, not a new mechanism, so it needs no design page.

### Numbers, measured on this head

| check | result |
| --- | --- |
| `./mvnw -B verify`, Docker up | green: core 315, starter 237, sample 17 = 569 tests, 0 failed, 0 skipped |
| coverage (line / branch) | core 90.0 / 75.5, starter 88.1 / 74.8 |
| `CipherProbe*` reports in that run | 66 classes, 0 failures, 0 errors, 0 skipped |
| first-pass probes | 6 in `CipherProbePr19Test` and 1 in `CipherProbePr19StarterTest`, all green. Their bodies match the probe file as delivered (formatter reflow only) |
| `gh pr checks 19` | 6/6 pass at af95483 |

### First-pass findings closed

| id | closed by | probe (green, executed) |
| --- | --- | --- |
| C-19-1 | 0cf7ec7, C-i | `probe_an_enum_with_a_role_owned_implicit_cast_is_admitted_and_its_erasure_clears_nothing` |
| C-19-2 | 0cf7ec7, C-i | `probe_a_name_typed_subject_is_admitted_and_a_long_subject_is_never_erased` |
| C-19-3 | 0cf7ec7, C-i, driver note removed | `probe_an_admitted_mapping_the_erasure_cannot_execute_is_reported_as_a_key_store_outage` |
| C-19-4 | 1b7f9f4, visited set, bound counts distinct relations | `probe_a_diamond_inheritance_is_walked_once_per_relation` |
| C-19-5 | 0cf7ec7, C-i | `probe_a_uuid_subject_lets_an_erasure_for_another_spelling_clear_this_subjects_index` |
| C-19-6 | fd02c0f; the PR body and the design row say the same | `probe_the_lock_cost_statement_names_the_wraparound_autovacuum` |

The `TABLE_PER_CLASS` test is adopted and green. SECURITY-NOTES no longer says `TABLE_PER_CLASS` is
untested.

### C-i attacked, holds (executed: `CipherProbePr19SecondPassTest`, 5/5)

Fixture: the same runtime role as in the first pass. That role owns schema `app`, can create
collations and domains there, and has no database `CREATE`. `citext` was installed by the superuser.

- Domain over domain over `text`: admitted. Domain over `varchar(64)` with a `CHECK`: admitted. Both
  are right, because the chase reaches oid 25 or 1043, and casts on a domain are ignored.
- `text[]`: refused (C-c). `citext` as tenant, and a domain over `citext` as subject: refused (C-b,
  ahead of C-i). Either clause is a refusal.
- `char(16)` tenant and subject: admitted. Rows stored padded (`'abc'` and `'abcd'`) are cleared
  exactly, under the driver's default and under `stringtype=unspecified`, each subject alone. Every
  `bpchar` comparison ignores trailing blanks, and identifiers cannot contain whitespace
  (`Identifiers.validate`), so no two subjects can collapse.
- `varchar(4)` with a 6-byte subject: the application's write fails with `22001`, and nothing is
  stored truncated. Non-blank excess is never silently cut, and blank excess cannot occur.
- A nondeterministic ICU collation (`und-u-ks-level2`) on a `text` column, on a domain, on a domain
  over that domain, and on a `char(16)` column: all refused by C-e. The harm is measured first: on
  the domain-collated column, the module's own `UPDATE` for `alice` matches the row of `Alice`. The
  erasure is refused, and the index stays populated.
- The role set is closed. `"Tenant Column"`, `"tenant"`, leading or trailing space, a doubled space,
  upper case, a no-break space and `""` are all refused when the `Column` is constructed. A
  non-interned equal string decides C-i like the constant. `Target.forErasure` gives both compared
  columns the C-i role.
- Who builds a `Column` in production code: `MappingAdmission.Target.forErasure` (erasure leg) and
  `ShreddedModel.admissionTargets` (startup leg). Neither takes the role from user input. The second
  one is C-19-7.

### Regressions in the other legs

None found. The whole suite and every earlier probe run green. The visited set marks the root and
counts only distinct relations against `MAX_DESCENDANTS`. The identifier column keeps C-b to C-h,
with its own remedy text. `TypeFacts.oid` is read only after C-a has guaranteed a declared type.

### Public text

SECURITY-NOTES, `docs/upgrading-0.2.0.md`, the CHANGELOG and the PR body contain no agent or
person name, internal path or internal document reference. Finding ids and probe names remain, as
the convention allows.

### Findings

| id | severity | one line |
| --- | --- | --- |
| C-19-7 | LOW | a tenant or subject column that is also the identifier column is checked at startup as the identifier only, so C-i is skipped there: the context starts green and every erasure is refused with `SHRED-SCHEMA-009` |

#### C-19-7 (LOW): the startup leg drops the subject role of a column that is also the identifier

**Repro.** The entity has `@Id UUID id` and `@Column(name = "id", insertable = false, updatable =
false) String subject`, and `@BlindIndex(subjectColumn = "id", tenantColumn = "tenant_id")`. The
direct form, with no property over the identifier column, is refused by the model, and that refusal
holds. Here one basic property maps the column, so the model accepts it. Hibernate creates `id
uuid`. `ShreddedModel.admissionTargets` adds `Column(id, COMPARED, IDENTIFIER)` first. Then
`addOnce` drops `Column(id, COMPARED, SUBJECT)`, because it compares the ref and the use only. The
startup targets measured are `[id COMPARED identifier column, tenant_id COMPARED tenant column,
email_idx ASSIGNED blind-index column]`. The identifier rules admit `uuid`, so the context starts
with no refusal and no WARN. The row persists, and then every erasure fails as follows:
`SHRED-SCHEMA-009 ... the subject column public.c19b_owner.id is of type uuid`. The erasure leg
builds its targets from the blind indexes alone. The erasure is refused before it changes anything:
the index stays populated and no record is written. The startup gate is meant to refuse what the
erasure refuses, and it does not. This is the same class as C-19-3, and the error code is now right.

**Fix.** In `ShreddedModel.addOnce` (starter), treat a column as a duplicate only when ref, use and
role all match, so a role is never dropped. `MappingAdmission.Target.addOnce` (core) gets the same
key for consistency. There, today, the tenant and subject roles both trigger C-i, so the change
there alters no verdict. Do not fix this by changing the order of insertion: a later caller would
bring the bug back. Add a unit row to `MappingAdmissionStarterTest`: the admission targets of an
entity whose subject column is its identifier column contain a `SUBJECT` entry for that ref. Probe:
`CipherProbePr19bStarterTest.probe_a_subject_column_that_is_also_the_identifier_skips_c_i_at_startup`,
with entity `cipherprobe19b.idsubject.C19bOwner`. It is red on af95483 because the context starts.
It turns green when startup fails with `SHRED-SCHEMA-009` naming `public.c19b_owner.id is of type
uuid`. Mutation row to add: dedup by ref and use only, which must make that probe red.
