# Security review: feat/statistics-admission (PR 24), planner statistics on blind-index columns

## Pass 1 (2026-10-05), head 463b4dd

**Verdict: MERGE WITH FIXES.** No HIGH. Two MEDIUM, two LOW. C-24-1 is a design stop (design page):
the builder writes a one-page design, the reviewer reviews it before code.

Method: the branch was built and run. Every finding below has a probe that fails on 463b4dd:
`internal/gdpr-shredding/probes/CipherProbePr24Test.java` (6 probes, PostgreSQL 16.15 on the digest
the module pins). The fixer adds it to `gdpr-shredding-core/src/test/java/.../adapter/jdbc/` before
touching production code. The catalogue facts and lock measurements were taken on 16.15, 17.11 and
18.6.

| check | result |
|---|---|
| `CIPHER_PROBE_MAVEN=1 ./mvnw -B verify` | BUILD SUCCESS, 620 tests, 0 failures, 0 skipped (core 363, starter 240, sample 17) |
| existing `CipherProbe*` tests | all green; the only change to them is the fixture's init script (deviation 1) |
| new probes `CipherProbePr24Test` | 6 run, 6 RED |
| test-only event trigger in shipped jars | absent from the core, starter and sample jars; it lives only in `src/test/resources` |

### Findings

**C-24-1 MEDIUM: the check does not cover ancestors, so a partition or inheritance child keeps its
index values in the parent's statistics. DESIGN STOP.**
The family is the table plus its descendants. When the erased table is itself an inheritance child
or a partition, `ANALYZE` on the parent stores `inherited` statistics computed from the child's rows
under the parent's column. Any role with `SELECT` on the parent reads them from `pg_stats`.
Repro: `app.p24kid INHERITS (app.p24par)`, `SET STATISTICS 0` on `ONLY app.p24kid`, 300 rows,
`ANALYZE app.p24par`. A plain reader sees `most_common_vals` of the child's `email_idx` on
`p24par`, and `MappingAdmission.verdict` on `app.p24kid` returns `Admitted[warnings=[]]`. The
partition variant (`app.p24pp_t1` of `app.p24pp`, the target being the partition) gives the same
result.
The lock claim in deviation 6 also stops at the target's own family. While an erasure holds `ROW
EXCLUSIVE` and `SHARE UPDATE EXCLUSIVE` on the child, `ALTER TABLE ONLY par ALTER COLUMN email_idx
SET STATISTICS 100` and `ANALYZE par` both complete (measured, 16.15), so the parent samples values
the erasure is about to clear.
Property that must hold: no ancestor of an erasure target stores statistics computed from the
target's blind-index column, and none can start storing them between the verdict and the commit.
Paths to cover:
- an ancestor's target and its `inherited` rows, for both partitions (`pg_partition_ancestors`) and
  legacy inheritance (`pg_inherits` walked upward, bounded like the descendant walk);
- expression indexes and extended statistics on an ancestor, which `ANALYZE` builds from inherited
  samples;
- the lock (an ancestor locked against `ALTER ONLY` and `ANALYZE`, with a lock order that cannot
  deadlock against `ANALYZE parent`), or a refusal of any target that has an ancestor;
- the remedy text and the upgrade guide's step 1 queries, which list descendants only.
Probes: `probe_inheritance_parent_statistics_keep_the_child_index_values`,
`probe_partition_erased_directly_parent_statistics_keep_its_index_values`.

**C-24-2 MEDIUM: the printed remedy binds names through the runtime role's `search_path`, so
running it can re-point the view and weaken the policy.**
`VIEW_SQL` (`pg_get_viewdef`) and `POLICY_SQL` (`pg_get_expr`) run on the application's
connection with whatever `search_path` it has. With `currentSchema=app` (a common Spring datasource
setting), the definitions print unqualified names. The operator then runs the transaction "as the
table owner" in a session with a different path:
- view: printed `CREATE VIEW app.p24s_v AS SELECT id, email_idx FROM p24s`. With a `public.p24s` on
  the owner's path, the view is re-created over the other table and keeps its grants; without one,
  the whole remedy fails.
- policy: printed `USING ((p24_allowed(tenant) AND ...))`. With a `public.p24_allowed` on the
  owner's path, the re-created policy calls the other function and the reader's visible rows go
  from 10 to 300. That is the policy gap this transaction exists to close, reopened by its own
  text.
Fix, in `PlannerStatistics`: (a) read every definition with the path pinned. Run `VIEW_SQL` and
`POLICY_SQL` (and `DEPENDENTS_SQL`, for `pg_describe_object`) inside the
`JdbcSupport` one-statement window with `search_path = pg_catalog, pg_temp`, restoring the
connection's path afterwards as `SchemaVerification` already does, so every non-catalogue name comes
back qualified. (b) Make the printed transaction pin the same path:
`BEGIN; SET LOCAL search_path = pg_catalog, pg_temp; SET LOCAL lock_timeout = '5s'; ...`, and give
the no-dependents shape the same `SET search_path` line. Update §4e/§3b text, `docs/upgrading-0.2.0.md`
step 3a and the S1/S11 expected messages. Probes:
`probe_printed_remedy_recreates_the_view_over_another_table`,
`probe_printed_remedy_rebinds_the_policy_function`.

**C-24-3 LOW: a re-created view picks up default privileges the original never had.**
`CREATE VIEW` applies `pg_default_acl` for the creating role and schema. The remedy revokes only
from the owner, then re-grants the original ACL, so a default added after the view was created
(or a grant revoked from the view by hand) comes back. Repro: `ALTER DEFAULT PRIVILEGES IN SCHEMA
p24dp GRANT SELECT ON TABLES TO shred_snoop` after creating `p24dp.v`, then run the printed
remedy: `has_table_privilege('shred_snoop','p24dp.v','SELECT')` goes from `f` to `t`. The view
exposes the blind-index column and the table's rows.
Fix, in `PlannerStatistics.viewNotRecreatable`: when a `pg_default_acl` row with `defaclobjtype =
'r'` applies to the creating role (the view's owner, global or for the view's schema), name the view
with the reason "(default privileges would change its grants)" and leave it out of the generated
transaction. Do not try to compute and revoke the defaults. Probe:
`probe_recreated_view_gains_default_privileges_it_never_had`.

**C-24-4 LOW: an expression that calls a user function hides the column from the Var scan.**
Path 3 reads the expression tree's `Var` nodes, so `CREATE INDEX ... (app.p24_peek(id))` reads
only `id`, while `p24_peek` (a SQL function labelled `IMMUTABLE`) returns `email_idx`. After
`ANALYZE`, the index's own `pg_stats` row holds the blind-index values, and the verdict is
`Admitted`. This module cannot see into a function body, and unverifiable is not clean.
Fix, in `PlannerStatistics.referencedAttnums` and `facts`: also collect `:funcid` of `FUNCEXPR`
nodes and `:opfuncid` of `OPEXPR` nodes, using the same count-every-token rule as `VAR`. Resolve the
ids through `pg_proc.pronamespace`. Any expression index on a family member that calls a function
outside `pg_catalog` is refused with `SHRED-SCHEMA-005`, naming the index and the function, with the
remedy "drop the index, or replace the function by a pg_catalog expression". Apply the same rule to
expression-based extended statistics (`stxexprs`) and to a stored generated column's `adbin` on a
family member: both are statistics carriers reached through the same opacity. Probe:
`probe_expression_index_through_a_user_function_hides_the_column`.

### Attacks that did not produce a finding

| attack | result |
|---|---|
| runtime role reads `pg_stats` for each carrier | `may_read` and `rls_active` are checked per carrier, and a hidden carrier is `-005` (S5, S5b). The root's RLS is already refused by R-g. |
| default target `-1` (16), `NULL` (17, 18), explicit value, `0` | non-zero and NULL are refused, and the fact names the value; 18.6 behaves as 17 (`attstattarget` NULL) |
| target 0 with a stale row | refused until the row is gone (S2); `pg_stats` is read, not the target |
| extended statistics on a whole-row expression | PostgreSQL refuses to create it ("statistics creation on system columns is not supported", 16 and 18) |
| expressions using casts, jsonb paths, whole-row index | every such reference is a `Var` (whole-row is `varattno 0`, S4b) |
| generated columns | stored ones are carriers (S13, S13b). A virtual one (18.6) cannot take a target and stores nothing, and its dependency makes `TYPE` fail, which the message names (falls back to the alternatives). On 18.6, `pg_clear_attribute_stats` as owner clears both the column and the stored generated column (measured). |
| remedy with a view, a policy, a view chain and a stored generated column | S11, S11b and S12 execute the printed or documented text and pass. The failures are C-24-2 and C-24-3. `SET LOCAL lock_timeout` inside the transaction is honoured. |
| deviation 6 lock claim on the family | measured with the erasure's two locks held: `ALTER ... SET STATISTICS`, `CREATE STATISTICS`, `CREATE INDEX`, `CREATE INDEX CONCURRENTLY` and `ANALYZE` on the table all time out at 1s. The claim holds for the family and fails for ancestors (C-24-1). |
| test-only event trigger | not in any built jar, and not referenced from `src/main`. It can mask only statistics, never another refusal, and the four statistics test classes and the starter boot test run without it. |
| messages vs design §4e | wording matches, including the `-005` text; the partition fact reads "on partition X" as designed |

### Rulings on the eight deviations

1. Event-trigger fixture instead of `import_files`: **accepted**. `import_files` does not run on
   `update` or for SQL-built core fixtures. Scope is test resources only (verified above).
2. Sample untouched: **accepted**. `Customer` has no `@BlindIndex`.
3. `pg_index.indexprs` Var scan, with an unparsable tree going to `-005`: **accepted**, with C-24-4
   extending it to function calls.
4. RLS-hidden descendant is `-005`: **accepted**. `pg_stats` does hide it, and the root's case is
   R-g already.
5. Re-creatable vs named dependents, superuser template in docs only: **accepted**, with C-24-2 and
   C-24-3 applied to the re-creatable branch.
6. No post-`UPDATE` second check here: **accepted for the family** (measured). Not accepted as a
   general statement: the ancestor window is part of the C-24-1 design.
7. `-009` step-7 row left to PR 23: **accepted**.
8. `Column` gains `attribute`, 3-arg constructor kept: **accepted** (unreleased API).

### Routing

C-24-1 goes to the builder for a design page, reviewed before code. C-24-2, C-24-3 and C-24-4 are
corrections inside the mechanism this PR built, so the builder of this PR does them, in the same run
if possible. Pass 2 checks that the six probes flip green and attacks the ancestor design.

## Pass 2 (2026-10-05), head 33599c2

**Verdict: MERGE WITH FIXES.** No HIGH. C-24-2, C-24-3 and C-24-4 are closed: their probes are
green. C-24-1 (MEDIUM) stays open; its design (rev 4, option B) is APPROVED WITH CHANGES on the
design page and is built inside this PR. Four new LOW findings, each with a probe that fails on
33599c2: `internal/gdpr-shredding/probes/CipherProbePr24Pass2Test.java` (5 probes). The fixer adds
it to `gdpr-shredding-core/src/test/java/.../adapter/jdbc/` before touching production code. Pass 3
is a probe check only: the five probes here, the two C-24-1 probes enabled, and the A-tests.

| check | result |
|---|---|
| `CIPHER_PROBE_MAVEN=1 ./mvnw -B verify` (Docker up) | BUILD SUCCESS, 665 tests, 0 failures, 2 skipped (core 399 with the two `@Disabled` C-24-1 probes, starter 249, sample 17) |
| existing `CipherProbe*` tests, unchanged | all green |
| pass-1 probes `CipherProbePr24Test` | 4 green (C-24-2 x2, C-24-3, C-24-4), 2 skipped (C-24-1, design ruled below) |
| new probes `CipherProbePr24Pass2Test` | 5 run, 5 RED, each on its final assertion |

### Attacks on the fixes that held

- C-24-2: with the leg pinned, a view over a same-named table in another schema, a shadowed policy
  function and an extension operator all deparse schema-qualified; `pg_temp` is never searched for
  functions or operators, and a temporary relation is session-private. Every printed remedy opens
  with the pin (`SET LOCAL` inside the transaction branch).
- C-24-3: the default-privileges count is over-inclusive (any role's defaults for relations, global
  or in the view's schema). Over-inclusion only moves a view to the named branch. Accepted.
- C-24-4: user functions and operators are refused by namespace. The call nodes the scan does not
  parse (`ROWCOMPAREEXPR` operator lists, `MINMAXEXPR`, `COERCEVIAIO`) can only reach code a
  non-superuser cannot write: a row comparison needs a btree operator family and a type I/O needs a
  base type, and both are superuser-only (measured: "must be superuser to create an operator
  family", "... a base type"). A domain check does not change the stored value. Not findings.
- The named branch's `SET STATISTICS 0` statements: `SHARE UPDATE EXCLUSIVE`, no rewrite, does not
  block reads or writes, recurses to partitions and inheritance children. Safe, with C-24-7.

### Rulings on the builder's four fix-round deviations

1. The whole statistics leg runs in one pinned window (not the one-statement window of
   `JdbcSupport`): **accepted**, because every statement inside is module-written and fully
   qualified. The one-statement rule existed so that an exception cannot leave the path replaced;
   that is exactly C-24-5, so the acceptance carries C-24-5's fix.
2. Default privileges name the view instead of re-creating it: **accepted** (over-inclusive, safe).
3. `-005` for foreign calls in expression indexes, extended-statistics expressions and stored
   generated columns: **accepted**, with C-24-6 (index predicates) and C-24-8 (volatility).
4. The named branch prints runnable `SET STATISTICS 0`: **accepted**, with C-24-7.

### Findings

**C-24-5 LOW: a refusal inside the caller's transaction leaves `search_path` pinned.**
`PlannerStatistics.withPinnedPath` restores the arrived path only when the work succeeded. A
`ShreddingException` thrown by `refuseOpaqueExpressions` is a Java-side refusal: the transaction is
not aborted, so a caller of the public `MappingAdmission.verdict` that catches it keeps working on
`pg_catalog, pg_temp`, and its unqualified names fail or resolve to its own temporary relations.
The module's own paths roll back (erasure in `inTransaction`, startup on an auto-commit or
pool-rolled-back connection), so the reach is the public API.
Repro: `probe_refusal_inside_a_caller_transaction_leaves_search_path_pinned`.
Fix: in `withPinnedPath`, restore in `finally` on every exit when the connection arrived outside
auto-commit; a restore that fails because the work aborted the transaction (25P02) is added as
suppressed to the primary, as `JdbcSupport.inOneStatementWindow` does.

**C-24-6 LOW: a partial index predicate is read by neither scan.** ANALYZE samples an expression
index only from rows that satisfy its predicate. `CREATE INDEX ... ((lower(subject))) WHERE
email_idx = md5('1')` stores the subjects whose blind index had that value, and they stay in
`pg_stats` after the erasure; a predicate through a user function hides the column completely.
`INDEXES_SQL` reads `indexprs` only. Repro: `probe_partial_index_predicate_on_the_blind_index_is_not_read`,
`probe_partial_index_predicate_through_a_user_function_is_not_read` (both `Admitted`).
Fix: `INDEXES_SQL` returns `CAST(i.indpred AS pg_catalog.text)`; `PlannerStatistics.facts` treats
a blind-index attnum in the predicate like one in the expressions (the index is a carrier, remedy
"drop the index"), and `refuseOpaqueExpressions` scans the predicate tree with `calls` as well.

**C-24-7 LOW: the named remedy leaves a child's stored generated column sampling.** The named
branch prints `SET STATISTICS 0` for root carriers only. A legacy-inheritance child may add its own
stored generated column computed from the inherited blind-index column; the root's statement
recurses to the inherited column but not to a column the child alone has. After the printed
statements and the clearing step the verdict is still `Copied`, and the next start prints the same
remedy again. Repro: `probe_named_remedy_leaves_a_child_generated_column_sampling`.
Fix: in `PlannerStatistics.message`, named branch, print `ALTER TABLE <relation> ALTER COLUMN
<column> SET STATISTICS 0;` for every generated carrier whatever its relation, root carriers as
now, and list them in the "rows already stored" sentence.

**C-24-8 LOW: a `pg_catalog` function that runs SQL passes the call scan.** `CREATE STATISTICS`
does not require an immutable expression (measured on 16). `CREATE STATISTICS ... ON
(pg_catalog.query_to_xml('SELECT email_idx FROM app.q5 WHERE id = ' || id, ...)::text), id`
stores every blind-index value in `pg_stats_ext_exprs`, with the blind-index column at statistics
target 0; the Var scan sees `id`, the call scan sees a `pg_catalog` function. The same holds for
`table_to_xml`, `cursor_to_xml` and the `*_to_xml_and_xmlschema` family.
Repro: `probe_extended_statistics_through_a_catalogue_query_executor_is_admitted` (`Admitted`).
Fix: `FOREIGN_FUNCTIONS_SQL` also returns every function whose `provolatile` is not `'i'`, and
`FOREIGN_OPERATORS_SQL` every operator whose `oprcode` is not immutable; the `opaque` message says
"outside pg_catalog or not immutable" and "replace it by an immutable pg_catalog expression".

### Routing

All four are corrections inside the mechanism this PR built, so the builder of this PR applies
them, together with the C-24-1 build ruled on the design page (rev 4, approved with changes), in
this PR. Pass 3 runs the seven probes and the A-tests and attacks nothing new unless the build
departs from the ruled design.
