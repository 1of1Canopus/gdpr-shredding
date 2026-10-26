# Security review: fix/fk-action-owner-context (PR 53, owner-context control)

## Pass 1, 2026-10-26

Head reviewed: `308cc5f` ("chore(core): merge main into fk-action-owner-context").
Findings under re-verification: C-RC021-2c, -2e, -2f, -2g, -2h (MEDIUM). This pass is also the
review of the owner-context design page, Revision 2, judged together with the code.

Words used here. **Owner context**: code the server runs as a role other than the caller,
because of the caller's statement. **Reach**: every role the login is a member of.
**FK-action target**: a table whose foreign key has CASCADE, SET NULL or SET DEFAULT.

### Verdict: MERGE WITH FIXES

The five MEDIUM rows hold on the paths the page names. Their tests are green on both pins,
and four builder mutations re-run here are caught. The three deviations from the page are
stricter than the page, and they are accepted (rulings below).

This pass found five new rows. Four are MEDIUM and one is LOW. None is HIGH. None needs a
new mechanism: each one adds a source, a fact kind or a document line to a rule the PR
already has. Under the no-allowance rule, all five are fixed before merge.

### Numbers on this head

| What | Result |
| --- | --- |
| `CIPHER_PROBE_MAVEN=1 ./mvnw -B verify`, Docker up | green: core 1307, starter 319, sample 25; 0 failures, 0 errors, 0 skipped; JaCoCo gate passed. Matches the PR body |
| Earlier security probe classes on this head | all green inside the run above |
| Statement 4 timing, 500 FK tables (each with a default, a CHECK and an expression index) | 16.14: 354 to 408 ms; 17.11: 320 to 407 ms (three runs each, about 3,550 fact rows) |
| Mutation M5: O1 skips rules | caught: `fk_rule_action_over_withheld_function_refuses` red |
| Mutation M7: O1 skips typelem | caught: `fk_domain_in_array_over_withheld_function_refuses` red |
| Mutation M11: O2 ownership leg dropped | caught: `runtime_role_owning_a_table_written_by_owner_code_refuses` red |
| Mutation M14: O3 dropped | caught: `maintain_on_a_table_owned_outside_reach_refuses_on_17` red |
| New probes from this pass | 7 tests: 6 RED (C-PR53-1 to -5), 1 GREEN control |

### Rulings on the builder's deviations

- **(a) Facts from stored expression trees, not pg_depend (row C-RC021-2j).** Accepted. The
  measurement is right: a built-in function has no pg_depend row, so the page's source would
  have missed the page's own first example. One gap remains in the tree reader: C-PR53-5.
- **(b) Planner sources of every table on either side of a foreign key (row C-RC021-2i).**
  Accepted. The page's ruling 9 was wrong, and the builder measured it. One planner source is
  missing: C-PR53-2.
- **(c) O3 not relaxed by any mode; no module-object exception from O2; every constraint
  kind read.** Accepted. Each choice removes a weaker state. No compatibility is owed on an
  unreleased branch.

### What was checked and holds

- BEFORE trigger on an FK-action target, six actions (-2c): refused through O2 when its names
  can reach an object reach controls. Tests green on both pins.
- Expressions on an FK-action target (-2e, -2h): defaults, domain defaults, generated
  columns, CHECK, domain CHECK, index expressions and predicates, BEFORE and AFTER `WHEN`, rule
  actions, partition keys, a domain inside an array or a composite, exclusion operators.
  Each test is green on both pins.
- MAINTAIN on 17 (-2f): refused, also with allow-privileged-runtime-role on.
- Reach owning a table that owner code writes (-2g): refused. The test first shows the path,
  then the refusal.
- Partitioned FK-action targets: the key of the target and of each ancestor is read.
- Event triggers: they run as the role that runs the DDL, never as an owner. Definer
  event-trigger functions are entry point (i). Nothing new found.
- Implicit cast function inside an FK check: attempted, not a finding. The server refuses
  the foreign key when the two key types need a cast function (enum and text, measured on 16).
- JSON_OBJECT ... RETURNING a domain on 16: the stored tree carries a CoerceToDomain, and the
  domain is followed. Only the 17 node misses it (C-PR53-5).
- Call-site map: same files as the grep on both majors. One mapping is too broad: C-PR53-3.

### Findings

Every probe is in the internal file `CipherProbePr53Test.java`. The fix pass adds it to the
suite before touching production code. Each probe turns green when its fix is in.

**C-PR53-1 (MEDIUM). A TRIGGER grant on a table owned outside reach is not read.**
TRIGGER is a control over code the owner runs, just like ownership (C-RC021-2g). No leg
reads it. O2 reads ownership and CREATE. O3 reads MAINTAIN. Object grants are read on the
module's own tables only. Example, measured on 16 and 17: the owner grants `TRIGGER ON
public.ch` to the runtime role. `ch` is a CASCADE target. The gate starts. The runtime role
then adds a BEFORE DELETE trigger whose `WHEN` calls a revoked function. It deletes a parent
row, and the `WHEN` runs as the owner. With a withheld file-reading function in the `WHEN`,
the error message returned the file content to the runtime role.
Fix: `owner-context.sql` gets a `trg` kind, shaped like `mnt`: a TRIGGER grant on a relation
owned outside reach, to a role in reach or to PUBLIC. `OwnerContext.judge` refuses it as a
strict line, with no entry-point condition and no mode that relaxes it. Reason: a trigger
reach adds fires for every writer outside reach, the owner's own sessions included.
Tests: `trigger_grant_on_a_table_owned_outside_reach_refuses`,
`trigger_grant_to_public_refuses`, `trigger_grant_is_not_relaxed_by_allow_privileged_runtime_role`.
Probe: `probe_trigger_grant_on_fk_action_target_owned_outside_reach_is_not_refused`.

**C-PR53-2 (MEDIUM). Extended statistics expressions are a planner source, and statement 4
does not read them.** When the planner plans a query on a table, it reads the table's
statistics objects and folds their constant immutable calls. So a RESTRICT check, and a
cascade write, run them as the table's owner. Example, measured on 16 and 17: `CREATE
STATISTICS rcs ON (spy(1) + pid) FROM rc`, where `rc` is a RESTRICT child. The runtime role
deletes an unreferenced parent row, and `spy` runs as the owner. This is the same class as
C-RC021-2i.
Fix: statement 4 reads `pg_statistic_ext.stxexprs` for every table on either side of a
foreign key, as a new slot ("statistics expression"). That slot joins `PLANNER_SLOTS`, so it
is judged on `chk` tables and on targets.
Tests: `fk_statistics_expression_over_withheld_function_refuses`,
`fk_check_statistics_expression_over_withheld_function_refuses`.
Probes: `probe_statistics_expression_on_fk_check_table_over_withheld_function_is_not_judged`,
`probe_statistics_expression_on_fk_action_target_over_withheld_function_is_not_judged`.

**C-PR53-3 (MEDIUM). REINDEX through an owned partitioned table runs a partition's index
as the partition's owner.** O3 reads MAINTAIN grants only. The call-site map sends
`indexcmds.c` to O3, on the idea that the table owner is either in reach or covered by
MAINTAIN. That idea fails inside a partition tree. Example, measured on 16 and 17: the
runtime role owns the partitioned table `pp`. Its partition `pp1` is owned outside reach and
has an expression index over a revoked function. `REINDEX TABLE pp` rebuilds `pp1x` and
runs the function as `pp1`'s owner. VACUUM and ANALYZE skip the partition with "permission
denied"; REINDEX does not. There is no foreign key and no definer function, so O2 has no
entry point and passes.
Fix: O3 also refuses any partitioned table or partitioned index owned in reach that has a
descendant (through `pg_inherits`, any depth) owned outside reach. It is a strict line. In
the call-site map, the comment for `indexcmds.c` and `cluster.c` names this case.
Tests: `owned_partitioned_parent_over_partition_owned_outside_reach_refuses` (pins 16 and
17), with the REINDEX path shown first. A CLUSTER variant on 17 is in the same test.
Probe: `probe_reindex_through_owned_partitioned_parent_is_not_refused`.

**C-PR53-4 (LOW). The second-hop limit is not stated (QUESTIONS #C-61).** A rule action or a
trigger body on a target may write a second table. That table's defaults and triggers then
run as the owner, and O1 does not follow the write. Measured on 16 and 17: a rule on `c4`
inserts into `rlog`, and `rlog`'s default read a server file as the owner. Under O2, reach
cannot own or create `rlog`, so this code is the owner's own. A trigger body is already
the stated limit L19.
Ruling: a stated limit for 0.2.1, graded LOW. The fix is the statement itself. Following
rule writes to a fixpoint would be a new mechanism: if the founder wants it, it gets its own
design page and PR.
Fix: SECURITY-NOTES, section "Code that runs as another role", gets one paragraph with this
example and the finding id. It explains that O2 is what keeps reach out of the second table.
Probe: `probe_second_hop_write_limit_is_not_documented`.

**C-PR53-5 (MEDIUM, PostgreSQL 17 only). The tree reader misses a domain named only by
`JsonReturning.typid`.** On 17, `JSON_VALUE(... RETURNING d)` stores the domain only as
the `typid` of its JsonReturning node. There is no CoerceToDomain and no `resulttype`. The
server still checks the domain when it evaluates the expression. Measured on 17: a SET
DEFAULT target whose default is `(JSON_VALUE(jsonb '5', '$' RETURNING dj))::int`, where `dj`
has a CHECK over a revoked function. The CHECK ran as the owner when the runtime role
deleted a parent row. Statement 4 never follows `dj`.
Fix: the regex of statement 4 also reads `typid` as a type row, exactly as it reads
`resulttype`. Extra type rows only add domains to follow, so the reader stays strict.
Test: `fk_json_returning_domain_check_over_withheld_function_refuses_on_17`.
Probe: `probe_json_value_returning_domain_check_is_not_followed_on_17`.

### Questions #C-59 to #C-63

- **#C-59:** keep the stored trees, with the C-PR53-5 fix.
- **#C-60:** keep; add statistics expressions (C-PR53-2).
- **#C-61:** a LOW stated limit for 0.2.1, written into SECURITY-NOTES (C-PR53-4). It is not
  a blocker.
- **#C-62:** keep all three stricter choices.
- **#C-63:** keep. A superuser login can call any function directly, so O1 adds nothing for it.

### Cost of this pass

About 0.15M tokens. One full verify (plus one that failed only on this review's unformatted
probe file), three probe runs, four mutation runs, and two throwaway containers.
