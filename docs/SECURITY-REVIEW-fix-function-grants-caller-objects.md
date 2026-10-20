# Security review: fix/function-grants-caller-objects (C-PR45-3, design revision 5)

## Pass 1, 2026-10-20

Head reviewed: `5899b95` (code `d461403`), stacked on `fix/function-grants` (`99e2927`). The
branch builds design revision 5: statement 3 (caller objects), rule R6 (an object that makes
the server call a function for you), rule R7 (a pinned record of every core native function),
and a seventh manifest column (the support functions of each contrib aggregate).

Words used here:
- **gate**: the startup schema check.
- **reach**: the login role and every role it reaches.
- **W**: the withheld set (functions the server or a shipped extension ships without PUBLIC
  EXECUTE, plus the baseline).
- **caller object**: a catalogue row that names a function the server runs for you (an
  aggregate, an operator, a language).
- **slot**: one function column of a caller object (an aggregate's `sfunc`, a language's
  validator).
- **owner-checked slot**: the server checks EXECUTE as the object's owner (aggregate slots).
- **no-check slot**: the server checks nothing (language handler, inline handler, validator;
  operator estimators).

### Verdict: MERGE WITH FIXES

The two findings under verification hold for the paths the design page names.
C-PR45-3-15 (aggregates) and C-PR45-3-17 (core functions rewritten in place) are fixed for
every case I attacked with a withheld or hand-made native function. Three new findings remain.
None is HIGH. All must be fixed before merge (no allowance). This PR also cannot merge before
PR 46, which it is stacked on.

| Id | Severity | One line | Route |
| --- | --- | --- | --- |
| C-PR47-1 | LOW | R6 skips a caller object owned by a role in reach, also for no-check slots, where the owner's rights play no part | correction |
| C-PR47-2 | MEDIUM | A `SECURITY DEFINER` function in any language, that nobody in reach may execute, runs through an owner-checked slot; R6 never sees it, and limit L19 does not cover it | builder of R6 |
| C-PR47-3 | INFO | The count test behind "refused by signature" counts only the initdb part of W, and lists the combine shape as refused although R6 reads that slot | correction |

### Numbers (local, own worktree, Docker up)

| What | Result |
| --- | --- |
| `./mvnw -B clean verify` on `5899b95` | BUILD SUCCESS, 11 min 52 s |
| core / starter / sample tests | 968 / 319 / 25, 0 failures, 0 skipped |
| builder's mutations (19) re-run | 19 red, 0 survived |
| new probes (`CipherProbePr47Test`, both pins) | 10 red (5 probes x 2 pins), 12 confirms green |
| statement 3, clean database | 113 to 127 ms (16 and 17, three runs each) |
| statement 3, 47 extensions installed | 162 to 175 ms |

The probe class `CipherProbePr47Test` (package `com.housedevinci.shredding.adapter.jdbc`, core
tests) is handed to the fix pass, which adds it to the suite before it touches production code.
Methods named `probe_*` are red on `d461403` and must turn green. Methods named `confirms_*` are
green on `d461403` and must stay green.

The statement timings are from containers capped at one CPU and 512 MB, with JIT off as the
gate runs it. The cost is paid once at startup. No finding.

### Findings

#### C-PR47-1 (LOW): R6 skips a reach-owned object on a slot that has no check

`FunctionGrants.judgeCallers` skips every caller object whose owner is in reach. The reason
given is "its owner checks run as reach". That is true for aggregate slots. It is false for a
language's handler, inline handler and validator, and for an operator's `oprrest` and
`oprjoin`: the server runs those with no EXECUTE check at all (the PR's own measurement, and
`ownerOrNobody`'s comment).

Example, measured on 16 and 17. A superuser runs `CREATE TRUSTED LANGUAGE p47lang HANDLER
pg_catalog.plpgsql_call_handler VALIDATOR pg_catalog.pg_ls_tmpdir` and then `ALTER LANGUAGE
p47lang OWNER TO` the runtime role. The runtime role's direct call
`pg_ls_tmpdir(1)` is "permission denied". Its `CREATE FUNCTION ... LANGUAGE p47lang` runs
`pg_ls_tmpdir` anyway ("tablespace with OID ... does not exist"). The gate verifies. The same
holds for an operator owned by the runtime role whose `RESTRICT` estimator is a hand-made
internal copy that PUBLIC may not execute.

Impact is low today (a validator receives only the new function's oid). The property of
revision 5 is broken all the same, and the fix is small.

Probes: `probe_language_owned_by_the_runtime_role_with_a_withheld_validator_passes`,
`probe_operator_owned_by_the_runtime_role_with_a_hand_made_estimator_passes` (red on both pins).

Fix:
- `FunctionGrants`: split `ownerOrNobody(kind, slot)` into two predicates, `ownerChecked`
  (every aggregate slot) and `noCheck` (language handler, inline, validator; operator `oprrest`,
  `oprjoin`). In `judgeCallers`, apply `reach.contains(c.owner())` only when the slot is
  owner-checked. A no-check slot is judged whatever the owner.
- `SECURITY-NOTES.md`, "Objects that call a function for you": the sentence "An object owned by
  a role in reach is not judged here" applies to aggregates only.
- Tests (both pins): `language_owned_by_the_runtime_role_with_a_withheld_validator_refuses`,
  `operator_owned_by_the_runtime_role_with_a_hand_made_estimator_refuses`. The existing
  `aggregate_over_a_withheld_function_owned_by_the_runtime_role_is_skipped_by_r6` stays green.
- Mutation: apply the owner skip to every slot again; both new tests go red.

#### C-PR47-2 (MEDIUM): a revoked SECURITY DEFINER wrapper runs through an owner-checked slot

`judgeCallers` looks up each slot function in statement 2's facts. Statement 2 holds native
functions, extension members, core functions and the baseline. A SQL or PL/pgSQL function made
by hand is in none of these, so R6 skips the slot ("code reach could write"). That is right for
a function that runs with the caller's rights. It is wrong for a `SECURITY DEFINER` function:
its body runs as its owner, and through an owner-checked slot nobody checks whether reach may
execute it.

Limit L19 does not cover this. L19 accepts a wrapper that PUBLIC or reach may execute: the
operator chose to grant it. Here nobody in reach holds EXECUTE on the wrapper. The published
L19 audit query filters on PUBLIC or a role of the login, so it does not list this wrapper
either.

Example, measured on 16 and 17:

```sql
CREATE FUNCTION public.w(text, boolean) RETURNS text LANGUAGE sql SECURITY DEFINER
  AS 'SELECT pg_catalog.pg_read_file($1, 0, 200, $2)';
REVOKE EXECUTE ON FUNCTION public.w(text, boolean) FROM PUBLIC;
CREATE AGGREGATE public.agg_w(boolean) (sfunc = public.w, stype = text, initcond = 'PG_VERSION');
```

The runtime role's `SELECT public.w('PG_VERSION', true)` is "permission denied". Its
`SELECT public.agg_w(true)` returns `16` (or `17`). The gate verifies. Two more shapes of the
same hole, both measured:
- A core aggregate rewritten in place: `CREATE OR REPLACE AGGREGATE pg_catalog.bool_or(boolean)
  (sfunc = public.w, ..., finalfunc = public.leak)` keeps oid 2518 and the symbol
  `aggregate_dummy`, so R7 is silent. `SELECT bool_or(true)` raises `leak: 16`.
- A contrib aggregate re-created over a wrapper with the same key in another schema:
  `evil.citext_larger(citext, citext)`. The manifest's support column writes keys without a
  schema, so R5b sees `transfn=citext_larger(citext,citext)` as shipped.
  `SELECT public.max(x)` over `('a'), ('PG_VERSION')` returns the file.

Probes (red on both pins):
`probe_aggregate_over_a_revoked_security_definer_wrapper_passes_and_reads_a_file`,
`probe_core_aggregate_rewritten_over_a_revoked_wrapper_passes_and_leaks_a_file`,
`probe_contrib_aggregate_over_a_same_key_wrapper_in_another_schema_passes`.

Fix (inside R6, the mechanism this PR built, so it goes to its builder):
- Statement 3 carries two more facts per slot function: `prosecdef`, and whether PUBLIC or a
  role in reach holds EXECUTE on it (the same `aclexplode` form the statement already uses).
- R6 refuses a slot, on the objects it already judges (usable by reach or PUBLIC; owner
  outside reach for an owner-checked slot; any owner for a no-check slot, after C-PR47-1),
  when its function is `SECURITY DEFINER` in any language and neither PUBLIC nor a role in
  reach holds EXECUTE on it. A wrapper that reach may execute stays limit L19, as today.
- The same rule covers a no-check slot. Example: a trusted language whose validator is a
  revoked `SECURITY DEFINER` SQL function `(oid) RETURNS void`.
- The generator proves zero rows on every clean database of each pin, as it does for R5 to R7.
- `SECURITY-NOTES.md`: L19 says that a wrapper reach may not execute, named by a caller
  object, refuses (R6).
- Tests (both pins): `aggregate_over_a_revoked_security_definer_wrapper_refuses`,
  `core_aggregate_rewritten_over_a_revoked_wrapper_refuses`,
  `contrib_aggregate_over_a_same_key_wrapper_in_another_schema_refuses`,
  `trusted_language_with_a_revoked_security_definer_validator_refuses`, and
  `aggregate_over_a_public_security_definer_wrapper_is_the_stated_limit` (verifies).
- Mutation: drop the new condition; the four refusal tests go red.

Rejected alternative: list such wrappers in the L19 audit query. A query an operator may run is
not a control, and the secure mode is the default.

The schema-less support key is not a finding on its own. Measured: a same-key function that is
native and outside an extension is R3; inside an extension it is judged by R5; a plain SQL one
runs with the caller's rights. Only the `SECURITY DEFINER` case gains anything, and the fix
above closes it.

#### C-PR47-3 (INFO): the count test counts only the initdb part of W

`FunctionGrantsCases.withheld_built_ins_fit_no_refused_slot_shape_and_four_fit_the_validator`
is the guard for every path that statement 3 does not read ("refused by signature"). It
counts initdb functions only (`privtype = 'i'`). W also holds extension functions. With the
extension part counted, the test's own shape list gives one fit on both pins:
`dblink_connect_u(text, text) -> text`, in the combine shape `(s, s) -> s`. Combine is a slot
R6 reads, and R6 refuses it (`confirms_combine_over_dblink_connect_u_refuses`). So there is no
hole today. But a pin bump that adds an extension function with an `internal` argument would
not turn the guard red.

Repro (psql, both pins, 47 extensions installed): the test's query with
`privtype IN ('i', 'e')` returns 1 instead of 0. No Java probe: the defect is in a test, and a
probe could not flip green on the fix.

Fix:
- Rename to `withheld_functions_fit_no_unread_slot_shape`. W is `privtype IN ('i', 'e')`, in a
  database with every manifest extension of the pin created.
- Move the combine shape out of the refused list; assert its fits by name (today
  `dblink_connect_u(text, text)`), next to the four validator fits.
- Add the shapes the list misses: a `cstring[]` argument (type modifier input), `(T) -> int4`
  (hash support), `(T, int8) -> int8` (extended hash), `(oid) -> bool` (btree equal-image).
  Measured: zero fits for each on both pins.
- Required test: `count_test_sees_an_extension_withheld_function_with_an_internal_argument`.
  A test-only extension (like the existing `tp`) ships one function with an `internal`
  argument, revoked from PUBLIC in its script; the widened query must count it.
- `SECURITY-NOTES.md`: "no withheld built-in fits" becomes "no withheld function, built-in or
  shipped extension, fits".

### Attacks from the brief

| Attack | Outcome |
| --- | --- |
| R7 keyed by signature: core function renamed, then a new one made under the old name | Refused with 005, two lines: `pg_catalog.lower(text)` missing (the new one has an oid above 16384) and `pg_catalog.lower_x(text)` unknown. An oid cannot be reused below 16384 (`confirms_core_function_renamed_and_replaced_refuses_with_005`). |
| Aggregate whose support function is a reach-owned `SECURITY DEFINER` wrapper of `pg_read_file` | No hole: the wrapper runs as reach, and the call is "permission denied" at run time. Consistent with the skip. The wrapper owned outside reach is C-PR47-2. |
| Moving aggregate with only `minvfunc` withheld | Open in PostgreSQL (the inverse transition reads the file once a row leaves the frame); R6 refuses slot 7 (`confirms_moving_aggregate_with_only_minvfunc_withheld_refuses`). |
| Aggregate made by a role in reach over a function it cannot execute | Refused by the server at `CREATE AGGREGATE` ("permission denied for function pg_read_file"). |
| Contrib aggregate re-created over a new support function | R5b refuses through column 7 (the builder's test). With a same-key wrapper in another schema it passes: C-PR47-2. |
| Core aggregate rewritten in place over a withheld function | R7 is silent (symbol `aggregate_dummy`), R6 refuses (`confirms_core_aggregate_rewritten_over_a_withheld_sfunc_refuses`). Over a revoked wrapper: C-PR47-2. |
| Statement 3 cost | 113 to 175 ms at startup (table above). |
| Value of the count test | Real, but initdb-only: C-PR47-3. |

### Rulings on the builder's questions

- **#C-54 (R7 keyed by signature): accepted.** An oid of 10000 and above is given at initdb
  time, so it is not a stable key. A signature cannot change under `CREATE OR REPLACE`. A
  rename changes it, and R7 then reports the recorded one missing and the renamed one unknown
  (measured).
- **#C-55 (R7 mismatch is 005): accepted.** A rewritten core function means the record the
  other legs read is not the one this module verified. 005 is not relaxed by
  `allow-privileged-runtime-role`, which is right.
- **#C-56 (R6 judges the slots the server refuses by signature): accepted.** It costs nothing.
  One wording fix in the question text: by the server's source, aggregate combine, serialise
  and deserialise are owner-checked like the other aggregate slots, not "no check". The rule
  does not change. Not measured, so not a finding.
- **#C-57 (four validator fits): accepted.** Add the extension fit of C-PR47-3 to the same
  list.
- **#C-58 (two items for the PR 46 fix pass): accepted.** Item (b) is a name in the PR 46
  review file, written by the review. This PR inherits that red check until PR 46 is fixed.

### Mutations

The builder's 19 mutations re-run on this worktree; results below.

All 19 are red: M27 (leg 2 core rule), M28 (R6 dropped), M29 (aggregate owned outside reach
exempt), M30 to M37 (each of the eight aggregate columns dropped in turn), M38 (validator
dropped), M39 (untrusted language counted as usable), M40 (operator code judged as owner),
M41 to M43 (R7 dropped, its unrecorded direction dropped, blind to extension members), M44
(manifest column 7 ignored), M45 (aggregates judged as R3 code again). Production files were
restored after each one (`git status` clean). The script selects tests of the 16 pin only;
the 17 pin runs the same cases in the full build.

No mutation covers C-PR47-1 or C-PR47-2: the fixes above each name the mutation to add.

### Integration surface

The surface on the design page holds as measured (both pins), with two corrections: no-check
slots are judged whatever the owner (C-PR47-1), and a `SECURITY DEFINER` slot function in any
language is a path (C-PR47-2). No other catalogue path was found. Cast functions and operator
code are checked as the caller (measured by the build). I measured four more on both pins, as
a role with no grant: a column default, a CHECK constraint, a row security policy and a view
that call `pg_read_file` are each "permission denied for function pg_read_file". Index
expressions and generated columns need an immutable function, which no withheld function is.

Security review, pass 1.

## Pass 2 (2026-10-20)

Head reviewed: `13afe8f` (fix commits `6a74c92`, `3904cc7`, `13afe8f`; the function-grants head
`f10d151` merged in at `0669566`). Limited pass: verify the three fixes, then attack the surfaces
they added.

### Verdict: MERGE WITH FIXES

C-PR47-1 and C-PR47-3 are fixed. C-PR47-2 is fixed for the three shapes pass 1 measured. Its new
"reach may run it as itself" test is too wide, and that opens the same hole through a weaker role
grant (C-PR47-4, MEDIUM). Two smaller findings remain. None is HIGH. All must be fixed before
merge (no allowance). PR 46, which this PR is stacked on, must merge first.

| Id | Severity | One line | Route |
| --- | --- | --- | --- |
| C-PR47-4 | MEDIUM | `fn_reach` counts a role the login is a member of WITH INHERIT FALSE, SET FALSE; the login has none of that role's rights, yet R6 treats a wrapper granted to it, or owned by it, as one reach may run | builder of R6 |
| C-PR47-5 | LOW | The refusal label of a slot function hides a zero width character in its schema name: `public​.w` prints as `public.w` | correction |
| C-PR47-6 | INFO | SECURITY-NOTES says the second half of the L19 query lists every wrapper an operator calls; it reads the estimators only, not the operator's function | correction |

### Numbers (local, own worktree, Docker up)

| What | Result |
| --- | --- |
| `./mvnw -B clean verify` on `13afe8f` | BUILD SUCCESS, 12 min 54 s |
| core / starter / sample tests | 1010 / 319 / 25, 0 failures, 0 skipped |
| pass 1 probes (`CipherProbePr47Test`, both pins) | 22 / 22 green (10 former `probe_*` now green, 12 `confirms_*` still green) |
| M46 (owner skip on every slot again) | 8 red (rules, cases on 16, probes) |
| M47 (revoked-definer condition removed) | 11 red; also turns 4 of the new pass 2 `confirms_*` runs red |
| M48 (count test W back to initdb only) | 4 red |
| pass 2 probes (`CipherProbePr47Pass2Test`, both pins) | 6 red (3 probes x 2 pins), 8 `confirms_*` green |
| CI on PR 47 | none: `ci.yml` runs on pull requests to `main` only, and this PR targets `fix/function-grants`. `gh pr checks 47` reports no checks. The required checks run once the base is `main` |

Production files were restored after each mutation (`git status` clean but for the new probe
file). The probe class `CipherProbePr47Pass2Test` (package
`com.housedevinci.shredding.adapter.jdbc`, core tests) is handed to the fix pass, which adds it
to the suite before it touches production code. `probe_*` methods are red on `13afe8f` and must
turn green. `confirms_*` methods are green and must stay green.

### Verification of pass 1 findings

| Id | Outcome |
| --- | --- |
| C-PR47-1 | Fixed. Both probes green on 16 and 17. `ownerChecked` and `noCheck` split as prescribed; an operator's own function is neither. M46 red. |
| C-PR47-2 | Fixed for the three measured shapes (all three probes green, four `*_refuses` tests and the L19 limit test green). The new may-run test is C-PR47-4. |
| C-PR47-3 | Fixed. W reads `privtype IN ('i', 'e')` with every manifest extension created; the test-only extension `tpi` turns the count from 0 to 1; combine fit named; shapes added. M48 red. |

### Attacks from the brief

| Attack | Outcome |
| --- | --- |
| Reach-owned `SECURITY DEFINER` wrapper over a withheld function, behind an aggregate owned outside reach | Not refused, and need not be: no rule fires (`fn_reach` is true through the owner), and the call is "permission denied for function pg_read_file" at run time, because the body runs as reach (`confirms_reach_owned_wrapper_behind_a_foreign_aggregate_is_denied_at_run_time`). Consistent for an owner whose rights the login may use. Not consistent for an owner reached WITH INHERIT FALSE, SET FALSE: C-PR47-4. |
| Same name in two schemas | Judged apart. `public.w` granted to PUBLIC and `evil.w` revoked, same key `w(text,bool)`, one aggregate over each, both creation orders: the refusal names `public.agg_a` over `evil.w` only (`confirms_same_key_wrappers_in_two_schemas_are_judged_apart`). |
| L19 query against a renamed wrapper | Holds. The wrapper renamed to `w2` and moved to schema `evil` after the aggregate was made: the query lists `evil.w2(text,boolean) via called by aggregate agg_w(boolean)`, and R6 refuses naming `evil.w2(text, boolean)`; both follow the oid (`confirms_renamed_and_moved_wrapper_is_listed_by_l19_and_refused`). |
| Wrapper owned by a no-inherit, no-set member that holds EXECUTE on `pg_read_file` | Refused by the reach leg (that role is in reach and holds a withheld function): `confirms_wrapper_owned_by_a_no_inherit_no_set_member_refuses`. |
| CI state | No checks (table above). |

### Findings

#### C-PR47-4 (MEDIUM): "reach may run it" counts a role whose rights the login cannot use

Statement 3 sets `fn_reach` when the slot function's owner, or a grantee of EXECUTE on it, is in
reach. Reach is every role the login is a `MEMBER` of (`SchemaVerification`, `pg_has_role(..,
'MEMBER')`). Since PostgreSQL 16 that includes a grant `WITH INHERIT FALSE, SET FALSE`, which gives
the login none of the role's rights and no `SET ROLE` to it. Reach is the right set for the legs
that refuse (more roles, more refusals). It is the wrong set for `fn_reach`, which exempts: L19
holds only when the object gives nothing a direct call does not.

Example 1, grant side, measured on 16 and 17:

```sql
CREATE ROLE g NOLOGIN;
GRANT g TO app WITH INHERIT FALSE, SET FALSE;
CREATE FUNCTION public.w(text, boolean) RETURNS text LANGUAGE sql SECURITY DEFINER
  AS 'SELECT pg_catalog.pg_read_file($1, 0, 200, $2)';
REVOKE EXECUTE ON FUNCTION public.w(text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.w(text, boolean) TO g;
CREATE AGGREGATE public.agg_w(boolean) (sfunc = public.w, stype = text, initcond = 'PG_VERSION');
```

The runtime role's `SELECT public.w('PG_VERSION', true)` is "permission denied for function w".
Its `SELECT public.agg_w(true)` returns `16` (or `17`). The gate verifies.

Example 2, owner side, measured on 16 and 17: the same `g` and `public.w` (granted to `g` only),
plus `public.w1(text, boolean)` `SECURITY DEFINER` with body `SELECT public.w($1, $2)`, revoked
from PUBLIC and owned by `g`, as the `sfunc` of `public.agg_w1`. Both direct calls are denied. The
aggregate runs `w1` as `g`, `w1` calls `w` as `g` (granted), `w` reads the file as the superuser.
The gate verifies: `fn_reach` is true through the owner.

Probes (red on both pins):
`probe_wrapper_granted_only_to_a_no_inherit_no_set_member_passes_and_reads_a_file`,
`probe_wrapper_owned_by_a_no_inherit_no_set_member_chains_to_a_file_read`.

Fix (inside the may-run test of R6, which the builder of R6 wrote; a correction of one condition,
not a new mechanism):
- `function-grants-3.sql`, the `fn_reach` expression of all three branches: the owner and each
  non-PUBLIC grantee count only when the login may use that role's rights:
  `pg_catalog.pg_has_role(<login oid>, x, 'USAGE') OR pg_catalog.pg_has_role(<login oid>, x,
  'SET')`. PUBLIC stays as today. Bind the login oid (`FunctionGrantsSql.callers`; update
  `STATEMENT_THREE_BINDS` and the bind comment). The usable flags and every refusing leg keep
  reach as it is.
- `FunctionGrantsSql.CallerFact` javadoc and `SECURITY-NOTES.md` (L19 and "Objects that call a
  function for you"): "a role in reach" becomes "a role whose rights the login may use (inherited,
  or reachable by `SET ROLE`)".
- The generator proves zero rows on every clean database of each pin, as for R5 to R7.
- Tests (both pins): `aggregate_over_a_wrapper_granted_to_a_no_inherit_no_set_member_refuses`,
  `aggregate_over_a_wrapper_owned_by_a_no_inherit_no_set_member_refuses`, and
  `aggregate_over_a_wrapper_granted_to_an_inherited_group_is_the_stated_limit` (verifies: the
  login may call it directly). The two probes above turn green.
- Mutation: go back to reach membership for `fn_reach`; the two refusal tests go red.

Rejected alternative: refuse every grant `WITH INHERIT FALSE, SET FALSE` in reach. It is a valid
way to give a role nothing; the defect is only that the exemption reads it as something.

#### C-PR47-5 (LOW): a zero width character in a schema name hides in the refusal

The fix gives each slot function a schema-qualified label, so the operator can tell `evil.w` from
`public.w`. The label is built with `concat(nspname, '.', proname, ...)`, unquoted, and the message
escape (`LogText.escape`) escapes C0 and C1 controls and U+2028/U+2029 only. A schema made with
`CREATE SCHEMA U&"public\200B"` (public followed by U+200B, zero width space) gives a refusal that
reads, on screen and in a log viewer, `whose transfn is function public.w(text, boolean)`. The
gate still refuses; the operator is pointed at the wrong object. The object labels of statement 3
are built the same way.

Probe (red on both pins): `probe_refusal_label_hides_a_zero_width_character_in_the_schema_name`.

Fix:
- `LogText.escape`: also escape every character whose `Character.getType` is `FORMAT` (U+200B to
  U+200F, U+202A to U+202E, U+2060 to U+2064, U+FEFF and the rest of Cf) and every lone surrogate,
  as `\uXXXX`.
- `function-grants-3.sql`: build `fn_label` and the object labels with `pg_catalog.quote_ident` on
  the schema and the name, so a name that is not plain lowercase shows in quotes, as
  `regprocedure` prints it.
- Tests: `LogText` unit test `escapes_format_characters` (U+200B, U+202E, U+FEFF); the probe turns
  green.
- Mutation: drop the `FORMAT` branch; the probe and the unit test go red.

#### C-PR47-6 (INFO): the L19 note over-states the second half of the audit query

SECURITY-NOTES says the second half "lists every wrapper an aggregate, operator or language calls,
granted or not". Its operator branch reads `oprrest` and `oprjoin` only. An operator over a revoked
wrapper (`CREATE OPERATOR public.### (LEFTARG = text, RIGHTARG = boolean, FUNCTION = public.w)`)
is not listed (`confirms_l19_second_half_omits_an_operator_function`, green). The omission opens
nothing: an operator's function is checked as the caller, so a granted wrapper is in the first
half and a revoked one is denied. Only the sentence is wrong.

Fix: `SECURITY-NOTES.md`: "every wrapper in a slot R6 reads (the eight aggregate slots, an
operator's estimators, a language's handler, inline handler and validator)". No code change; the
confirm test stays green.

### Integration surface

Unchanged from pass 1, with one addition: the may-run test is now a path of its own, and it must
use the rights the login holds, not the roles it is a member of (C-PR47-4).

Security review, pass 2.

## Pass 3 (2026-10-20)

Limited pass on head 43dfc2c, findings C-PR47-4, C-PR47-5 and C-PR47-6 only.

**Verdict: MERGE.** The three findings are closed. No new finding.

### Numbers

| Check | Result |
|---|---|
| `./mvnw -B clean verify` (Docker up) | core 1051, starter 319, sample 25; 0 failures, 0 skipped; coverage gates met |
| Pass 2 probes (`CipherProbePr47Pass2Test`) | 14 of 14 green, pins 16 and 17 |
| Pass 3 attacks (`CipherProbePr47Pass3Test`, new) | 12 of 12 green, pins 16 and 17 |
| `LogTextTest` | 5 of 5 green |

Core counts 1051: the builder's 1039 plus the 12 pass 3 runs.

### Mutations, re-run by the review

| Mutation | Red |
|---|---|
| M49: `fn_reach` back to `pg_has_role(..., 'MEMBER')` | both pass 2 probes, plus pass 3 ADMIN-only and two-hop cases, on both pins |
| M49b (review's own): `SET` half removed, `USAGE` only | pass 3 `INHERIT FALSE, SET TRUE` case, both pins |
| M50: format and surrogate branch removed from `LogText.escape` | pass 2 zero-width probe (both pins), 3 `LogTextTest` units |
| M51: `quote_ident` removed from the labels | pass 3 quote and 63-byte cases, both pins |

Each mutation was restored with `git checkout`; the tree was clean before the full build.

### C-PR47-4 (MEDIUM): closed

`fn_reach` now counts an owner or a grantee in reach only when the login holds `USAGE` or `SET`
on it. PUBLIC is a separate `CASE` branch, so oid 0 never reaches `pg_has_role`. The login oid is
bound once per branch (binds 4, 7, 11). Attacks, each with the grant on the EXECUTE side and on
the owner side:

- `WITH INHERIT TRUE, SET FALSE`: the login calls `w` directly. Leg 7 does not name the
  aggregate (limit L19). Correct.
- `WITH INHERIT FALSE, SET TRUE`: the direct call is denied, `SET ROLE g` then the call works.
  Leg 7 does not name the aggregate. Correct.
- `WITH ADMIN TRUE, INHERIT FALSE, SET FALSE`: direct call denied, `SET ROLE` denied, the
  aggregate reads `PG_VERSION`. The gate refuses and names the aggregate and `public.w`. Correct.
- Two hops (login `SET` to `a`, `a` inherits `b`, only `b` holds EXECUTE): refused. This is
  stricter than needed (the login could `SET ROLE a` and call `w`). It fails closed, so it is
  not a finding.

### C-PR47-5 (LOW): closed

Labels are built with `quote_ident`. A schema `"ev""il"` prints as `"ev""il".w(text, boolean)`,
the same form `regprocedure` uses. A 63-byte schema name (capital plus two-byte characters) and a
63-byte function name print whole: the label is `text`, so quoting adds two bytes and truncates
nothing. `LogText.escape` escapes Cf characters and lone surrogates per UTF-16 unit; the pass 2
zero-width probe is green.

### C-PR47-6 (INFO): closed

SECURITY-NOTES L19 now lists the slots the audit query reads and says an operator's own function
is not listed because the server checks it as the caller. The text matches the query.
