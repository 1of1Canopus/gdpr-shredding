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
