# Security review: fix/function-grants-no-check-slots (PR 51, C-RC021-2)

## Pass 1, 2026-10-26

Head reviewed: `b868da2` ("test(core): pin the leg 4 closure in unit tests and time statement 3").
Findings under re-verification: C-RC021-2, -2a, -2b, -2d (MEDIUM), fixed by the trigger-slots
design page, Rev 2, approved with edits. Rows -2c and -2e to -2h belong to the owner-context
page and are not judged here.

### Verdict: MERGE WITH FIXES

The four MEDIUM rows are closed: their tests are green on both pins, and four mutations re-run
by this review are caught. The leg 4 closure opened one gap. A user range type now refuses
startup and nothing the operator can do lets it start (C-PR51-1, LOW). One claim in the PR body
is wrong (C-PR51-2, INFO). Neither needs a new mechanism. Under the no-allowance rule both are
fixed before merge.

### Numbers on this head

| What | Result |
| --- | --- |
| `CIPHER_PROBE_MAVEN=1 ./mvnw -B verify`, Docker up | green: core 1186, starter 319, sample 25; 0 failures, 0 errors, 0 skipped; JaCoCo gate passed. Matches the PR body |
| Earlier security probe classes on this head | all green inside the run above, `CipherProbeRc021TriggerTest` included (red on `d6f88a6`) |
| Mutation M9 (PR table): leg 4 keyed on ACL again | caught: 5 of 5 targeted tests red |
| Mutation M10 (PR table): leg 7 applied to `trg` | caught: `revoked_and_public_sql_definer_trigger_get_the_same_verdict` red |
| Mutation M11 (PR table): the filter also drops extension members | caught: `statement_3_filter_drops_only_rows_the_verdict_passes` red |
| Mutation M12 (this review): `sup` removed from the no-check kinds | caught: `other_no_check_slot_hand_made_refuses[planner support]` red |
| New probes from this pass | 6 tests: 2 RED (C-PR51-1), 3 GREEN controls, 1 time record |

### What was checked and holds

- **Every catalogue column that names a function is accounted for.** `pg_get_catalog_foreign_keys()`
  on the 16 pin lists 43 columns that point at `pg_proc`. Statement 3 reads 41 of them. The
  other two are the aggregate's own `aggfnoid` and `pg_cast.castfunc`. Measured: a cast's
  function is checked as the caller (`permission denied for function spy` through an explicit
  cast and an assignment cast on `INSERT`). SECURITY-NOTES already says so.
- **The type branch has eight columns, not nine.** The design page says "9 columns with
  `typanalyze`". `pg_type` has eight function columns on 16 and 17, and the branch reads all
  eight. Wording only; the code is right.
- **Extension door of the closure.** Leg 4 skips extension members. A hand-made native trigger
  function added to `plpgsql` with `ALTER EXTENSION ... ADD FUNCTION`, revoked and attached,
  refuses through R5 on the slot line. Red on main, green here.
- **A native re-creation of a contrib trigger function** (`moddatetime` rewritten in place over
  `suppress_redundant_updates_trigger`, revoked, attached) refuses through R5b on the slot line.
- **Renaming the native languages does not hide hand-made code.** Statements 2 and 3 decide
  "native" by language name. A superuser may run `ALTER LANGUAGE internal RENAME TO builtin`.
  R7 then reports every core function as rewritten and the gate cannot verify the server.
  Reclassified: not a finding.
- **Statement 3 cost: a documented cost, not a finding.** JIT is off inside the gate's window
  (with JIT on, the same statement takes 2.8 s on the 16 pin). Measured on the 16 pin, JIT off,
  through `psql`: 6,338 rows in 266 ms on a pristine database; 76,348 rows in 512 ms with 5,000
  tables, each with one foreign key. The whole gate on 5,000 tables with foreign keys took
  910 to 992 ms through the module. The row count grows with the number of relations: each
  table adds two types and each foreign key adds four core triggers. Every kept row is one the
  verdict reads, as the filter ruling requires. Under one second at startup on a large schema is
  acceptable. No threshold.

### Findings

#### C-PR51-1 (LOW): a user range type refuses startup, with no remedy

`CREATE TYPE public.floatrange AS RANGE (subtype = float8)` makes five functions:
`floatrange(float8, float8)`, `floatrange(float8, float8, text)` and three
`floatmultirange(...)` constructors. The server makes them, not the operator. They are
`LANGUAGE internal`, oid 16384 or above, in no extension, over the symbols `range_constructor2`,
`range_constructor3` and `multirange_constructor0/1/2`. Each has an internal (`i`) dependency on
its range or multirange type. The leg 4 closure counts them as native code made by hand.

On main, `REVOKE EXECUTE ... FROM PUBLIC` on the constructors let the schema start. On this head,
leg 4 ignores grants, so the same schema refuses with five `SHRED-SCHEMA-004` lines. The remedy
line says "Drop it, or install it as an extension". A constructor cannot be dropped apart from
its type. So any schema with a user range type can no longer use the library. Booking and
scheduling schemas use them. The constructors only build a range value. They reach nothing a
revoke would protect.

- Repro: `CipherProbePr51Test.probe_user_range_type_with_revoked_constructors_refuses_with_no_remedy`
  (green on main `6c02eaa`, red here) and `probe_user_range_type_with_default_grants_refuses`
  (red on main and here).
- Fix (`FunctionGrants`, statement 2): statement 2 gets one more fact column, `server_made`. It
  is true when all of these hold: the language is `internal`; `prosrc` is one of the five
  constructor symbols; and a `pg_depend` row exists with `classid = pg_proc`,
  `refclassid = pg_type`, `deptype = 'i'`, and the referenced type has `typtype` `r` or `m`.
  `ExecuteFact` carries it. `judgeHandMade` skips a fact with `server_made`. Leg 4 in `verdict`
  also skips it, so no slot or grantee line refuses it through leg 4. Every other leg still
  applies.
- Tests, on both pins: `user_range_type_constructors_verify` (default grants and revoked);
  `hand_made_function_over_range_constructor_symbol_refuses_leg_4`. The second one creates
  `public.x(float8, float8) RETURNS public.floatrange LANGUAGE internal AS 'range_constructor2'`.
  It has no `i` dependency, so it still refuses. Mutation: drop the `deptype = 'i'` condition.
  The second test must go red. Show it in the PR body.
- Docs: one sentence in SECURITY-NOTES "No-check slots": the constructors the server makes for a
  range type are not native code made by hand.

#### C-PR51-2 (INFO): the PR body gives a wrong reason for dropping an approved test

The design page lists `re_created_moddatetime_trigger_refuses_r5` in its section 5. The PR drops
it: "leg 4 already refuses it". Leg 4 skips extension members, so leg 4 never sees a re-created
contrib function. R5b on the slot line refuses it. Measured by
`control_re_created_moddatetime_native_trigger_is_named_by_its_slot`, green. So the behaviour
holds, but no suite test pins it. Related: the statement 3 comment says each keep clause keeps
"only when the verdict can refuse the function". The extension-member clause also keeps
non-native invoker members, and the verdict always passes those. Removing that clause changes
no test (this review ran it). The design ruling's example, "a re-created SQL contrib function",
is wrong for the same reason: a non-native invoker runs as the caller and is not judged.

- Fix: add `re_created_moddatetime_trigger_refuses_r5` to `FunctionGrantsCases` on both pins,
  with the body of the control above. Fix the PR body line. Fix the statement 3 comment: the
  extension clause keeps a superset, and that is safe.

### Probe file

`CipherProbePr51Test`, six tests, kept with the internal review material. The fix pass adds it
to the suite before changing production code. The two `probe_` tests are expected to turn
green. The controls stay green.

## Pass 2, 2026-10-26

Head reviewed: `750980e` ("fix(core): let server-made range constructors pass the leg 4 closure").
Limited scope: re-verify C-PR51-1 and C-PR51-2, re-run two mutations, reproduce the build numbers.

### Verdict: MERGE

Both pass 1 findings are closed by their probes and by measurement. Three new variants of the
server-made rule hold on both pins. Two mutations are caught. No new finding.

### Numbers on this head

| What | Result |
| --- | --- |
| `CIPHER_PROBE_MAVEN=1 ./mvnw -B verify`, Docker up | green: core 1214, starter 319, sample 25; 0 failures, 0 errors, 0 skipped; JaCoCo gate passed. Core 1214 = the PR's 1209 plus the 5 tests of this pass's probe file, run in place and then removed from the tree |
| Pass 1 probes (`CipherProbePr51Test`, unchanged) | 6 of 6 green. Both `probe_user_range_type_*` tests flipped from red to green |
| Pass 2 probes (`CipherProbePr51Pass2Test`, 4 probes, 1 measurement) | 4 of 4 green on both pins |
| Mutation M-A: `range_owned` without the `deptype = 'i'` condition | caught: 3 red (`hand_made_function_over_range_constructor_symbol_refuses_leg_4` on 16 and 17, `probe_user_multirange_constructor_replaced_in_place_refuses_leg_4`) |
| Mutation M-B: a server-made constructor skips every leg, leg 3 included | caught: 2 red (`a_server_made_range_constructor_made_security_definer_is_still_leg_3`, `probe_user_range_type_definer_constructor_refuses_leg_3`) |
| Extension clause restored (C-PR51-2 measurement) | 425 of 425 function-grants and probe tests green, same as the head; gate outcome identical on both pins |

### C-PR51-1: verified

- `probe_user_range_type_starts_default_and_revoked_on_both_pins`: `CREATE TYPE ... AS RANGE`
  starts with default grants and with every function revoked from PUBLIC, on 16 and 17.
- New variant, range over a domain with a named multirange
  (`subtype = public.d8, multirange_type_name = public.dmulti`): starts on both pins. The
  constructors carry extra normal dependencies on the domain and the array type. The internal
  dependency on the range or multirange type is still there.
- New variant, a constructor made SECURITY DEFINER with `ALTER FUNCTION`. `ALTER FUNCTION` does
  not touch `pg_depend`, so `serverMade` stays true. Leg 3 still refuses it on both pins, with
  "native code that runs with the rights of its owner".
- New variant, `CREATE OR REPLACE` of a multirange constructor over its own symbol
  (`multirange_constructor0`). Measured on both pins: the server deletes the internal dependency
  on replace and keeps the normal ones. The function is then no longer server-made, and leg 4
  names it, and only it, on both pins. A user cannot add an internal dependency through SQL.
  Only a superuser writing `pg_depend` directly can, and that is outside the threat model.

### C-PR51-2: verified

- `re_created_moddatetime_trigger_refuses_r5` is in `FunctionGrantsCases` and green on both pins.
  The statement 3 comment now gives the right reason.
- The extension-member clause was removed, not documented. Measured whether that changes
  anything. Method: the no-check branch of statement 3, run through `psql`, with the clause and
  without it. Two databases on each pin: a pristine one, and one with 37 contrib extensions, five
  contrib triggers (`moddatetime`, `insert_username`, `autoinc`, `lo_manage`,
  `triggered_change_notification`), a range type, a foreign key, and two planted non-native
  invoker members on trigger slots (`insert_username` re-created in plpgsql, and a plpgsql
  function added to `plpgsql`).

| Pin, database | Rows with clause | Rows without | Rows new without old |
| --- | --- | --- | --- |
| 16, pristine | 3,974 | 3,974 | 0 |
| 16, contrib | 4,822 | 4,820 | 0 |
| 17, pristine | 3,997 | 3,997 | 0 |
| 17, contrib | 4,847 | 4,845 | 0 |

- The two rows dropped on each pin are the two planted members: plpgsql, invoker, normal oid,
  no `pg_init_privs` entry. Their verdict is empty on both versions of the filter. Leg 1 needs a
  baseline oid or an init-privs entry. Legs 2 to 6 need native code. Leg 7 needs a definer. Every
  shipped contrib member keeps its row through another clause.
- Leg verdicts: with the clause restored, the 425 function-grants and probe tests give the same
  results as the head, refusals included. On the contrib fixture the gate starts with and
  without the clause, on both pins
  (`measure_gate_outcome_with_contrib_extensions_and_member_triggers`, same SHA-256).
- Conclusion: the builder's reason holds. The clause kept only rows that always pass.

### Probe file

`CipherProbePr51Pass2Test`, kept with the internal review material. No finding, so nothing for
the fix pass to add. The suite may take it as is: it pins leg 3 for a definer constructor on
both pins, and only a unit test pins that today.
