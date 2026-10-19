# Security review: fix/login-role-privilege (C-PR-1c)

## Pass 1, 2026-10-18

Head reviewed: `285fd1c` ("chore(core): merge main into fix/login-role-privilege"). The test
runs used `285fd1c` with `main` `f2e15b4` merged in locally (not pushed), so the deterministic
starter test of PR 43 was in the suite.
Finding under verification: C-PR-1c (MEDIUM, role verification). The gate judged `current_user`
only. A pool could log in as the owner or a superuser, move in its init SQL, and pass as
unprivileged.

Words used here:
- **gate**: the startup schema check.
- **login role**: the role the connection authenticated as.
- **reach**: the login role and every role it is a member of.
- **marker**: the random per-verification value the per-call check leaves in a session setting
  (`shredding.login_checked`) so it reads the login only once per server backend.

### Verdict: MERGE WITH FIXES

C-PR-1c is fixed. Both original probes are green. The 21 mutations of the design page are all
caught. The cost table holds at the one load point I measured again. The deviations are sound.

This pass found four new problems. Under the no-allowance rule each is fixed before merge,
with one routing question for the coordinator (C-PR45-3, below).

| Id | Severity | One line |
| --- | --- | --- |
| C-PR45-1 | MEDIUM | The owner of the verified schema passes when it has revoked CREATE from itself, and can DROP the erasure log |
| C-PR45-2 | LOW | A column-level REFERENCES grant to the runtime role itself passes the allow list, and a foreign key then blocks key destruction |
| C-PR45-3 | MEDIUM | EXECUTE on a server-file function (for example `lo_export`) passes, while the role that carries the same right is refused. DESIGN STOP |
| C-PR45-4 | LOW | The required probe check (job `cipher-probes`) is red on this head: two release probes plant the old six-argument constructor |

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -B clean verify`, Docker up | green: core 706, starter 315, sample 25; 0 failures, 0 errors, 0 skipped; JaCoCo gate met |
| Original design-review probes (`internal/.../CipherProbeCPr1DesignReviewTest.java`, unchanged, run under a renamed class) | 4 of 4 green, both C-PR-1c probes included |
| In-tree `CipherProbe*` classes | all green inside the verify above |
| The 21 builder mutations, re-run with the builder's script | 21 of 21 caught; RED counts 10, 2, 4, 1, 1, 4, 5, 9, 1, 1, 4, 9, 1, 1, 4, 7, 2, 4, 2, 2, 1, the same as the PR body |
| `cipher-probe-c-pr-1c-design.sh` | the three attacks still work against the round-1 query (expected: the script tests the proposed SQL, not the code). The code's legs for the same three cases are green tests: `reachable_server_file_or_program_role_refuses`, `reachable_role_with_alter_system_on_a_parameter_refuses`, `LoginRoleReachPg17Test` |
| `cipher-probe-c-pr-1c-design-r2.sh` (A1 to A11) | same results as at design time; hot 0.013 / 0.021 / 0.031 ms, cold on a running backend 0.85 / 0.99 / 1.08 ms at 156 backends, 32 kB |
| Load point re-measured: pin 16, 406 live backends, 32 kB text, the module's fingerprint statement verbatim, server time, 100 calls | hot 0.047 / 0.084 / 0.158 ms; cold on a running backend 1.71 / 2.42 / 4.88 ms; hot plan shows `pg_stat_get_activity (never executed)`. Matches the PR table |
| `tools/cipher-probe-c-pr38-p2-changelog-codespans.sh` | GREEN |
| `tools/cipher-probe-release-pipeline.sh` | 90 fixed, 3 weak (the same three as on `main`) |
| `tools/cipher-probe-c-pr-1-split-package.sh`, `-starter-scope.sh` | both UNVERIFIABLE: the planted class does not compile. CI probe check (job `cipher-probes`) is red on 285fd1c (C-PR45-4) |
| New probes from this pass | 5 tests in `internal/gdpr-shredding/probes/CipherProbePr45Test.java`: 3 RED (C-PR45-1, -2, -3), 2 confirmations green |

### Checks the brief asked for

| Check | Result |
| --- | --- |
| Set the marker as the runtime role to a guessed value | settable (`SET`, startup options); a wrong value is read as cold and the login is read. Tests `wrong_marker_in_init_sql_is_read_as_cold`, mutations 15 and 19 |
| `RESET ALL`, `DISCARD ALL`, `RESET name` | all clear it to `''`; read as cold. Tests `discard_all_makes_the_next_call_cold`, `empty_marker_after_reset_is_read_as_cold`, mutation 20 |
| `SET LOCAL` scope | the module uses `set_config(.., false)`; a transaction-local marker is caught by mutation 18 |
| Stale marker from another module instance on a reused backend | each `VerifiedSchema` draws 16 bytes from `SecureRandom`; another instance's marker never matches, so the call is cold. Mutation 17. The alternating cost is stated (C-PR1c-5) |
| Log leakage via `log_statement` | the marker is a bind value in the server log when statement logging is on (A8). Stated in SECURITY-NOTES; helps only a superuser login. Module messages and `toString` never hold it (test P9) |
| ADMIN, SET, INHERIT false grants | `'MEMBER'` counts them all. ADMIN-only: existing test, mutation 9. SET FALSE and INHERIT FALSE to a group that holds the owner: refused, confirmation `confirm_owner_reached_only_through_a_set_false_inherit_false_grant_refuses` |
| Recursive membership depth | `pg_has_role(.., 'MEMBER')` follows the whole chain; the SET FALSE confirmation above is two levels deep |
| Built-in roles, 16 vs 17 | every `pg_` role outside the five accepted ones is refused by name prefix, so 17's `pg_maintain` is refused with no version switch (`LoginRoleReachPg17Test`) |
| CREATEROLE on 15 | the leg refuses `rolcreaterole` on every version; there is no version branch to get wrong |
| "Owner's own grants left out" | holds for tables, sequence and database: each has an ownership leg with the same `'MEMBER'` reach, so a reachable owner is refused before its entries matter. It does not hold for the schema: C-PR45-1 |
| One-message superuser path | still refuses with 004 ("login role X is a superuser"); tested with three init SQL forms |
| L17 rename refused | accepted as a deviation. It fails closed with 012 and says to restart. A rename of a login role during maintenance is rare, PostgreSQL clears an MD5 password on rename anyway, and SECURITY-NOTES says so. Not a finding |
| `pg_read_all_data` reads another login's password | yes, measured by the builder (`pg_authid.rolpassword`), test green; refusing it is right (row C-PR1c-8). My owed check is closed |
| Error mapping to 005, 57P01 included | every `SQLException` in verification is 005 (`verify` catch and the login and reach reads); confirmation `confirm_terminated_backend_during_verification_is_005`. Per call, every `SQLException` in `DatabaseIdentity.require` is 012 |
| Constant-time compare | `sameMarker` uses `MessageDigest.isEqual` on UTF-8 bytes; read, holds |

### C-PR45-1 (MEDIUM): the schema owner slips through when it revoked CREATE from itself

**What goes wrong.** PostgreSQL lets the owner of a schema drop any object in it, whoever owns
the object. That right comes from ownership, not from the schema's grant list. The gate has no
ownership leg for the schema. It only reads the schema's grant list, where the owner's implicit
`CREATE` shows up. An owner can revoke `CREATE` from itself. Then the grant list says `USAGE`
only, and the gate reports the role clean.

**Example.** `ALTER SCHEMA public OWNER TO shredding_app; REVOKE CREATE ON SCHEMA public FROM
shredding_app;` The gate starts as "unprivileged". Then `shredding_app` runs `DROP TABLE
public.shredding_erasure CASCADE` and it succeeds. The same works for the data key table and for
`DROP FUNCTION ... CASCADE` on a guard, which takes its triggers with it. The same holds for any
role in reach that owns the schema. SECURITY-NOTES already tells users not to run as the schema
owner; the gate does not enforce it. The PR body's mutation 2 note ("probe 1 stays refused
through the schema-owner CREATE leg") shows the same reliance on that one grant entry.

**Repro.** `CipherProbePr45Test.probe_schema_owner_with_its_own_create_revoked_passes_and_can_drop_the_erasure_log`,
RED on 285fd1c: the DROP (rolled back) succeeds, then `verifySchema` returns.

**Fix (correction, fixer).** In `SchemaVerification.checkRole`, add an ownership leg on the
verified schema, bound to the login oid like the others:
`pg_catalog.pg_has_role(?::pg_catalog.oid, n.nspowner, 'MEMBER')` for the schema oid. Message
"`<login prefix>`owns, or is a member of the owner of, schema `<name>`". Keep the schema's
grant-list leg as it is. Fix the comment on `OBJECT_GRANTS_SQL` ("the schema has no ownership
leg") and the PR body's deviation line. Test: the probe above, moved into `LoginRoleReachTest`,
plus a NOINHERIT member of a schema-owning group. Mutation for the PR body: drop the new leg,
expected red the probe.

### C-PR45-2 (LOW): column-level REFERENCES to the runtime role itself passes the allow list

**What goes wrong.** `checkColumnGrants` skips the current role for every column grant
(`continue` when the grantee is the current role). It means to leave UPDATE to
`checkColumnUpdate`. But `checkColumnUpdate` checks UPDATE only. So a column grant of
`REFERENCES` (the only other column privilege outside `SELECT` and `INSERT`) to the runtime role
itself passes. The same grant to any other role in reach refuses. The allow-list promise in
`SchemaExpectations` ("any other privilege refuses") is broken on this one path.

**Example.** `GRANT REFERENCES (tenant, subject, version) ON shredding_data_key TO
shredding_app`, and the runtime role owns another schema `mine` (common). The gate starts. The
role creates `mine.pin` with a foreign key to the data key table and inserts one row. Now the
crypto-shredding `DELETE` of that key fails with SQLState 23503. The erasure cannot finish.
Foreign-key triggers are internal, which the trigger leg leaves out by design, so a restart
does not catch it either.

**Repro.** `CipherProbePr45Test.probe_column_references_grant_to_the_runtime_role_passes_and_blocks_key_destruction`,
RED on 285fd1c: the DELETE fails with 23503, then `verifySchema` returns.

**Fix (correction, fixer).** In `SchemaVerification.checkColumnGrants`, skip the current role
only in the first branch of the union (the UPDATE rows). Rows from the second branch (non-UPDATE
column grants) are judged for the current role too. Message as today ("holds REFERENCES on
shredding_data_key.tenant"). Test: the probe moved into `LoginRoleReachTest`. Mutation: restore
the unconditional skip, expected red the probe.

### C-PR45-3 (MEDIUM): EXECUTE on a server-file function passes. DESIGN STOP

**What goes wrong.** The gate refuses `pg_write_server_files`, `pg_read_server_files` and
`pg_execute_server_program` in reach (C-PR1c-1), because they let the role act as the server's
operating-system user. The same rights can be granted function by function. PostgreSQL ships
`lo_export`, `lo_import`, `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_stat_file`
and others with EXECUTE revoked from PUBLIC so that a superuser can grant them one at a time. No
leg reads function grants.

**Example.** `GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid, text) TO shredding_app`. The
gate starts as "unprivileged". The runtime role then writes a file of its choice as the server's
user. With that it can overwrite `postgresql.auto.conf` (a shell after the next reload, like
C-PR1c-2) or a table's data file. `pg_read_binary_file` on `global/1260` reads the password
verifiers that made `pg_read_all_data` refused (C-PR1c-8).

**Repro.** `CipherProbePr45Test.probe_execute_on_lo_export_passes_and_writes_a_server_file`, RED
on 285fd1c: the file `/tmp/cipher-pr45-written-by-runtime-role` is written by the runtime role
and read back by the superuser, then `verifySchema` returns.

**Why a design stop.** The fix is a new leg with a data rule, not a correction. It must decide
which functions count, and stay true across releases without a version switch, like the
C-PR1c-4 allow list. I do not prescribe the mechanism here.

**Property to hold.** No role in reach, and PUBLIC no more than the server's own default, holds
EXECUTE on a function that reads or writes server files, runs programs, or reloads or signals
the server. A function a later release adds must be refused by default.

**Paths the design must cover.** A direct grant to the login or the current role; a grant to a
role in reach (INHERIT and NOINHERIT); a grant to PUBLIC; `pg_catalog` functions on 16 and 17;
functions of extensions in the database (`adminpack`, `dblink` connect `_u` forms, `lo_*`);
overloads (`pg_read_file(text)` and its three-argument form); the weaker mode (WARN);
`SECURITY DEFINER` wrappers stay the stated L19 limit, and the page says why the line is drawn
there.

**Routing question.** The rule "one mechanism per PR" says this gets its own PR with two passes.
The no-allowance rule says no merge while it is open. I recommend: the coordinator opens the
design page now; this PR merges after C-PR45-1, -2 and -4; the 0.2.1 tag waits for C-PR45-3.
The coordinator decides.

### C-PR45-4 (LOW): the required probe check (job `cipher-probes`) is red on this head

**What goes wrong.** `tools/cipher-probe-c-pr-1-split-package.sh` and
`tools/cipher-probe-c-pr-1-starter-scope.sh` plant a class that calls `new DatabaseIdentity(0L,
0L, "app", 2200L, "app", "app")`. This PR added two components (`loginRoleOid`, `loginRole`), so
the planted class no longer compiles. Both probes stop as UNVERIFIABLE. The CI job
probe check (job `cipher-probes`) fails on 285fd1c (run 39111970629, step "Probe the sealed jdbc package"). The
builder report lists the suite green and does not mention it.

**Example.** Today nobody can tell from CI whether the jdbc package is still sealed against a
forged `VerifiedSchema`. The probe that answers that question cannot run.

**Fix (correction, fixer).** In both scripts, plant the eight-argument form: `new
DatabaseIdentity(0L, 0L, "app", 2200L, "app", "app", 0L, "app")`. Run both with
`CIPHER_PROBE_MAVEN=1` and show in the PR body that each is GREEN for the right reason (split
package: a sealing violation at run time; starter scope: both architecture rules report the
planted class). CI probe check (job `cipher-probes`) green before the PR leaves draft.

### Deviations from the design page, judged

| Deviation | Ruling |
| --- | --- |
| `pg_read_all_data` refused | right. Measured read of `pg_authid.rolpassword`. Follows the round-2 rule |
| L17 rename refused, not accepted | accepted, fail closed, documented (see table above) |
| Superuser login gets one message | accepted. The refusal holds and the message is clearer |
| Owner's own entries left out of the allow list | accepted for tables, sequence and database. Wrong for the schema reasoning: C-PR45-1 |
| Starter Hikari test waits for the first pool fill | accepted. It removes a timing race; the assertion is unchanged |
| PgBouncer and managed services open (#C-50, #C-51) | accepted as open items for the tag, as round 1 ruled. The PR body must state the managed-service master-login facts before the tag |

### Fix list for the fixer

1. C-PR45-1: schema ownership leg in `SchemaVerification.checkRole`; comment and PR body text;
   probe into `LoginRoleReachTest`; mutation shown red.
2. C-PR45-2: `checkColumnGrants` skips the current role only for UPDATE rows; probe into
   `LoginRoleReachTest`; mutation shown red.
3. C-PR45-4: eight-argument constructor in both planted classes; both probes GREEN for the right
   reason; CI green.
4. C-PR45-3: no code in the fix list. Design page by the builder, reviewed before code.

The probe file for the fixer is `internal/gdpr-shredding/probes/CipherProbePr45Test.java`. The
load-point script is `internal/gdpr-shredding/probes/cipher-probe-pr45-load-point.sh`.

## Pass 2 (2026-10-19)

Head reviewed: `4cd0e1e` (fix pass on top of `main` `f2e15b4`; `main` is now `d24b2ae`, a probe
check rename, no code change). Scope: the fix commits `b5ed156` and `f378af9`, and the line break
moved in this file by `4cd0e1e`. That last change only re-wraps one paragraph of C-PR45-4: no word
changed (checked with a word diff). In this pass I also replaced the old display name of the probe check by
its job id in the pass-1 text, because the reference guard on `main` now refuses that name. Only
that name changed.

### Verdict: MERGE WITH FIXES

C-PR45-1, C-PR45-2 and C-PR45-4 are fixed. Their probes are green and the three mutations are
caught. C-PR45-3 stays open in its own design and PR, as the coordinator ruled; the tag waits for
it. This pass found three INFO problems. Two are small corrections for this PR (C-PR45-6, C-PR45-7).
One joins the C-PR45-3 design page (C-PR45-5).

| Id | Severity | Status | One line |
| --- | --- | --- | --- |
| C-PR45-1 | MEDIUM | fixed | schema ownership leg in `checkRole`; probe green |
| C-PR45-2 | LOW | fixed | column skip limited to UPDATE rows; probe green |
| C-PR45-3 | MEDIUM | open, DESIGN STOP, own PR | probe still red, as expected |
| C-PR45-4 | LOW | fixed | both release probes GREEN for the right reason; CI probe check (job `cipher-probes`) green |
| C-PR45-5 | INFO | new, routed to the C-PR45-3 design | a view owned by the owner lets the runtime role UPDATE `wrapped_key`; the gate passes |
| C-PR45-6 | INFO | new, fix in this PR | a column SELECT grant on the erasure log's sequence passes the sequence allow list |
| C-PR45-7 | INFO | new, fix in this PR | the split-package probe reports a non-compiling plant as exit 1 (its RED code), with no UNVERIFIABLE line |

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -B clean verify`, Docker up, no other Maven run | green: core 709, starter 315, sample 25; 0 failures, 0 errors, 0 skipped; JaCoCo gate met |
| CI on `4cd0e1e` | all six checks green, probe check (job `cipher-probes`) included |
| Pass-1 probes (`CipherProbePr45Test`, unchanged) | 4 of 5 green; C-PR45-1 and C-PR45-2 probes green; C-PR45-3 probe red (expected) |
| Pass-2 probes (`CipherProbePr45Pass2Test`, 5 tests) | 3 confirmations green; 2 probes red (C-PR45-5, C-PR45-6) |
| Mutation 1: schema ownership leg off (`if (false)`) | caught: the 2 builder tests, the pass-1 probe and 2 pass-2 confirmations go red |
| Mutation 2: unconditional current-role skip restored | caught: the builder test and the pass-1 probe go red |
| Mutation 3: plant back to six arguments | caught by both scripts (non-zero exit). Starter scope: "UNVERIFIABLE: the planted copy did not compile", exit 2. Split package: javac error, exit 1, no verdict line (C-PR45-7) |
| `cipher-probe-c-pr-1-split-package.sh`, `CIPHER_PROBE_MAVEN=1` | GREEN: "sealing violation" |
| `cipher-probe-c-pr-1-starter-scope.sh`, `CIPHER_PROBE_MAVEN=1` | GREEN: both architecture rules name the planted class |

A correction to pass 1: I wrote that both release probes "stop as UNVERIFIABLE". The starter-scope
probe did. The split-package probe stopped on the javac error with exit 1. Both failed CI, so the
finding stands as written; the wording was wrong. The PR body's mutation line repeats it ("shown for
both scripts"); the fixer corrects that line with C-PR45-7.

### Attacks the brief asked for

| Attack | Result |
| --- | --- |
| Schema owner reached only through a SET FALSE, INHERIT FALSE grant | refused, 004, "login role ... owns, or is a member of the owner of, schema public". `confirm_schema_owner_reached_only_through_a_set_false_grant_refuses`. Such a member cannot use the owner's rights; refusing it matches the table legs and errs on the safe side |
| Schema owned by a group the login is a NOINHERIT member of | refused; covered by the builder test `noinherit_member_of_a_schema_owning_group_refuses_naming_the_login_and_the_schema`. Confirmed |
| Module in a non-public schema `shred` | the leg judges `shred`, the schema the gate verifies. The runtime role owning `public` passes, which is right: it cannot drop objects in `shred`. Owning `shred` with CREATE revoked refuses with "owns schema shred", after the role showed it could drop the erasure log (rolled back). `confirm_module_in_a_non_public_schema_judges_that_schema` |
| Column grants on the sequence | PostgreSQL accepts only SELECT on a sequence column; it warns and drops UPDATE, INSERT and REFERENCES. The SELECT grant passes the gate: C-PR45-6. UPDATE on the sequence (it allows `setval`) through a group in reach is refused |
| Column grants on views | PostgreSQL accepts them. No leg reads views: C-PR45-5 |
| The UPDATE allow list | `encryption_count` on the data key table and `erased_at` on the erased-subject table, nothing else. UPDATE on `wrapped_key` to the runtime role, and on `state` and `tenant` through an INHERIT FALSE group, all refuse. `encryption_count` cannot re-key. `erased_at` is inert: the append-only trigger refuses every UPDATE of that table. `confirm_update_on_a_key_column_refuses_directly_and_through_reach` |
| Probe scripts, UNVERIFIABLE path for a non-compiling plant | both fail closed (non-zero exit). Only starter scope says UNVERIFIABLE: C-PR45-7 |

### C-PR45-5 (INFO): a view owned by the owner writes the data key table for the runtime role

**What goes wrong.** A view (with the default `security_invoker = false`) reads and writes its
base table with the view owner's rights. The column and table legs read the module's four tables
only. So a view over the data key table, owned by the owner, with UPDATE granted to the runtime
role, passes the gate. The role then rewrites any column of a key row.

**Example.** The owner runs `CREATE VIEW rpt.keys AS SELECT * FROM public.shredding_data_key;
GRANT SELECT, UPDATE ON rpt.keys TO shredding_app`. The runtime role runs `UPDATE rpt.keys SET
wrapped_key = '\x02', state = 'X'`. It succeeds and the gate still starts.

**Measured bound.** I found no gain beyond rights the role already holds on that table. The wrap
uses AAD `tenant|subject|keyVersion`, so a moved or copied wrapped key does not unwrap under
another identity. INSERT plus SELECT already lets the role copy a key row under a new name. DELETE
already lets it destroy a key. The three guarded tables carry row triggers on the base table. I did
not measure a write through a view on them in this pass.

**Repro.** `CipherProbePr45Pass2Test.probe_view_owned_by_the_owner_lets_the_runtime_role_update_wrapped_key`,
red on `4cd0e1e`.

**Fix: routed to the C-PR45-3 design page.** This is the same line as C-PR45-3 and the stated L19
limit: rights reached through an object a privileged role owns (a function, a view, a rule), not
through a role. The design page must take views and rules as paths. It either refuses them, or
states the limit with the bound above in SECURITY-NOTES (the stated-limits paragraph today names
`SECURITY DEFINER` functions only), and says why the line is drawn there. If the page refuses, the
probe flips green. If it states the limit, I reclassify the probe to a confirmation at that review.
No code in this PR.

### C-PR45-6 (INFO): a column SELECT grant on the sequence passes

**What goes wrong.** `SEQUENCE_ALLOWED` says USAGE is the only privilege a role in reach may hold on
`shredding_erasure_seq_seq`. A table-level SELECT on it is refused. A column-level SELECT
(`GRANT SELECT (last_value) ON shredding_erasure_seq_seq TO shredding_app`) passes, because
`checkColumnGrants` scans the four tables only. This is the C-PR45-2 shape on one more object.
Measured impact: the role reads `last_value`. It can already read every sequence value in the
erasure log, so it gains nothing.

**Repro.** `CipherProbePr45Pass2Test.probe_column_select_grant_on_the_sequence_passes_the_sequence_allow_list`,
red on `4cd0e1e` at the first refusal.

**Fix (correction, fixer).** In `SchemaVerification.checkColumnGrants`, include the sequence's oid
in the column scan (second branch of the union) and judge its rows against `SEQUENCE_ALLOWED`, so
every column grant on the sequence refuses. Message: "holds SELECT on
shredding_erasure_seq_seq.last_value". Test: the probe moved into `LoginRoleReachTest`. Mutation:
take the sequence out of the scan; expected red: the probe.

### C-PR45-7 (INFO): the split-package probe gives the wrong verdict for a non-compiling plant

**What goes wrong.** The script's contract is exit 0 GREEN, 1 RED, 2 UNVERIFIABLE. Its `javac` line
runs under `set -e`. When the planted class does not compile, javac exits 1 and the script stops
with exit 1, the RED code, and prints no verdict line. CI still fails, so nothing passes that
should not. But the result says "the package is forgeable" when the truth is "not checked".

**Example.** Plant the six-argument constructor again. The script prints the javac error and exits
1. The starter-scope probe in the same state prints "UNVERIFIABLE: the planted copy did not compile"
and exits 2.

**Repro.** `internal/.../probes/cipher-probe-pr45-p2-split-package-unverifiable.sh <module root>`,
RED on `4cd0e1e`. With the fix below applied to a copy, it is GREEN, and the unmodified plant still
gives "GREEN: the JVM refused the split package".

**Fix (correction, fixer).** In `tools/cipher-probe-c-pr-1-split-package.sh`, end the javac line
with `|| { echo "UNVERIFIABLE: the planted class did not compile"; exit 2; }`. Correct the PR body's
mutation 3 line to the real output of each script. Mutation: none needed; the probe is the test.

### Fix list for the fixer

1. C-PR45-6: sequence in the column scan, judged against `SEQUENCE_ALLOWED`; probe into
   `LoginRoleReachTest`; mutation shown red.
2. C-PR45-7: verdict line and exit 2 on a javac failure in the split-package probe; PR body line.
3. C-PR45-5: no code here. Add views and rules to the C-PR45-3 design page's paths.
4. Merge `main` (`d24b2ae`) before the PR leaves draft: the reference guard on `main` refuses the
   old check name, and this branch still holds it in files outside this review.

The probe files are `internal/gdpr-shredding/probes/CipherProbePr45Pass2Test.java` and
`internal/gdpr-shredding/probes/cipher-probe-pr45-p2-split-package-unverifiable.sh`.
