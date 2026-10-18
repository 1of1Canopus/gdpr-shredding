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
| C-PR45-4 | LOW | The required "Cipher probes" check is red on this head: two release probes plant the old six-argument constructor |

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
| `tools/cipher-probe-c-pr-1-split-package.sh`, `-starter-scope.sh` | both UNVERIFIABLE: the planted class does not compile. CI "Cipher probes" is red on 285fd1c (C-PR45-4) |
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

### C-PR45-4 (LOW): the required "Cipher probes" check is red on this head

**What goes wrong.** `tools/cipher-probe-c-pr-1-split-package.sh` and
`tools/cipher-probe-c-pr-1-starter-scope.sh` plant a class that calls `new DatabaseIdentity(0L,
0L, "app", 2200L, "app", "app")`. This PR added two components (`loginRoleOid`, `loginRole`), so
the planted class no longer compiles. Both probes stop as UNVERIFIABLE. The CI job "Cipher
probes" fails on 285fd1c (run 39111970629, step "Probe the sealed jdbc package"). The builder
report lists the suite green and does not mention it.

**Example.** Today nobody can tell from CI whether the jdbc package is still sealed against a
forged `VerifiedSchema`. The probe that answers that question cannot run.

**Fix (correction, fixer).** In both scripts, plant the eight-argument form: `new
DatabaseIdentity(0L, 0L, "app", 2200L, "app", "app", 0L, "app")`. Run both with
`CIPHER_PROBE_MAVEN=1` and show in the PR body that each is GREEN for the right reason (split
package: a sealing violation at run time; starter scope: both architecture rules report the
planted class). CI "Cipher probes" green before the PR leaves draft.

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
