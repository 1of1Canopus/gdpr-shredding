# Security review: feat/no-ddl-at-runtime (PR 13)

## Pass 1, 2026-09-28

Head reviewed: `e1f711d`. Mechanism: "no DDL at runtime", built from the design page approved with
changes (version 2.1, must-dos M1 to M7 claimed landed, M8 out of scope). One mechanism, one PR.

Method: the branch was built and run, not read. Full `verify` on a clean worktree with Docker up;
every attack below was first reproduced against a throwaway PostgreSQL on the digest the module's
tests pin, then written as a probe test that fails against this head.

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw verify` | green, exit 0 |
| Tests | 389 run, 0 failures, 0 errors, 0 skipped (core 155, starter 217, sample 17) |
| New probe tests added by this review | 5, all RED against `e1f711d` |
| Prior review probes re-run | the whole suite, unchanged, green |

The five probe tests are committed to the module test tree by this review, and they are red. The
branch's build is therefore red from this commit on, which is the accurate state of a branch whose
verdict is NOT MERGEABLE. They go green as the findings are fixed; none of them is to be disabled,
renamed or weakened.

### Verdict: NOT MERGEABLE

One HIGH. Under the no-allowance rule the MEDIUM, the two LOWs and the two INFOs are fixed in the
same round.

What the mechanism gets right, confirmed by execution rather than assumed: the default is refusal
and the two weaker modes each WARN at every startup; the gate is unconditional, eager and the owner
of the verified `DataSource`, and neither `spring.main.lazy-initialization=true` nor a user-supplied
`KeyProvider`/`JdbcErasureStore` bean nor a second `DataSource` bean gets past it; every one of the
module's eighteen statements names the schema that was verified, so the second-schema, `pg_temp` and
mid-session `SET search_path` shadows are all closed in this module's own SQL; the guard bodies are
compared against the bundled resource with a lone-CR refusal that holds; the eight upgrade steps
execute in order on a 0.1.1-shaped database and the schema boots clean at the end; two concurrent
first starts in creation mode both succeed under the script's advisory lock and leave exactly seven
triggers; and the flaky-test fix (closing and rebuilding the role pools rather than soft-evicting
them) is the right one - every `ALTER ROLE` in the suite goes through the rebuilding helper, so no
session-state race remains in it.

The HIGH is the same class of defect as D-2 and D-5 of the design review, in a column of
`pg_trigger` that the exact-trigger-set leg does not read.

---

## C-13-1 (HIGH) - a guard trigger with a `WHEN` predicate, or narrowed to a column list, is reported "schema verified"

**Property broken.** Design §1: "A schema whose guards are missing, disabled, replaceable or
bypassable by the runtime role is refused, not reported clean." §4.4 makes the trigger set
exhaustive on name, table, `tgfoid`, `tgtype` and `tgenabled`. Two further columns decide whether a
trigger fires at all, and neither is read:

- `pg_trigger.tgqual` - the `WHEN (...)` predicate. `WHEN (false)` is a guard that never fires.
- `pg_trigger.tgattr` - the `UPDATE OF <columns>` list. A guard narrowed to one column does not
  fire for an `UPDATE` of any other.

Both are invisible to every leg this branch runs: name, relation, `tgfoid` -> `proname`,
`pronamespace`, `tgtype` and `tgenabled` are byte-identical to the clean schema.

**Repro, leg 1 (the erasure log).** As the owner, against a schema the bundled script created:

```sql
DROP TRIGGER shredding_erasure_append_only ON shredding_erasure;
CREATE TRIGGER shredding_erasure_append_only
  BEFORE UPDATE OR DELETE ON shredding_erasure
  FOR EACH ROW WHEN (false) EXECUTE FUNCTION shredding_erasure_append_only();
ALTER TABLE shredding_erasure ENABLE ALWAYS TRIGGER shredding_erasure_append_only;
```

Catalogue after, for all seven triggers: `tgtype` 27/34/27/34/19/11/34 and `tgenabled` `A`
throughout - the expectation exactly. `INSERT` one row, then `DELETE FROM shredding_erasure`:
`DELETE 1`, no exception, the log is empty. `JdbcSupport.verifySchema(app, false)` returns a verdict
and the gate logs `shredding: schema verified ... 7 triggers ENABLE ALWAYS ...`.

**Repro, leg 2 (the chain anchor), and this one does not need the owner to stay involved.**

```sql
DROP TRIGGER shredding_erasure_anchor_monotonic ON shredding_erasure_anchor;
CREATE TRIGGER shredding_erasure_anchor_monotonic
  BEFORE UPDATE OF updated_at ON shredding_erasure_anchor
  FOR EACH ROW EXECUTE FUNCTION shredding_erasure_anchor_monotonic();
ALTER TABLE shredding_erasure_anchor ENABLE ALWAYS TRIGGER shredding_erasure_anchor_monotonic;
```

`tgtype` stays 19, `tgenabled` stays `A`, only `tgattr` changes (`{4}`). The runtime role holds
table `UPDATE` on the anchor by the documented grant block, so from that point the runtime role
itself, owning nothing and a member of nothing, runs

```sql
UPDATE shredding_erasure_anchor SET head_hash = '999...', row_count = 0;
```

and the monotonic guard never fires. `row_count` reads 0. The anchor is the external,
attacker-unwritable record that makes tail deletion detectable; after this it is writable by the
role the whole mechanism exists to constrain, and boot verification calls the schema clean.

**Probes (RED on `e1f711d`).**
`gdpr-shredding-core/src/test/java/com/housedevinci/shredding/adapter/jdbc/CipherProbeNoDdlPr13Test.java`:
`probe_a_guard_recreated_with_a_when_clause_is_still_reported_verified`,
`probe_a_guard_narrowed_to_update_of_one_column_is_still_reported_verified`.

**Fix (the builder - inside the mechanism he built).** In `SchemaVerification.checkTriggers`, add
`t.tgqual IS NULL` and `t.tgattr` to the `pg_trigger` projection, carry both on the `Found` record,
and add a `guards` entry when either is wrong. The seven shipped triggers all carry `tgqual` null
and `tgattr = '{}'`, measured, so the expectation is a constant and `SchemaExpectations.Trigger`
needs no new field. The message must name the trigger and say which of the two it is, because
`\d+ <table>` shows a `WHEN` clause and an operator can read it. Add the two columns to design §4.4's
table and to the §8 mutation plan ("drop the `tgqual`/`tgattr` legs" -> the two probes go red), and
to SECURITY-NOTES "What startup verification does and does not prove".

---

## C-13-2 (MEDIUM) - an inheritance child of the erasure log is reported "schema verified"

**Repro.** As the owner, on a script-created schema:

```sql
CREATE TABLE shredding_erasure_child () INHERITS (shredding_erasure);
INSERT INTO shredding_erasure_child (seq, ts, ...) VALUES (999, ...);
```

`SELECT count(*) FROM shredding_erasure` returns 1: a row nobody appended is returned by every read
of the verified relation, including the module's own `read()` and the chain verifier, because a
child RTE carries no separate permission check and no separate name. `DELETE FROM shredding_erasure
WHERE seq = 999` removes it - the parent's row-level trigger does not fire for a child row, and the
child has no triggers of its own. `verifySchema` returns clean.

This is the same shape as the `relhasrules` and `pg_policy` legs the design already has: one
catalogue signal, one count, a statement rewritten or re-targeted before any guard sees it.

**Probe (RED).** `probe_an_inheritance_child_of_the_erasure_log_is_still_reported_verified`.

**Fix (the builder).** In `SchemaVerification.relations`, add
`EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = c.oid)` to the projection and refuse it in
`checkRulesAndPolicies` as `SHRED-SCHEMA-003`, naming the child from `pg_inherits`/`pg_class`. Use
`pg_inherits`, not `pg_class.relhassubclass`: the flag is a hint and is not cleared when the last
child is dropped, so it would produce a refusal that re-applying the script cannot clear. Design
§4.5 gains the leg, §8 gains the mutation row, SECURITY-NOTES gains it in the same sentence as the
rules and policies.

---

## C-13-3 (LOW) - `VerifiedSchema` is forgeable, so §6b row 12 has no control

Design §6b row 12 closes "a caller-supplied `DataSource` handed to core directly" with: the adapters
"will not construct without a `VerifiedSchema`, which only `JdbcSupport.verifySchema` produces".
`VerifiedSchema` is a record, so its canonical constructor is public: `new VerifiedSchema("public")`
compiles anywhere and the adapters accept it. The type is the control for that row of the
integration surface, and the type is a naming convention.

**Probe (RED).** `probe_a_verified_schema_can_be_produced_without_any_verification` asserts the
canonical constructor is not public.

**Fix (the builder).** Turn `VerifiedSchema` into a `public final class` with a package-private
constructor, keeping `name()`, `qualify(String)`, `equals`, `hashCode` and `toString`. Only
`SchemaVerification` (same package) constructs it. Nothing outside the package constructs one today,
so this is source-compatible for every real caller.

---

## C-13-4 (LOW) - verification is not the read-only transaction it says it is

`SchemaVerification`'s class Javadoc and design §4 both say "one connection, one read-only
transaction, catalogue reads only". `JdbcSupport.verifySchema` takes a connection and never calls
`setAutoCommit(false)` or `setReadOnly(true)`, so the eleven catalogue reads take eleven snapshots.
Two consequences, neither dramatic and both cheap to close: the INFO line "schema verified" is a
claim about no single instant of the database; and nothing on the server side refuses a write from
this connection, so the "catalogue reads only" rule is enforced by review alone.

**Probe (RED).** `probe_verification_does_not_run_in_one_read_only_transaction` wraps the connection
in a proxy and records `getAutoCommit()`/`isReadOnly()` at the first `prepareStatement`.

**Fix (the builder).** In `JdbcSupport.verifySchema(DataSource, boolean)`, set `setReadOnly(true)` and
`setAutoCommit(false)`, run `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`, verify, then roll
back and restore both flags in a `finally`. The creation path already holds one transaction under
the script's advisory lock and must not be made read-only; state that difference in §4.7.

---

## C-13-5 (INFO) - an agent name in public text

`gdpr-shredding-core/src/main/resources/com/housedevinci/shredding/schema-postgresql.sql:13` reads
"Module B, Cipher findings J1 and K1". Public text carries roles, never agent names; finding ids and
technical detail stay. Pre-existing on `main`, in a file this PR modifies, so it is fixed here rather
than rediscovered at the release pass.

**Fix (the fix pass).** "Module B, security-review findings J1 and K1."

---

## C-13-6 (INFO) - the health indicator publishes the security posture and no document says so

`ShreddingActuatorAutoConfiguration.shreddingHealthIndicator` gains two details, `schema` and
`runtimeRolePrivileged`. Reporting the gate's verdict rather than re-deriving it is right. But
`runtimeRolePrivileged: yes` is a one-word statement that this application's append-only controls are
advisory, readable by anyone who can reach `/actuator/health` with details on, and SECURITY-NOTES has
no line anywhere about health-detail exposure.

**Fix (the fix pass).** One paragraph in SECURITY-NOTES, beside "What startup verification does and does not
prove": the two new details, and that `management.endpoint.health.show-details` must not be
`always` on an anonymously reachable endpoint.

---

## Attacks attempted that produced no finding

Recorded so the next pass does not spend the tokens again. Each was executed, not reasoned about.

1. **A guard body swap whose normalised text equals the expected one.** The two normalisation steps
   erase exactly two things: CRLF versus LF line endings, which PostgreSQL's lexer treats
   identically, and leading/trailing Unicode whitespace. Neither can change the statements the
   server executes, so no such body is constructible.
2. **A lone `\r` that survives the fold at the very start or the very end of a body.** `String.strip`
   removes it before the `\r` check sees it, so three boundary variants are accepted. Not a finding:
   PostgreSQL ends a `--` comment early only at a CR that follows the `--` on the same line, which is
   necessarily interior, and the interior case is refused (T22b). The refusal is complete where it
   matters.
3. **Two concurrent first starts in creation mode on an empty database.** Both succeed, exactly seven
   triggers exist afterwards, no partial schema and no deadlock: the script's
   `pg_advisory_xact_lock` and the fact that both the script and the verification run in one
   transaction do what §4.7 claims.
4. **A partial view of a schema being created by another instance.** Not reachable: the first
   catalogue read either sees all four tables or none, and none is `SHRED-SCHEMA-001`. PostgreSQL
   DDL is transactional.
5. **A same-named guard function overloaded with arguments, to win the name-keyed map with a clean
   body while the trigger points at a swapped one.** Fails closed: a trigger function must take no
   arguments, so a same-name overload has `pronargs > 0` and the shape leg refuses it.
6. **A second `ShreddingSchemaGate` bean, by name or by type.** Both fail the context: the same name
   is a `BeanDefinitionOverrideException` with overriding off, a second bean of the type is
   ambiguous at the adapters' injection point, and the class is `final`.
7. **A DevTools restart.** The gate's work is in a constructor on an ordinary singleton with no
   static state anywhere on the path, so a restarted context re-verifies.
8. **The Hibernate read-back reaching a second `DataSource`.** `HibernateBlindIndexResidual` opens
   its `StatelessSession` with `withStatelessOptions().connection(connection)` on the erasure's own
   gate-verified connection. The relation it names comes from the mapping, which is the residual the
   branch declares and documents; it is not a second database.
9. **`StatelessSession`, `merge` and `refresh` reaching the module's four tables.** None of the four
   is a JPA entity anywhere in the module, so no Hibernate path names them.

## Fix routing and the next pass

C-13-1 to C-13-4 are inside the mechanism the builder wrote and go back to the builder, not to a
fix pass.
C-13-5 and C-13-6 are corrections and go to the fix pass. None of the six needs a new mechanism, so
none is a design stop. Pass 2 confirms each finding by its probe flipping green, then attacks the
surfaces the fixes introduce - principally the new `tgqual`/`tgattr` legs against a re-applied
script, and the read-only transaction against the creation path.

---

# Pass 2, 2026-09-28 (second and final pass)

Head reviewed: `da93f91` - three builder commits on top of pass 1's `07f706b`. Method unchanged:
built and run on a clean worktree with Docker up, every attack executed against a throwaway
PostgreSQL on the digest the module's tests pin before it was written as a probe.

## Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw verify` on `da93f91` as submitted | green, exit 0 |
| Tests on `da93f91` as submitted | 394 run, 0 failures, 0 errors, 0 skipped |
| Pass-1 probes (`CipherProbeNoDdlPr13Test`) | 5 run, 5 green - all five flipped by code change |
| Whole `CipherProbe*` suite re-run unchanged | 222 tests, 0 failures |
| Release-pipeline probe suite, `CIPHER_PROBE_MAVEN=1` | 67 probes, 67 fixed, 0 weak - re-run by this review, not taken from the PR body |
| New probes added by this pass (`CipherProbeNoDdlPr13bTest`) | 10, of which **9 green and 1 RED** |
| Tests after this review's commit | 404 run, 1 failure - the one red probe, which is C-13-7 |

## Verdict: MERGE WITH FIXES

Two INFO findings, both closing by prescription with no further pass. No HIGH, no MEDIUM, no LOW
is open. The branch stays draft; the fix pass applies C-13-7 and C-13-8, the red probe goes green,
and the PR is marked ready by the fix pass or the coordinator, not by this review.

## Pass-1 findings, ruled

| Finding | Severity | Ruling | Evidence |
| --- | --- | --- | --- |
| C-13-1 | HIGH | **CLOSED** | `probe_a_guard_recreated_with_a_when_clause_is_still_reported_verified` and `probe_a_guard_narrowed_to_update_of_one_column_is_still_reported_verified` both green; the two new legs also refuse an always-true `WHEN` and a full-column `UPDATE OF` list (two new probes, green) |
| C-13-2 | MEDIUM | **CLOSED** | `probe_an_inheritance_child_of_the_erasure_log_is_still_reported_verified` green; the mirror direction and a real `ATTACH PARTITION` are also refused (two new probes, green) |
| C-13-3 | LOW | **CLOSED** | `probe_a_verified_schema_can_be_produced_without_any_verification` green; `VerifiedSchema` is `final` with a package-private constructor, `equals`/`hashCode`/`name()` carried over by hand |
| C-13-4 | LOW | **CLOSED** | `probe_verification_does_not_run_in_one_read_only_transaction` green, and the server-side half is now proved directly: a write issued on the verification connection while verification is running is refused with SQLState `25006` |
| C-13-5 | INFO | **CLOSED** | the agent name is gone from `schema-postgresql.sql:13`; "Module B, security-review findings J1 and K1" |
| C-13-6 | INFO | **CLOSED** | SECURITY-NOTES gains "The health endpoint publishes the posture", naming both details and prescribing `when-authorized` over `always` |

### The probe file's own diff, checked

`chore(test): apply spotless to the review's probe file` touches
`CipherProbeNoDdlPr13Test.java` in exactly two ways: one unused `java.lang.reflect.Method` import
removed (the identifier appears nowhere else in the file) and one Javadoc paragraph rewrapped.
`git diff -w` over the whole pass-1..pass-2 range on that file shows the import line and nothing
else. No assertion, no fixture statement, no expected error code was touched. Accepted.

## C-13-1: ruling on the declined `pg_get_triggerdef` route

The builder declined the alternative and argued it in design page v2.2 and in the PR body:
`pg_get_triggerdef` returns a normalised, schema-qualified rendering that does not match the text
of `schema-postgresql.sql` character for character, so comparing the two needs an extractor and a
normaliser for `CREATE TRIGGER` - a second parser inside a security control, which is exactly what
§14.1 already refused for columns, and a normaliser that mishandles one form fails **open**.

**The declination is accepted.** Two conditions had to hold and both were checked rather than
assumed.

1. *Fail direction.* Two catalogue columns compared against two constants (`tgqual IS NULL`,
   `tgattr` empty) cannot under-specify: any deviation is a refusal. A text comparison against a
   rendering whose format is a server-version property is the one that degrades into
   "contains", and "contains" is the fail-open shape.
2. *Completeness.* `pg_get_triggerdef` renders nothing that the check now misses, at the four
   `tgtype` values this module ships. `pg_trigger` columns not read are `tgnargs`/`tgargs`,
   `tgdeferrable`/`tginitdeferred`/`tgconstraint`/`tgconstrrelid`/`tgconstrindid`, and
   `tgoldtable`/`tgnewtable`. Trigger arguments reach a plpgsql body only through `TG_ARGV`, and
   the three guard bodies are compared text for text and read `TG_ARGV` nowhere. The constraint
   columns and the transition-table columns are only settable on an `AFTER` trigger, and all four
   shipped `tgtype` values (27, 34, 19, 11) carry the `BEFORE` bit, which the exact-trigger leg
   already compares. `tgparentid` is covered by the new `pg_inherits` leg. There is no rewrite
   that `pg_get_triggerdef` would show and these columns would not.

## The constrained runtime role, enumerated

The builder's pointer - three times the attack came from the constrained runtime role, not the
owner - was taken as the main line of this pass. With **exactly** the grant block of
SECURITY-NOTES.md "Database roles" and the four `REVOKE`s beside it, 44 statements were executed as
the runtime role against a clean script-created schema. Every one of them was refused by the server:

`ALTER TABLE ... DISABLE TRIGGER ALL`, `DISABLE TRIGGER <one>`, `ENABLE TRIGGER ALL` (the `O`
downgrade), `CREATE TRIGGER`, `CREATE OR REPLACE FUNCTION` over a guard body, `CREATE RULE ... DO
INSTEAD NOTHING`, `ENABLE ROW LEVEL SECURITY`, `CREATE POLICY`, `CREATE TABLE ... INHERITS`, `ALTER
TABLE ... INHERIT`, `ALTER COLUMN ... SET DEFAULT`, `ALTER COLUMN seq DROP DEFAULT`, `ADD COLUMN`,
`ADD COLUMN ... GENERATED ALWAYS AS ... STORED`, `ALTER COLUMN ... DROP NOT NULL`, `ADD
CONSTRAINT`, `DROP CONSTRAINT`, `ALTER COLUMN ... SET STATISTICS`, `SET (fillfactor = ...)`, `SET
UNLOGGED`, `OWNER TO`, `RENAME TO`, `SET SCHEMA pg_temp`, `REINDEX TABLE`, `CLUSTER`, `LOCK TABLE
... IN ACCESS EXCLUSIVE MODE`, `TRUNCATE`, `DELETE`/`UPDATE` on the erasure log, `DELETE`/`UPDATE`
on the tombstone table, `DELETE`/`TRUNCATE` on the anchor, `setval` and `ALTER SEQUENCE ... RESTART`
and `SELECT last_value` on the erasure sequence, `CREATE TEMP TABLE shredding_erasure`, `CREATE
SCHEMA`, `CREATE TABLE`, `CREATE EVENT TRIGGER`, `CREATE EXTENSION`, `DROP INDEX`, `DROP FUNCTION
... CASCADE`, `DROP TABLE`. Probe:
`probe_the_runtime_role_can_change_no_verified_property`, green, and it asserts the *empty* list,
so a future grant that opens one of them turns it red.

The one write the runtime role does hold on a guarded table is table-wide `UPDATE` on the anchor,
which the documented grant block gives it on purpose. Seven directions were tried and all seven
were refused by `shredding_erasure_anchor_monotonic`: decrement, rewind to zero with a new head
hash, touch `updated_at` alone, flip `keyed`, advance the count without changing the head hash,
move `id` off 1, and advance by two. Probe `probe_the_anchor_guard_bounds_the_runtime_roles_update`,
green. What remains allowed is exactly "advance by one with a different head hash", which without
the erasure-log HMAC secret produces an anchor the chain verifier refuses; that is the anchor's
design and it holds.

`MAINTAIN` (PostgreSQL 17 and later) is not in the module's `refused` privilege matrix. Ruled **not
a finding**: the six operations it confers - `VACUUM`, `ANALYZE`, `CLUSTER`, `REINDEX`, `REFRESH
MATERIALIZED VIEW`, `LOCK TABLE` - preserve triggers, rules, policies, constraints and inheritance
edges without exception, so none of them changes a property this module verifies. Adding it would
also have to be version-guarded: on PostgreSQL 16, which is the digest this module's own tests pin,
`has_table_privilege(..., 'MAINTAIN')` raises `unrecognized privilege type`, which this module
correctly turns into `SHRED-SCHEMA-005` - so a naive addition would refuse every boot on every
supported server below 17. Named here so the next pass does not rediscover it.

## Attacks on the new legs, all refused

| Attack | Result | Probe |
| --- | --- | --- |
| a guard recreated with an always-true `WHEN` predicate | `SHRED-SCHEMA-003`, message names the `WHEN` clause | `probe_a_guard_with_an_always_true_when_clause_is_refused` |
| the anchor guard narrowed to the *full* column list, which still fires | `SHRED-SCHEMA-003`, message names the column list | `probe_a_guard_narrowed_to_the_full_column_list_is_refused` |
| one of the four tables made a **child** of a foreign parent (`ALTER TABLE ... INHERIT`) | `SHRED-SCHEMA-003`, "inherits from" | `probe_one_of_our_tables_made_a_child_of_a_foreign_parent_is_refused` |
| the erasure log attached as a **partition** of a foreign partitioned table (`ATTACH PARTITION` executed, not skipped) | `SHRED-SCHEMA-003` | `probe_the_erasure_log_attached_as_a_partition_is_refused` |
| a decoy schema earlier on the runtime role's `search_path` holding a *view* named `shredding_erasure` and three real decoy tables | refusal, not a clean verdict: `current_schema()` is the decoy, so the shape and the relkind legs fire there | `probe_a_decoy_relation_earlier_on_the_search_path_is_refused` |
| a write on the verification connection while verification is running | refused by the server, SQLState `25006`, and the connection writes again after the pool hands it back | `probe_the_verification_transaction_is_read_only_on_the_server` |
| autocommit, read-only and isolation after a **refusing** verification | all three restored, and the connection writes | `probe_the_verification_restores_the_connection_settings_after_a_refusal` |

## C-13-7 (INFO) - the `bigserial` leg does not catch the thing its own comment says it catches

`SchemaVerification.checkSequence` reads the sequence's `relkind` and the `pg_depend` `deptype='a'`
edge, and its message reads "A hand-made table with no bigserial default takes its first append to
discover that." The `a` edge is a dependency of the *sequence* on the column; it survives `ALTER
TABLE shredding_erasure ALTER COLUMN seq DROP DEFAULT` untouched. The column default itself
(`pg_attrdef`) is read nowhere in the module.

**Repro.** Apply the bundled script as the owner, grant the documented block, then as the owner:
`ALTER TABLE shredding_erasure ALTER COLUMN seq DROP DEFAULT`. `JdbcSupport.verifySchema` returns a
clean verdict; the first append then fails with a `NOT NULL` violation on `seq`. Probe
`CipherProbeNoDdlPr13bTest.probe_the_sequence_leg_catches_a_dropped_bigserial_default`, **RED**.

**Why INFO and not higher.** Not reachable by the runtime role: `ALTER TABLE ... ALTER COLUMN` is
owner-only and was refused in the 44-statement enumeration above. It is an availability defect, it
fails loudly, and nothing that verification asserts becomes silently untrue. It is reported because
the leg's stated purpose is to move that failure from the first erasure request to boot, and it
does not.

**Fix.** `SchemaVerification.checkSequence`, one more column on the query it already runs, no
parsing and no version-dependent text: require a `pg_attrdef` row for `shredding_erasure.seq` whose
`pg_depend` `deptype='n'` edge points at `shredding_erasure_seq_seq`'s oid - which catches both a
dropped default and a default wired to a different sequence.

```sql
SELECT count(*) FROM pg_attrdef ad
  JOIN pg_depend d ON d.classid = 'pg_attrdef'::regclass AND d.objid = ad.oid
   AND d.refclassid = 'pg_class'::regclass AND d.refobjid = <sequence oid> AND d.deptype = 'n'
 WHERE ad.adrelid = <erasure oid> AND ad.adnum = <attnum of seq>
```

A count other than 1 is `SHRED-SCHEMA-002` with the existing `incompleteRemedy()`. The acceptable
alternative, if the leg is meant to stay where it is, is to delete the sentence from the message and
from `SchemaExpectations`' Javadoc so the check no longer claims it - but the check is the better
of the two, because boot is where an operator can act. Test name for the fixer:
`SchemaVerificationTest.sequence_with_the_default_dropped_is_refused`. Closes when the probe above
is green.

## C-13-8 (INFO) - a dead Javadoc block, and a stale version line, in the file the fix touched

`SchemaVerification.java` now carries **two consecutive Javadoc comments** on
`verify(Connection, boolean)`: the pre-existing one, which documents
`@param allowPrivilegedRuntimeRole` and the rule that `007` is never downgraded, and the new one
about the read-only transaction. Java attaches only the comment immediately preceding the
declaration, so the `@param` block and the "`007` is never downgraded" rule are dead text - the
clue that they are unreferenced is that the dead block's `{@link Verdict#privilegeLegs()}` names a
type that does not exist (`SchemaVerdict` does) and no tool complains. The class Javadoc two
declarations above still reads "Design §4 ... version 2.1" and "One connection, catalogue reads
only", which is the state before this fix.

**Repro.** Read `SchemaVerification.java` lines 41 to 53 on `da93f91`; the two blocks are adjacent
with no declaration between them.

**Fix.** Merge the two blocks into one - the read-only-transaction paragraph, then the surviving
`@param` - and fix the broken `{@link}` to `SchemaVerdict#privilegeLegs()`. Update the class
Javadoc to "version 2.2" and to "one connection, one read-only REPEATABLE READ transaction,
catalogue reads only". No test: this one closes on the diff.

## Attacks attempted that produced no finding

Recorded so pass 3, if there ever is one, does not spend the tokens again. Each was executed unless
marked otherwise.

1. **`REPEATABLE READ` does not make the whole verification one snapshot.** The direct scans of
   `pg_class`, `pg_attribute`, `pg_constraint`, `pg_trigger`, `pg_inherits`, `pg_policy` and
   `pg_rewrite` are ordinary MVCC scans and do share the transaction snapshot. The
   `has_table_privilege`, `has_column_privilege`, `has_schema_privilege`,
   `has_database_privilege`, `has_sequence_privilege`, `pg_has_role`, `format_type`,
   `pg_get_constraintdef` and `pg_get_function_result` calls go through the syscache, which uses a
   catalogue snapshot rather than the transaction's. So the "one instant" claim is exact for the
   shape and guard legs and approximate for the privilege legs. **Not a finding:** no capability
   follows. Every way to change an ACL mid-verification (`GRANT`, `REVOKE`, `ALTER ... OWNER`,
   role membership) requires the owner or a superuser, and an owner does not need a race to remove
   a guard. The control that actually matters here - the server refusing a write from this
   connection - is `READ ONLY`, and that is proved by `25006` above.
2. **`MAINTAIN`.** See "The constrained runtime role" above.
3. **A partition edge as an escape from the `pg_inherits` leg.** `ATTACH PARTITION` really
   attached and was really refused; the probe distinguishes "refused by verification" from
   "`ATTACH` itself was impossible", and the first branch is the one that ran.
4. **A decoy earlier on the `search_path` diverting the module's own statements.** Not reachable:
   all eighteen statements are built from `VerifiedSchema.qualify`, the trigger functions are
   resolved by `tgfoid` and their bodies name no relation, and `proconfig IS NULL` is already a
   shape refusal so a `SET search_path` cannot be attached to a guard function either.
5. **Leaving the pooled connection read-only after verification.** `restore()` swallows its own
   failures by design; HikariCP additionally resets `readOnly`, `autoCommit` and isolation on
   return because the proxy saw all three setters. The probe writes on the connection afterwards
   and on a later pool checkout, and both succeed.
6. **A public path to `verifyInCallersTransaction`.** There is none: the method and the class are
   package-private, and the only caller is `JdbcSupport.initializeAndVerifySchema`, which is the
   `initialize-schema=true` path that already WARNs at every startup.
7. **Column defaults on the other fifteen defaulted columns.** Every one of them is overwritten by
   the module's own `INSERT`, which names all columns, so a rewritten default reaches no row.

## Fix routing

C-13-7 and C-13-8 are corrections inside code the builder already wrote; both are small and neither
needs a new mechanism, so neither is a design stop and both go to the fix pass. This is the second
and final review pass on this PR: the fix pass closes both, the red probe turns green, and the
result goes to the coordinator, not back to this review.

## Addendum, B-38-10 class (2026-10-02)

Targeted probe, not a third pass. One question, asked because the same class was found HIGH on
another module's no-DDL design page: **does `SchemaVerification` answer "schema verified" to a
runtime role that shadows the catalogue functions it calls?** It does.

Pass 2 recorded, under "Attacks attempted that produced no finding", item 4: a decoy earlier on the
`search_path` cannot divert the module's own statements, because every one of them is built from
`VerifiedSchema.qualify`. That is true and it still is. It is a statement about **relation
references**. The probe below is about **function names**, which were not in scope on either pass.

### The threat model, with nothing added

The hardened deployment of SECURITY-NOTES.md "Database roles": the application connects as a
runtime role holding only the grant block, and that role owns its own business schema - the normal
shape, since an application owns the tables its own entities live in. Two PostgreSQL facts do the
rest.

1. A role may always set its own default `search_path` (`ALTER ROLE <itself> SET search_path = ...`).
   There is no privilege to revoke and no server setting that refuses it. It is carried by any
   connection from any client, so it is not something the application's configuration can pin away.
2. `pg_catalog` is searched **first only when it is not named**. Name it explicitly and it is
   searched in the position it is named, so `search_path = public, app, pg_catalog` puts a
   role-owned schema ahead of the system catalogue for **every unqualified function and relation
   name** that server-side SQL resolves.

`SchemaVerification` writes all of them unqualified: `pg_has_role`, `has_table_privilege`,
`has_column_privilege`, `has_schema_privilege`, `has_database_privilege`,
`has_sequence_privilege`, `current_setting`, `format_type`, `pg_get_constraintdef`,
`pg_get_function_result`, `count`, `current_schema`, and the eleven catalogue relations. So does the
bundled script (`to_regclass`, `quote_ident`, `pg_advisory_xact_lock`, `pg_attribute`, `pg_trigger`)
and so does the erasure store's blind-index read-back (`count`, `now`). Nothing in the verification
transaction pins the `search_path`. The verdict is therefore an answer supplied by the role being
verified.

### C-13-9 (HIGH) - the verified role answers its own privilege legs

`CipherProbeNoDdlPr13cTest`, PostgreSQL 16.14 on the digest the module's tests already pin.
Fixture: role `probe_shadow_app`, `NOSUPERUSER NOCREATEDB NOCREATEROLE`, no `TEMPORARY` and no
`CREATE` on the database, owner of its own schema `app`; it is given `CREATE` on `public` for the
length of one script run, applies the bundled script, and the grant is taken straight back. It now
owns the four tables, the two indexes, the sequence and the three guard functions and holds every
privilege an owner holds - the exact state `SHRED-SCHEMA-004` exists to refuse. Eight SQL functions
in `app`, then `ALTER ROLE probe_shadow_app SET search_path = public, app, pg_catalog`, then a new
pool:

| function shadowed in `app` | returns | leg it silences |
|---|---|---|
| `pg_has_role(name, oid, text)` | `false` | owns 4 tables, 2 indexes, 1 sequence, 3 guard functions, the database |
| `current_setting(text)` | `off` for `is_superuser` | "is a superuser" |
| `has_schema_privilege(name, text, text)` | `$3 = 'USAGE'` | "holds CREATE on schema public" |
| `has_database_privilege(name, text, text)` | `false` | TEMPORARY, CREATE on the database |
| `has_sequence_privilege(name, oid, text)` | `$3 = 'USAGE'` | SELECT and UPDATE on `shredding_erasure_seq_seq` |
| `has_table_privilege(name, oid, text)` | the documented matrix, by `relname` | UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES on all four tables |
| `has_column_privilege(name, oid, smallint, text)` | the two documented columns only | per-column UPDATE excess |

Result, `probe_a_clean_verdict_implies_the_erasure_log_guards_cannot_be_disabled`:
`JdbcSupport.verifySchema(ds, false)` **returns** a verdict, `runtimeRoleIsUnprivileged()` is
`true`, and `summary()` carries the sentence "the role owns none of the 9 objects, holds no
privilege on them beyond the documented grant set, and holds no CREATE or TEMPORARY in this
database". On the same connection, immediately afterwards:

```
INSERT INTO public.shredding_erasure (...)        -- 1 row
ALTER TABLE public.shredding_erasure DISABLE TRIGGER ALL   -- succeeds
DELETE FROM public.shredding_erasure              -- succeeds, trail emptied
```

So the INFO line an auditor reads is false, and `SHRED-SCHEMA-004` - the whole of §4.6 - is not a
control against the role it is about. `allow-privileged-runtime-role=false`, the secure default,
is indistinguishable from the weaker mode. HIGH, and the same severity as B-38-10 for the same
reason: the control's subject is its witness.

Control test in the same class, no shadowing, same ownership: `SHRED-SCHEMA-004` is thrown
(`control_without_shadowing_the_same_state_is_refused_as_privileged`), and the honest two-role
deployment still verifies.

### C-13-10 (HIGH) - the shape legs are answerable too

Same role, same fixture. Two legs documented as deliberately definition-based rather than
name-based, both answered by one function each:

- `probe_a_shadowed_pg_get_constraintdef_cannot_hide_a_weakened_anchor_check`:
  `shredding_erasure_anchor_id_check` is dropped and re-added in place as `CHECK (id >= 1)`, so the
  anchor can hold a second head row; a 3-line `pg_get_constraintdef(oid)` reports
  `CHECK ((id = 1))` for that one `conname` and the truth for the other five. Verification passes.
- `probe_a_shadowed_format_type_cannot_hide_a_widened_hash_column`: `shredding_erasure.hash` is
  widened from `character(64)` to `character varying(100)`, so the chain's hash column stops being
  fixed width and blank-padded. `format_type` receives only the type oid and the modifier, so the
  lie has to be exact - no other column of the four tables is `varchar(100)` - and one `CASE` on
  the pair `(1043, 104)` is exact. Verification passes. (A crude shadow is caught: mapping all of
  `text` to `character(64)` makes the honest `hook_outcomes` leg fire, which is how this one was
  measured.)

### C-13-11 (MEDIUM) - the erasure store's blind-index read-back

`probe_a_shadowed_count_cannot_hide_blind_index_residue_from_the_read_back`. Not the gate:
`JdbcErasureStore`'s three `SELECT count(*)` read-backs, the control that refuses an erasure which
left an HMAC of the erased plaintext behind, and that is documented as sharing no identifier with
the statements the erasure built. `count` is an unqualified aggregate name and resolves through the
same `search_path`. With `CREATE AGGREGATE app.count(*)` whose `sfunc` returns the state unchanged,
the module's own read-back statement returns 0 against a table that holds 1 matching row. The
erasure is then recorded `COMPLETE`. `now()` in the `shredding_erased_subject` insert is the same
surface for the erasure timestamp. MEDIUM rather than HIGH only because the actor is the role whose
own erasure is being falsified, with no second party deceived until the trail is read.

### C-13-12 (MEDIUM) - the bundled script's own catalogue reads

`probe_a_shadowed_to_regclass_cannot_silence_the_scripts_keyed_from_birth_preflight`. The script's
first guard refuses a database written before keyed-from-birth and resolves both oids through
`to_regclass`, unqualified, inside a `DO` block - which resolves function names against the session
`search_path` like anything else. With `app.to_regclass(text) -> NULL`, both oids are NULL, both
arms of the `IF` are false, and the `RAISE` cannot fire: the script runs on a pre-redesign erasure
log and fails later and elsewhere (here, on the missing `subject_pseudonym` in `CREATE INDEX`)
rather than with the message written for it. The same shadow removes the `tgrelid` scoping from all
five trigger guards below it - the CIPHER-05 fix - and breaks idempotence, since every
`NOT EXISTS` is then true and `CREATE TRIGGER` hits "already exists" on a second run. Reachable on
the `initialize-schema=true` path, where the runtime role runs the script itself. MEDIUM: every
outcome measured so far is a refusal with the wrong message, not an accepted database - but the
leg does not do what it says, and the legs that would catch the result downstream are C-13-9 and
C-13-10.

### Checked and clean

- **The three guard function bodies** call no function at all (`RAISE EXCEPTION`, `IS DISTINCT
  FROM`, arithmetic). `proconfig IS NULL` is a shape refusal and stays correct: a `SET search_path`
  on a guard function is refused, and the bodies need none.
- **The module's eighteen write statements** remain unaffected: relation references come from
  `VerifiedSchema.qualify`, as pass 2 recorded. The adapters' exposure is function names only
  (`count`, `now`).
- **`md5`** is not a surface here: the digests in `SchemaVerification.md5Prefix` and the hash chain
  are computed in Java with `MessageDigest`, not in SQL. (This is where module B differs.)

### Must-do for PR 13

A correction, not a new mechanism: no new hook, lifecycle or data structure, and `VerifiedSchema`
already carries the captured schema name that the first item needs. Not a design stop. All four
items are one change and must land together; three of four alone leaves the verdict answerable.

1. `SchemaVerification.verify` and `verifyInCallersTransaction`: capture the session facts with
   `SELECT pg_catalog.current_schema(), current_user, pg_catalog.current_database()` as the first
   statement, then **pin the path for the rest of the transaction** with
   `SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)` (`true` = local, so the
   `restore()`/`rollback()` already in place undoes it, and `verifyInCallersTransaction` does not
   leak it into the caller's script transaction). `current_user` is a keyword and not shadowable.
2. Because the path is then pinned, every `current_schema()::regnamespace` in the eleven queries
   must become a bound parameter `?::regnamespace` carrying the captured `VerifiedSchema.name()`,
   or the queries will read `pg_catalog` instead of the application schema. This is the half of the
   fix that is easy to forget and that turns every shape leg into a false pass if forgotten, so the
   fix pass asserts the 47 `SchemaVerificationTest` cases and the 15 `CipherProbeNoDdlPr13*`
   cases unchanged.
3. Qualify every catalogue call and every catalogue relation in `SchemaVerification` to
   `pg_catalog.` anyway - the twelve functions listed above, the eleven relations, and the
   `'pg_class'::regclass` / `'pg_attrdef'::regclass` casts in the sequence leg. Belt and braces is
   the point: item 1 is one statement away from being lost in a later edit, and a qualified call is
   correct with or without it.
4. The two paths that cannot pin the path, because they have to resolve the application's own
   tables, are qualified only: `JdbcErasureStore`'s three blind-index read-backs become
   `SELECT pg_catalog.count(*)` and its `shredding_erased_subject` insert `pg_catalog.now()`; the
   bundled script's `to_regclass`, `quote_ident`, `pg_advisory_xact_lock`, `pg_attribute` and
   `pg_trigger` become `pg_catalog.`-qualified.

Then add a verification-time leg of the kind that cannot be shadowed, so a future unqualified call
is caught by a test rather than by a reviewer: `SchemaVerificationTest` gets a case that installs
the shadow set of this addendum and asserts the refusal, which is `CipherProbeNoDdlPr13cTest`
promoted. The probe file is
`gdpr-shredding-core/src/test/java/com/housedevinci/shredding/adapter/jdbc/CipherProbeNoDdlPr13cTest.java`,
committed RED: 6 failures, 2 controls green, on 970e67b.

### Numbers on this head

| | |
|---|---|
| head | 970e67b, `feat/no-ddl-at-runtime` |
| PostgreSQL | 16.14, `postgres:16-alpine@sha256:57c72fd2...c07777` |
| `CipherProbeNoDdlPr13cTest` | 8 run, **6 failures**, 0 errors, 0 skipped |
| `CipherProbeNoDdlPr13Test` | 5 run, 0 failures |
| `CipherProbeNoDdlPr13bTest` | 10 run, 0 failures |
| `CipherProbeJdbcTest` | 12 run, 0 failures |
| `SchemaVerificationTest` | 47 run, 0 failures |
| new findings | C-13-9 HIGH, C-13-10 HIGH, C-13-11 MEDIUM, C-13-12 MEDIUM |

### Verdict on this addendum: NOT MERGEABLE

Two HIGHs. 0.2.0 is not taggable with them open. Routing: the fix pass applies the four must-do
items as corrections; C-13-9 and C-13-10 are inside the mechanism the builder wrote on this PR, so
items 1 and 2 go to the builder, items 3 and 4 may go to the fix pass. The probe turning green is
the only accepted evidence.

## Addendum verification (2026-10-02)

Head `d25f30a`, replayed as `b45555b` after the DCO correction below; branch
`feat/no-ddl-at-runtime`; PostgreSQL 16.14 on the digest the module already pins.
Scope: confirm C-13-9 to C-13-12 by their probes flipping, rule on the two disclosed
deviations and the recorded residual, then attack the surfaces the fix created.

### C-13-9 to C-13-12: all four CLOSED

`CipherProbeNoDdlPr13cTest` reads **8 run, 0 failures** on this head, from 8 run / 6 failures
on `970e67b`. Nothing in the fixture, the shadow set or the assertions changed, bar the one
string ruled on below. The two controls that were green stayed green, so the flip is the fix
and not a weakened probe. Re-run unchanged and also green: `CipherProbeNoDdlPr13Test` (5),
`CipherProbeNoDdlPr13bTest` (10), `CipherProbeJdbcTest` (12). `SchemaVerificationTest` is 55,
the 47 of pass 2 plus T50 to T57, 0 failures. Full `./mvnw -B clean verify`: 187 core, 217
starter, 17 sample, 0 failures, 0 errors, 0 skipped, BUILD SUCCESS.

The mechanism is the one prescribed and both halves are present. The session capture runs
first through qualified names; `pg_catalog.set_config('search_path', 'pg_catalog', true)`
pins the rest of the transaction; the pin is read back against the literal `pg_catalog` and a
mismatch is `SHRED-SCHEMA-005`, which is right - `set_config` echoes its argument whether or
not it took, and outside a transaction block a local one silently does nothing. Every
catalogue function, catalogue relation and `regclass` cast in `SchemaVerification` now carries
the prefix as well, so the eleven queries are correct with the pin and without it. On the
paths that cannot pin because they address the application's own tables, the qualification
is there: `JdbcErasureStore`'s read-backs, its tombstone insert, `JdbcSupport.lockSubject`,
and the bundled script's `to_regclass`, `quote_ident`, `current_schema`,
`pg_advisory_xact_lock`, `pg_attribute` and `pg_trigger`.

### Deviation (a), the namespace oid: ACCEPTED, and better than what was prescribed

The fix list said `?::regnamespace` carrying `VerifiedSchema.name()`. The builder bound an
oid from an exact `nspname` match instead, because `regnamespacein` parses its argument as an
SQL identifier and `VerifiedSchema` deliberately supports `My Shred`, `Public` and `s"q`.
That is correct and the prescription was wrong: under the cast, every one of those schemas
would have turned the whole gate into `SHRED-SCHEMA-005` - unverifiable, which this module
treats as a refusal, so a deployment with a quoted schema name could not have booted at all.
T55 is the right test for it and it passes. The reasoning is in the Javadoc on `session()`
where the next reader will find it. Noted against my own fix list, not against the branch.

The exact-match form does introduce a surface the cast did not have, which is C-13-13 below.
That does not make the cast the better choice; it makes the capture statement need one more
correction.

### Deviation (b), the edited probe literal, and T57: ACCEPTED

`probe_a_shadowed_count_cannot_hide_blind_index_residue_from_the_read_back` built a copy of
the store's statement in the test, so it tracked the fix instead of proving it: adding
`pg_catalog.` to the copy turns it green whatever production does. That is my defect, not the
builder's, and the edit was disclosed in the commit body and in a comment at the line. One
string changed, nothing else; I diffed it. Accepted.

T57 is the mutation-sensitive form and I checked that it is, rather than taking the claim:
it builds a real `JdbcErasureStore` over a real table whose `BEFORE UPDATE` trigger
repopulates the blind-index column, stubs the independent read-back to zero so the same-text
`count` is the only thing that can refuse, calls `store.erase(...)`, and asserts
`SHRED-ERASURE-004` plus an empty `shredding_erasure`. Remove the prefix from the production
statement and the shadowed aggregate answers zero and the erasure is recorded COMPLETE, so
T57 goes red. The copy in the probe file is now redundant evidence; T57 is the control.

### Recorded residual, Hibernate's independent read-back: ACCEPTED as a design stop

`HibernateBlindIndexResidual` renders `count(*)` through HQL, which offers no way to qualify
an aggregate, so that one leg still resolves through the caller's `search_path`. The builder
named it rather than implying it, in the commit body, in SECURITY-NOTES and in the design page,
and the same-text read-back over the same column is qualified and refuses on its own - so the
control has a path that is not shadowable even when this one is. Closing the framework-rendered
half needs a mechanism, not a prefix. Correct call, correct place. It is now subsumed by
C-13-14, which is the general form of the same problem and which it must be designed with.

### C-13-13 (HIGH) - the one statement that runs before the pin resolves an operator

`CipherProbeNoDdlPr13dTest.probe_a_shadowed_equality_operator_cannot_redirect_the_captured_namespace_oid`.

The pin cannot be statement 1, because after it `current_schema()` answers `pg_catalog` and
the module's own schema would be unreadable. So the capture runs first and still resolves
names in the role's path. Every function and relation in it is qualified. The `=` of
`n.nspname = pg_catalog.current_schema()` is not, and an operator is resolved exactly the way
a function is: `pg_operator` entries are looked up along `search_path`, and an operator with
identical argument types in an earlier schema hides the one in `pg_catalog`. A role that owns
one schema may `CREATE OPERATOR app.= (LEFTARG = name, RIGHTARG = name, ...)`.

What it buys is the split the fix exists to prevent. The verdict's schema name comes from
column 1 and the namespace oid every later leg reads comes from the subquery; separate them
and the gate verifies one schema while `VerifiedSchema.qualify` sends every write to another.
Measured at the SQL level first:

```
 current_schema | captured_oid | public_oid | app_oid
----------------+--------------+------------+---------
 app            |         2200 |       2200 |   16385
```

and then end to end in the probe, in a fixture that grants the role nothing the hardened
posture refuses: the owner applies the script in `public` and issues the grant block; the role
owns one schema `app`, applies the script there, and puts it first on its own default path.
`JdbcSupport.verifySchema` returns a verdict, `runtimeRoleIsUnprivileged()` is `true`, the
summary carries "owns none of the 9 objects" - it is reading the owner's install in `public` -
and `verdict.schema().name()` is `app`, which is where every write goes. The same connection
then runs `ALTER TABLE app.shredding_erasure DISABLE TRIGGER ALL` and `DELETE`, and empties
the trail that was just certified. This is C-13-9's outcome restored, through the only name
the fix could not pin.

Control in the same class, `control_without_the_operator_the_role_owned_schema_is_refused_as_privileged`:
same two installs, same path, no operator, the gate refuses. Green.

**Fix (a correction, not a mechanism).** Split the capture in two and put the pin between them.
Statement 1 goes back to `SELECT pg_catalog.current_schema(), current_user,
pg_catalog.current_database()`, which contains no operator at all. Statement 2 is the pin.
Statement 3, now running under `search_path = pg_catalog`, resolves the oid:
`SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ?` with the captured name bound.
Write the comparison as `n.nspname OPERATOR(pg_catalog.=) ?` as well, for the same
belt-and-braces reason the prefixes are there. `SchemaVerification.session` and
`SchemaVerification.run`; the probe above is the test, promoted into `SchemaVerificationTest`.

### C-13-14 (HIGH) - DESIGN STOP - the guard function bodies resolve their operators in the writer's session

`CipherProbeNoDdlPr13dTest.probe_a_shadowed_operator_cannot_disarm_the_anchor_monotonic_guard`.

Pass 3 recorded, under "Checked and clean": "the three guard function bodies call no function
at all (`RAISE EXCEPTION`, `IS DISTINCT FROM`, arithmetic)". That is my error. `IS DISTINCT
FROM` is resolved through the `=` operator for the type, and arithmetic and comparison are
operators. `shredding_erasure_anchor_monotonic` is plain plpgsql, is not `SECURITY DEFINER`,
and - because `SchemaExpectations` requires `proconfig IS NULL` - carries no `SET search_path`
by design, so its body resolves in the session of whoever performs the write. Its whole guard
is four operators: the `=(boolean, boolean)` behind `IS DISTINCT FROM`, the `<>(bigint,
bigint)`, the `+` that makes the count monotonic, and the `=(bpchar, bpchar)` on `head_hash`.

Three operators in a schema the role owns and the anchor takes any value the role likes:

```
=== honest attempt ===      ERROR:  keyed is immutable
=== with shadowed operators ===   UPDATE 1
 id | row_count | keyed | left
----+-----------+-------+------
  1 |         1 | f     | bbbb
```

The probe runs it through the shipped script in the documented two-role posture. The role is
`NOSUPERUSER NOCREATEDB NOCREATEROLE`, owns none of the nine objects, holds exactly the grant
block, and `JdbcSupport.verifySchema` passes **truthfully** - `SHRED-SCHEMA-004` has nothing to
complain about and this is not a gate bypass. The role then rewrites `row_count` from 7 to 1,
replaces `head_hash` and flips `keyed` from true to false, all three of which the schema
comments call impossible, and `UPDATE` on the anchor is in the documented grant block. The
anchor is the module's external record of the trail's length, head and keyed mode - the thing
the design leans on precisely because the chain columns are what a table-owning attacker
rewrites - and flipping `keyed` is the documented route to a trail that can be forged without
the HMAC key. The append-only guards survive, their bodies being a bare `RAISE EXCEPTION` with
no operator in them, so rows still cannot be deleted; the detector for everything else does not.

Control `control_without_the_operators_the_anchor_guard_refuses_the_same_update`: green.

Scope, stated rather than probed: the same mechanism reaches every unqualified operator in
every statement the module runs on an application connection - `JdbcErasureStore`'s
`WHERE tenant = ? AND subject = ?` predicates among them, where a false `=` makes the erasure
clear nothing and the read-back see nothing and the outcome be recorded COMPLETE. I did not
raise that as its own finding because I could not isolate the shadow to one statement without
the fixture's other lookups failing first, and the repro attempt is recorded here rather than
asserted. Hibernate's HQL `count(*)`, recorded by the builder as a residual, is the same
problem seen from the framework side.

**DESIGN STOP, not a fix list.** This needs a new mechanism and it must cover paths, not
statements. The property that must hold: *no name in any statement this module's controls
depend on - function, relation, aggregate, operator or cast - is resolvable by the role the
control is about.* The paths it has to cover: (1) the three guard function bodies, invoked
from any session that writes, including sessions this module never opens; (2) every statement
`JdbcErasureStore`, `JdbcKeyProvider` and `JdbcSupport` issue on an application connection;
(3) anything the application's own ORM renders against the shredding tables. Note the tension
the design has to resolve rather than route around: the obvious hardening for (1) is
`SET search_path = pg_catalog` on the three functions, and `SchemaExpectations`'s
`proconfig IS NULL` leg currently **refuses** exactly that, so the shape rule has to invert
from "must carry none" to "must carry this one" and the bundled script and the upgrade page
move with it. One page from the builder, reviewed before any code.

### C-13-15 (MEDIUM) - the bundled script's `||`, the half of C-13-12 that is still open

`CipherProbeNoDdlPr13dTest.probe_a_shadowed_concatenation_operator_cannot_silence_the_keyed_from_birth_guard`.

C-13-12 closed `to_regclass`. The string `to_regclass` is handed is still built with an
unqualified `||`: `pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erasure'`.
An `app.||(text, text)` is enough:

```
NOTICE:  resolved oid = 1259, name = pg_class
```

and returning a name that resolves to nothing puts both oids back to NULL, which is the exact
state C-13-12 described. In the probe, a pre-redesign `shredding_erasure` with no `key_id` is
not refused by the keyed-from-birth guard; the script fails later and elsewhere, here
`SHRED-KEY-UNAVAILABLE` with SQLState 42703 on a missing column, which is the "refusal with
the wrong message" C-13-12 measured. The five trigger guards lose their `tgrelid` scoping
(CIPHER-05) in the same move. Reachable on `initialize-schema=true`, where the runtime role
runs the script itself. MEDIUM for the same reason C-13-12 was MEDIUM: every outcome measured
is a refusal with the wrong message, not an accepted database.

The fix belongs with C-13-14's design, not ahead of it: qualifying `||` as
`OPERATOR(pg_catalog.||)` closes this one line, and the script contains other unqualified
operators that the same page has to rule on in one pass rather than one finding at a time.

### Housekeeping, mine

**DCO.** `ad39c59` carried no `Signed-off-by`, which is my omission and the reason the DCO
check was red. Amended in place with the review's own `Signed-off-by` trailer, and `d25f30a`
replayed on top by cherry-pick so the builder's message, authorship and own sign-off are
byte-identical. `git diff origin/feat/no-ddl-at-runtime` is empty against the
replayed head. New heads: `d285374` (was `ad39c59`), `b45555b` (was `d25f30a`).

**The release probe suite.** `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh`
reads **67 fixed / 0 weak** on this head, measured, not inherited.
`scripts/verify-reproducible.sh` was run in the foreground on the full tree and on a fresh
clone: both builds green, every enforced artifact byte-identical, both sources jars and all
three poms matching, and the third build the probe adds (`clean verify -Prelease`, tests
running) reproduces both sources jars exactly. There is no reproducibility defect.

The earlier reading of 66 fixed / 1 weak on `probe_sources_jar_differs_from_a_test_run` is the
probe behaving as designed. Its body runs a full `clean verify` inside a clone and reports a
weakness whenever that build fails for any reason - "unverifiable is not clean", applied to
itself. On `ad39c59` the build failed because `CipherProbeNoDdlPr13cTest` was committed RED,
which is this review's own doing. The same will be true while `CipherProbeNoDdlPr13dTest`
sits RED on the branch, and it is not a pipeline finding either time; it clears when the
probes flip. Worth one line in the release runbook so the next person does not chase it.

### Numbers on this head

| | |
|---|---|
| head | `b45555b` (tree-identical to `d25f30a`), `feat/no-ddl-at-runtime` |
| full build | `./mvnw -B clean verify`, BUILD SUCCESS |
| core / starter / sample | 187 / 217 / 17, 0 failures, 0 errors, 0 skipped |
| `CipherProbeNoDdlPr13cTest` | 8 run, **0 failures** (was 6 failures on `970e67b`) |
| `CipherProbeNoDdlPr13Test` / `b` / `CipherProbeJdbcTest` | 5 / 10 / 12, 0 failures, unchanged |
| `SchemaVerificationTest` | 55 run, 0 failures (47 + T50 to T57) |
| `CipherProbeNoDdlPr13dTest` | 5 run, **3 failures**, 2 controls green, committed RED |
| release probe suite | 67 fixed / 0 weak (`CIPHER_PROBE_MAVEN=1`) |
| reproducibility | reproducible, 9 artifacts, 3 builds |
| findings closed | C-13-9, C-13-10, C-13-11, C-13-12 |
| findings open | C-13-13 HIGH, C-13-14 HIGH (design stop), C-13-15 MEDIUM |

### Verdict: NOT MERGEABLE

Two HIGHs, and they are the same class as the two the fix closed rather than a new one: a
control whose subject supplies the names it is resolved through. The fix was right and
complete about function and relation names; operator names were not in its scope and nobody,
me included, put them there. The branch does not become mergeable by pinning jackson-databind
to 3.1.7 - that pin clears the Vulnerability scan check and nothing else, and the CVE gate is
not the finding here.

Routing. C-13-13 is a correction inside the mechanism the builder wrote on this PR, so it goes
to the builder with the three-statement capture above. C-13-14 is a DESIGN STOP: one page,
reviewed, then built, and C-13-15 lands inside it. Nothing here goes to a fix pass. The
condition for MERGEABLE is the three probes in `CipherProbeNoDdlPr13dTest` flipping green with
their two controls still green, the 55 of `SchemaVerificationTest` and the 8 of
`CipherProbeNoDdlPr13cTest` unchanged, and the design page reviewed before the code that
closes C-13-14.
