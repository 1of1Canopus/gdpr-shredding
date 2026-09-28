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
