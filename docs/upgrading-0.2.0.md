# Upgrading to 0.2.0

0.2.0 stops the application from creating its own database schema, and refuses to start against a
schema whose append-only guards it could remove itself. **An installation that upgrades the jar and
changes nothing will not boot.** That is the intended outcome: the previous behaviour is the
finding.

Read [SECURITY-NOTES.md](../SECURITY-NOTES.md) "Database roles" alongside this; it carries the
grant block these steps refer to and the reasoning behind each grant.

## Why

Until 0.1.1 the starter called the schema step with the application's own database credentials, on
every boot, with no property and no condition. Running that DDL makes the role the **owner** of the
four tables, the sequence, the two indexes and the three guard functions - and an owner can
`ALTER TABLE ... DISABLE TRIGGER`, or `CREATE OR REPLACE` a guard function with a body that allows
everything, and then delete from `shredding_erasure`. The documentation told operators to run as a
non-owner; the code could only start as the owner. So the append-only erasure log (control 8) and
the erasure tombstone (control 11) held in no configuration anyone could actually run.

Because of that, **every existing installation runs as the owner**, and the steps below are written
for that state rather than for a tidy one.

## What changed

| | 0.1.1 | 0.2.0 |
| --- | --- | --- |
| schema DDL at boot | always | only with `shredding.jdbc.initialize-schema=true`, which WARNs at every startup |
| schema verified at boot | no | yes: objects, columns, constraints, guard bodies, trigger set and state, rules, RLS, policies |
| privileged runtime role | a WARN about one table's ownership | a refusal, unless `shredding.jdbc.allow-privileged-runtime-role=true`, which WARNs at every startup |
| relation names in SQL | unqualified | qualified to the schema verified at boot |
| `JdbcSupport.runtimeRoleOwnsErasureTable` | public | **removed** |
| `JdbcKeyProvider` / `JdbcErasureStore` constructors | `(DataSource, ...)` | `(DataSource, VerifiedSchema, ...)` |
| guard function bodies | `RAISE EXCEPTION 'shredding_erasure is append-only ...'` | `RAISE EXCEPTION '% is append-only ...', TG_TABLE_NAME, TG_OP`, every operator written `OPERATOR(pg_catalog....)` and fully parenthesised |
| guard function `search_path` | none, so a body resolved its operator names in the path of whoever wrote to the table | `SET search_path = pg_catalog, pg_temp` on all three, verified as an exact one-element `pg_proc.proconfig` |
| operators, types, casts and functions in SQL | unqualified | `OPERATOR(pg_catalog....)`, `::pg_catalog....`, `pg_catalog....` - in the adapters, in the bundled script, and in the three statements the starter builds on the application's own connection |
| trigger state | whatever `CREATE TRIGGER` left (`O`) | the script sets all seven to `ENABLE ALWAYS` |
| a `@Shredded` entity's table | mapped with or without a schema | **must name a schema**: `spring.jpa.properties.hibernate.default_schema`, or `@Table(schema = "...")`. Without one, startup refuses with `SHRED-CONFIG-001` naming the entity |
| the read-back Hibernate renders | resolved its `count(*)` and its `=` through the session's `search_path` | runs with `search_path` replaced by `pg_catalog, pg_temp` for that one statement and restored to the bytes it arrived with; `SHRED-SCHEMA-008` if that cannot be established |

The guard-body change matters for the upgrade: from 0.2.0 the bodies are verified material, so an
installation that upgrades the jar without re-applying the script is refused with a message naming
the function. Re-applying the script is step 3 and it is mandatory, not cosmetic. The same is true of
the `search_path` clause the script now puts on all three guard functions: `pg_proc.proconfig` is
compared against exactly `{"search_path=pg_catalog, pg_temp"}`, and anything else - absent, a second
setting beside it, or a spelling that stores different text such as
`SET search_path TO 'pg_catalog, pg_temp'` - is `SHRED-SCHEMA-003`. The one supported producer of
that clause is the bundled script.

**A trap worth one line of your runbook, measured:** `CREATE OR REPLACE FUNCTION` with no `SET`
clause silently resets `proconfig` to NULL, with no error. Re-applying an *older* copy of
`schema-postgresql.sql` over a 0.2.0 schema therefore disarms the clause on all three guards and the
next boot refuses. Re-apply the copy that ships with the jar you are deploying, and check with the
one-liner in step 1.

**An installation already running a 0.2.0 pre-release of this branch** must re-apply the script as
the owner before booting the new code, or startup refuses with `SHRED-SCHEMA-003` naming the
`proconfig`.

### Every installation: name the schema your entities live in

This is the one change that needs an edit to your application's own configuration, and it is a
startup refusal, so find out before the deploy window. Add, for the usual deployment:

```yaml
spring:
  jpa:
    properties:
      hibernate.default_schema: app      # the schema your own tables live in
```

or, per entity:

```java
@Entity
@Table(name = "customer", schema = "app")
public class Customer { ... }
```

If neither is present, startup fails with:

```
SHRED-CONFIG-001: Customer is @Shredded and is mapped to the table "customer", which names no
schema. ... Set spring.jpa.properties.hibernate.default_schema=<schema> for the application, or
map @Table(schema = "<schema>") on this entity.
```

Why it is a refusal and not a warning: without a schema the erasure's `UPDATE`, this module's own
read-back and the read-back Hibernate renders are all unqualified. A table of the same name in a
schema ahead of yours on the connection's `search_path` takes all three at once, so they agree with
each other, and the erasure reports `COMPLETE` over data it never touched. The schema name must be
lowercase and must not carry a catalog, which was already true in 0.1.x.

One consequence worth knowing before you hit it: one statement of each erasure - the read-back
Hibernate renders from your mapping - now runs with `search_path` replaced by `pg_catalog, pg_temp`.
If a row-level-security policy function on that table, or a function called from a view an entity is
mapped to, names a relation unqualified, that statement fails with the database's own `relation
"..." does not exist` and the erasure is refused rather than completing on an unexpected answer.
The remedy is one line per function: `ALTER FUNCTION <fn> SET search_path = <schema>, pg_catalog`.
A `LANGUAGE sql` body resolves its names at creation time and is unaffected.

## Steps

Run them in this order. They were executed end to end against a 0.1.x-shaped database.

### 1. Record the current state, before the upgrade hides it

```sql
SELECT tablename, tableowner FROM pg_tables
 WHERE schemaname = current_schema() AND tablename LIKE 'shredding%';

SELECT tgname, tgenabled FROM pg_trigger WHERE NOT tgisinternal;

SELECT proname, md5(prosrc) FROM pg_proc
 WHERE pronamespace = current_schema()::regnamespace AND proname LIKE 'shredding%';

SELECT proname, proconfig FROM pg_proc
 WHERE pronamespace = current_schema()::regnamespace AND proname LIKE 'shredding%';
```

A `tgenabled` other than `O` or `A`, or a guard-body md5 that does not match the one published in
the 0.1.1 release notes, means a guard has already been off or replaced. On a 0.1.x schema
`proconfig` is NULL on all three, which is expected there; after step 3 it must read
`{"search_path=pg_catalog, pg_temp"}` on all three, and a NULL at that point means an older script
was applied last. **That is an incident to
record now**, before a clean boot on 0.2.0 makes it invisible.

### 2. Move ownership to a role that is not the application's

As a role that is a member of both, or a superuser (which is what most managed estates will use):

```sql
ALTER TABLE    shredding_data_key                     OWNER TO <owner role>;
ALTER TABLE    shredding_erased_subject               OWNER TO <owner role>;
ALTER TABLE    shredding_erasure                      OWNER TO <owner role>;
ALTER TABLE    shredding_erasure_anchor               OWNER TO <owner role>;
ALTER FUNCTION shredding_erasure_append_only()        OWNER TO <owner role>;
ALTER FUNCTION shredding_erasure_anchor_monotonic()   OWNER TO <owner role>;
ALTER FUNCTION shredding_erasure_anchor_append_only() OWNER TO <owner role>;
```

Seven statements, not nine: `ALTER TABLE ... OWNER TO` carries the table's indexes and its owned
sequence with it. **The three functions do not move with the tables**, and that is the trap - a
role that owns only a guard function can `CREATE OR REPLACE` all four append-only guards and the
anchor guard into no-ops while owning no table at all.

`REASSIGN OWNED BY <application role> TO <owner role>` also works and is one line, but it moves
**every** object that role owns in the database, the application's own business tables included,
after which the application can no longer `ALTER` them. Use it only if the application role owns
nothing else.

Also move the schema if the application role owns it: `ALTER SCHEMA <schema> OWNER TO <owner role>`.

### 3. Apply the 0.2.0 `schema-postgresql.sql` once, as the owner role

Idempotent; adds no column. It restores the guard bodies and sets all seven triggers to
`ENABLE ALWAYS`, which is also the only documented repair for a trigger someone disabled - the
`CREATE TRIGGER` blocks are all guarded by "if not exists", so before 0.2.0 a disabled trigger
stayed disabled through every re-apply.

The script ships inside the `gdpr-shredding-core` jar at
`com/housedevinci/shredding/schema-postgresql.sql`, or call
`JdbcSupport.initializeSchema(ownerDataSource)` from a one-off job or a migration step.

### 4. Take DDL and shadowing privileges away from the application role

```sql
REVOKE CREATE    ON SCHEMA   <schema> FROM <application role>;
REVOKE CREATE    ON SCHEMA   public   FROM PUBLIC;   -- PostgreSQL 14 and earlier
REVOKE TEMPORARY ON DATABASE <db>     FROM <application role>, PUBLIC;
REVOKE CREATE    ON DATABASE <db>     FROM <application role>, PUBLIC;
```

The last two lines are not cosmetic. `TEMPORARY` lets the application role create
`pg_temp.shredding_erasure`; `CREATE` on a database is `CREATE SCHEMA`. Either one, plus one
`SET search_path` that needs no privilege at all, is a copy of the erasure log that its own appends
go into while `current_schema()` still answers with the real schema.

**The database must not be owned by the application role.** A database owner holds both privileges
implicitly and re-grants them to itself in one statement after boot, so the `REVOKE` does not bind
it:

```sql
SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database();
ALTER DATABASE <db> OWNER TO <owner role>;
```

### 5. Apply the grant block

The "Database roles" section of [SECURITY-NOTES.md](../SECURITY-NOTES.md), in full, including
`GRANT USAGE ON SCHEMA`. Keeping the old application role as the runtime role is fine once steps 2
and 4 have run.

### 6. Point the application at the runtime role

`spring.datasource.username` / `spring.datasource.password`. Keep the owner's credentials out of
the application's environment entirely; a migration step in the same deployment uses its own
secret.

### 7. Deploy 0.2.0 with no new properties set

Expect one INFO line, `shredding: schema verified in schema ... (4 tables, 32 columns, ...)`, and
no WARN. If instead you get:

| code | what it means |
| --- | --- |
| `SHRED-SCHEMA-001` | none of the tables are in `current_schema()`. Wrong schema on the `search_path`, or step 3 ran somewhere else |
| `SHRED-SCHEMA-002` | the objects are wrong in shape. Step 3 did not run as the owner, or the tables were hand-written |
| `SHRED-SCHEMA-003` | a guard is not load-bearing. Usually step 3 skipped: the message names the guard function whose body is stale, or the trigger that is disabled |
| `SHRED-SCHEMA-004` | the runtime role is privileged. Step 2, 4 or 6 did not take effect; the message names each leg |
| `SHRED-SCHEMA-005` | verification could not complete. A catalogue read was refused, or a migration is in flight |
| `SHRED-SCHEMA-006` | `initialize-schema=true` and the DDL failed. Use the owner-applied path instead |
| `SHRED-SCHEMA-007` | a privilege the application needs is missing. Step 5 is incomplete |
| `SHRED-CONFIG-001` naming an entity and a schema | a `@Shredded` entity's mapping names no schema. See "Every installation: name the schema your entities live in" above |

Every message lists **every** problem it found, so one round of fixes is enough.

### 8. Only if a role cannot be added in the same window

```yaml
shredding:
  jdbc:
    initialize-schema: false
    allow-privileged-runtime-role: true
```

Accept the WARN at every startup, and record in your processing documentation that the append-only
controls are not enforced against the application until steps 2 to 6 are done. Do not present that
configuration as an append-only erasure log to a supervisory authority.

## If you use the core module directly, without Spring

`JdbcSupport.initializeSchema(DataSource)` is unchanged in signature and is how an owner-run
migration applies the schema. Two things to add:

```java
VerifiedSchema schema = JdbcSupport.verifySchema(runtimeDataSource).schema();
var keys = new JdbcKeyProvider(runtimeDataSource, schema, masterKey, random, clock);
var store = new JdbcErasureStore(runtimeDataSource, schema, chain, blindIndexColumns, residual);
```

`JdbcSupport.runtimeRoleOwnsErasureTable` is removed. It had no `schemaname` predicate, so it
answered about whichever copy of `shredding_erasure` `pg_tables` listed first, and it tested
ownership of one table when owning one guard function is enough to replace every guard.
`verifySchema` replaces it and refuses rather than reporting.

## Rolling back

0.1.1 ignores both new properties and boots as before. The only schema changes 0.2.0 makes are the
guard-function bodies and `ENABLE ALWAYS`, and 0.1.1 tolerates both, so a rollback is an
application rollback with nothing to undo in the database.
