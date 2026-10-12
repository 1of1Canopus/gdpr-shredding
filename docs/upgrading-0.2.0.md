# Upgrading to 0.2.0

## Will 0.2.0 start on my schema? Ten questions

Answer each with the query or the look-up named in it. **Yes is the good answer.** A "no" is a
startup refusal with the code shown; the remedy is one line and the linked step has the detail.
Run the queries per blind-index column and per `@Shredded` table, as the owner role, before the
deploy window. Questions 1 to 4 concern the database setup, 5 to 10 your tables and mapping.

0.2.0 never creates or changes your schema at runtime: the application runs no DDL unless you set
`shredding.jdbc.initialize-schema=true`, which WARNs at every startup. You apply the script once, as
an owner role (question 3).

| # | Question (yes is good) | How to answer | Refusal if no | Remedy |
|---|---|---|---|---|
| 1 | Does every `@Shredded` entity map to a table in a named schema? | No query: look for `hibernate.default_schema` or `@Table(schema = ...)` ([the schema section](#every-installation-name-the-schema-your-entities-live-in)) | `SHRED-CONFIG-001` | Set the schema in configuration or on the entity |
| 2 | Does the application's runtime role hold exactly the [step 5](#5-apply-the-grant-block) grant block and nothing more: not a superuser, no CREATE on the schema, no CREATE or TEMPORARY on the database, no ownership of the four `shredding_` tables, the sequence, their indexes, the three guard functions or the database, no SELECT on the sequence, no table privilege beyond the block? | The first query of [step 1](#1-record-the-current-state-before-the-upgrade-hides-it), the database owner query in [step 4](#4-take-ddl-and-shadowing-privileges-away-from-the-application-role), and a comparison of the role's privileges with the step 5 block | `SHRED-SCHEMA-004` (too much), `SHRED-SCHEMA-007` (a grant missing) | [Steps 2, 4, 5 and 6](#2-move-ownership-to-a-role-that-is-not-the-applications): move ownership, revoke DDL, apply the grant block, switch the runtime role |
| 3 | Were the four tables and three guards created by the 0.2.0 script, as the owner, with all seven triggers enabled? | The `tgenabled` and `proconfig` queries of [step 1](#1-record-the-current-state-before-the-upgrade-hides-it): after the script every guard trigger reads `A` (`O`, a plain `ENABLE TRIGGER`, is refused too; before the script `O` or `A` only tells you whether a guard was off), and every `proconfig` reads `{"search_path=pg_catalog, pg_temp"}` | `SHRED-SCHEMA-001`, `-002` or `-003` | [Step 3](#3-apply-the-020-schema-postgresqlsql-once-as-the-owner-role): apply the script that ships with the jar |
| 4 | Is each `@Shredded` table with a blind index an ordinary, permanent table with no parent, and are its partitions and children ordinary and permanent too? | The `pg_inherits` query at the end of [step 1](#1-record-the-current-state-before-the-upgrade-hides-it) must return no row; `pg_partition_tree` lists partitions | `SHRED-SCHEMA-009` | Map the root of the hierarchy, or a plain table; no views, foreign or temporary tables ([the table rules](#every-installation-what-your-entity-tables-must-be)) |
| 5 | Are the tenant and subject columns `text`, `varchar` or `char(n)` with a deterministic collation, and the blind-index column nullable and not generated? Does no row-level-security policy apply to the runtime role, does it hold SELECT and UPDATE on the table, and is the equality operator of each column's type in `pg_catalog`? | Column definitions: no query, read them against [the table rules](#every-installation-what-your-entity-tables-must-be). Row security and privileges: the mapping-checks query of [step 1](#1-record-the-current-state-before-the-upgrade-hides-it). Equality operator: a type outside `pg_catalog` (a domain, an extension type) is the cause; use a built-in type | `SHRED-SCHEMA-009` | Store `uuid` and numeric ids as `text`; drop `NOT NULL` on the blind index; exempt the role from the policy (`BYPASSRLS`) or drop row security on the table; grant SELECT and UPDATE ([step 5](#5-apply-the-grant-block)) |
| 6 | Is the statistics target of every blind-index column 0, with no stored statistics, expression index or extended statistics on it? | The statistics target, `pg_stats`, expression-index and `pg_statistic_ext` queries of [step 1](#1-record-the-current-state-before-the-upgrade-hides-it): target 0 and no other row | `SHRED-SCHEMA-010` | [Step 3a](#3a-turn-off-and-clear-planner-statistics-on-every-blind-index-column); every 0.1.x installation needs it |
| 7 | Does the table, or any partition or child, have no enabled trigger and no rule? | The triggers and rules queries of [step 1](#1-record-the-current-state-before-the-upgrade-hides-it) | `SHRED-SCHEMA-010` | Drop or disable it, or [acknowledge it](#acknowledging-a-trigger-a-publication-or-a-slot) with the hook that clears what it writes |
| 8 | Does no publication carry the blind-index column, and is there no logical slot with a plugin other than `pgoutput`? | The publication and slot queries of [step 1](#1-record-the-current-state-before-the-upgrade-hides-it) | `SHRED-SCHEMA-010` | A publication column list without the index; drop the slot; or [acknowledge](#acknowledging-a-trigger-a-publication-or-a-slot) |
| 9 | Is the blind-index column absent from every materialized view, foreign key and leftover audit or history table? | The foreign-key and leftover-table queries of [step 1](#1-record-the-current-state-before-the-upgrade-hides-it); a materialized view shows in the dependents query | `SHRED-SCHEMA-010` | Leave it out of the view, drop the foreign key, clear and drop the audit column |
| 10 | Is every `@BlindIndex` field `@NotAudited` under Envers (or `@Audited.Excluded`), with no `@Temporal` history on it, and no association (a to-one foreign key or a collection key) joined on it? | No query: read the entity and its associations; the leftover-table query of question 9 finds old history tables | `SHRED-SCHEMA-010` | `@NotAudited` and Envers registered as `docs/index.md` "Using Hibernate Envers" shows; remove `@Temporal` (`@Temporal.Excluded` does not help); join the association on another column |

If you answer no to any of 6 to 10 on a 0.1.1 installation, expect the refusals one per start, in
the order set out under "A 0.1.1 installation with Hibernate Envers meets these refusals" below, so
plan the database changes for one window. Every refusal message lists every problem it found and
prints its remedy. This section is a map; the sections after it are the rules.

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
| a `@Shredded` entity's table and its tenant, subject, identifier and blind-index columns | never looked at | **checked against the catalogue** at startup (present and inadmissible: refusal, `SHRED-SCHEMA-009`; absent: WARN) and inside every erasure, under `LOCK TABLE ... ROW EXCLUSIVE` and `... SHARE UPDATE EXCLUSIVE` (any refusal, absent included: `SHRED-SCHEMA-009`, nothing destroyed or recorded) |
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
A view and a row-level-security policy that applies to the runtime role are refused by mapping
admission (next section) before that statement runs, so neither one's functions run in there. What
does is the SQL in your own mapping: the text of a `@SQLRestriction`, and of every
auto-enabled `@Filter` condition, on an entity with a `@BlindIndex` field is rendered into that
read-back. Schema-qualify every function, relation and non-keyword type they name, for example
`@SQLRestriction("public.pr18_visible(owner_id)")`; an unqualified name makes every erasure of that
entity fail, loudly, and the erasure rolls back whole.
A `LANGUAGE sql` function written with a string body (`AS $$ ... $$`) is parsed again when it runs
and fails there exactly like plpgsql; only a SQL-standard body (`BEGIN ATOMIC ... END` or
`RETURN ...`, PostgreSQL 14 and later) binds its names when the function is created and is
unaffected. For either kind, the remedy is one line per function,
`ALTER FUNCTION <fn> SET search_path = <schema>, pg_catalog`, or rewriting the function with a
SQL-standard body.

### Every installation: what your entity tables must be

0.2.0 reads each `@Shredded` entity's table from the PostgreSQL catalogue before it erases from it,
and refuses a table the erasure cannot be trusted on: the erasure and both of its read-backs would
agree that the blind index was cleared while it was not, and the record would say `COMPLETE`. Check
your tables before the deploy window; every refusal names the entity, the table or column, the
catalogue fact and the remedy.

| refused | why | remedy |
|---|---|---|
| a view, a materialized view, a foreign table | the relation can hide the subject's row from every statement the erasure issues | map the entity to the table itself; keep the view for your queries |
| a partition or inheritance child that is a foreign table, a temporary table, or a partitioned table with no partitions | the erasure's `UPDATE` routes to it and nothing can tell whether it hid a row | every partition and child an ordinary permanent table |
| a temporary table | nothing durable is erased | map a permanent table |
| row level security that applies to the runtime role (it does not own the table, or the table has `FORCE ROW LEVEL SECURITY`) | a policy can hide the rows to clear | exempt the role (`BYPASSRLS` or a policy that admits it - the admission then WARNs as an advisory posture), or no RLS on that table |
| `SELECT` without `UPDATE` for the runtime role | the erasure would fail at its first statement | the grant block in SECURITY-NOTES "Database roles" |
| a tenant, subject or identifier column the table does not have | the mapping is wrong | correct the mapping |
| a tenant, subject or identifier column of type `citext`, `hstore`, an array, a composite or a range, or of a domain over one | its equality is not `pg_catalog`'s, so the module's comparison and the application's disagree (`citext`: 0 rows where the application finds 1) | map them as `text` or `varchar`; a cast is not offered, because it makes the erasure case-sensitive where the application is not |
| a tenant or subject column that is not `text`, `varchar` or `char(n)` after following domains: `uuid`, a numeric type, an enum, `name`, `"char"` | the erasure compares these columns against the request's string; other types parse it (one spelling of a subject clears another's index), truncate it, let a cast the application's role owns decide, or cannot compare with it at all | store the tenant and subject ids in a `text` or `varchar` column; a UUID or numeric subject id is stored as text |
| a column whose declared type carries its own two-sided `=` outside `pg_catalog` | the same disagreement, one type definition away from `citext` | the same |
| a non-deterministic collation on a compared column | an erasure for `s1` also clears `S1`, another tenant's row included | a deterministic collation |
| a blind-index column that is `NOT NULL` or generated | the erasure sets it to `NULL` | drop the constraint; index a plain column |
| a table with a blind index that is itself a partition, or an inheritance child | `ANALYZE` on the parent stores statistics computed from this table's rows under the parent's columns, the blind index included, readable by any role with `SELECT` on the parent; no erasure of the child reaches them | map the entity to the root of the hierarchy (never detach or `NO INHERIT`: both leave the values in the former parent, see step 1). The statistics check then covers the root, so if the root already holds statistics of the column the **next** start refuses with `SHRED-SCHEMA-010` and its own remedy: two refusals across two starts |
| a mapped table with a blind index any of whose partitions or inheritance children, at any depth, also inherits from a table outside that hierarchy, or a mapped table with more than one parent (`SHRED-SCHEMA-009`) | that other parent's statistics hold the descendant's rows, blind index included, and mapping one parent leaves the other holding them | restructure so every table holding blind-indexed rows has a single parent chain, and map its root; the message names every parent |
| planner statistics on a blind-index column: a statistics target that is not 0 (every column's default), rows already in `pg_stats`, an expression index computing over it, extended statistics covering it, or a stored generated column computed from it that has any of these; on the table or any partition or inheritance child (`SHRED-SCHEMA-010`) | `ANALYZE` stores sampled values of the column, most common values and histogram bounds, which any role with `SELECT` on the table reads from `pg_stats`, and an erasure does not remove them: the erased subject's index stays matchable | step 3a, before the deploy window |
| a copy of a blind-index column outside the table (`SHRED-SCHEMA-010`): Hibernate Envers auditing it, `@org.hibernate.annotations.Audited` or `@Temporal` history writing it, an association or element collection keyed on it, or, in the catalogue, any enabled trigger or rule on the table or a partition or child, a materialized view reading it (directly, through a view, or as a whole row), a foreign key on it (either side), a publication carrying it, a logical replication slot of this database with a plugin other than `pgoutput`, or a leftover audit or history table holding a column of its name (named `<table>_aud`, `<table>_AUD`, `<table>_history` or as the mapping names it, or holding the revision columns `rev`/`revtype` or `effective`/`superseded` next to it) | the erasure clears the index in the table only; every copy keeps the erased subject's index, matchable with the application's index secret, and a trigger or rule fires on the erasure's own `UPDATE`. This module cannot see where a trigger or a subscriber writes | the message names the object and its remedy: `@NotAudited` / `@Audited.Excluded` and clear the audit column; remove `@Temporal`; drop or disable the trigger, or acknowledge it with the hook that clears what it writes (`shredding.jdbc.acknowledged-copies`, below); drop the rule; leave the column out of the materialized view; drop the foreign key; a publication column list without the index; drop the slot; for a trigger, a publication with `UPDATE` or a slot, acknowledge it with its clearing hook; reference the entity by its identifier |

At startup a table that is present and refused fails the context with `SHRED-SCHEMA-009`. A table
that does not exist yet is a WARN, so `spring.jpa.defer-datasource-initialization=true`, a schema a
test creates after the context starts, and a migration applied while the application runs all
keep working; every erasure on that entity is refused with `SHRED-SCHEMA-009` until the table exists
and is admissible. A catalogue that cannot be read is `SHRED-SCHEMA-005`.

The statistics row is refused with its own code, `SHRED-SCHEMA-010`, at startup and before every
erasure's first statement, and **every 0.1.x installation meets it**: a blind-index column has the
default statistics target unless someone changed it, and autovacuum has sampled it once the table
passed about fifty rows. A schema Hibernate's `ddl-auto` creates meets it too, because Hibernate
cannot emit `SET STATISTICS`. A partition or child whose `pg_stats` rows the runtime role cannot
see (no `SELECT` on the column, or row level security that applies to the role) is
`SHRED-SCHEMA-005`: unverifiable is not clean. A plain partial index whose predicate names the
column (`ON customer (id) WHERE email_idx IS NOT NULL`) stores no statistics and is admitted; a
plain index on the column stores none either. An **expression** index whose predicate names the
column is refused: `ANALYZE` samples it only from the rows the predicate selects, so its statistics
record which index values those rows held. An expression index, extended-statistics expression or
stored generated column that calls a function or operator outside `pg_catalog`, or one that is not
immutable, is `SHRED-SCHEMA-005`.

A copy outside the table is refused with the same code, at startup and before every erasure's
first statement, and once more inside every erasure, after its `UPDATE` and read-backs and before
commit: `CREATE MATERIALIZED VIEW` and `CREATE PUBLICATION ... FOR ALL TABLES` are not blocked by
the erasure's locks, so a copy made while an erasure runs refuses that erasure, which rolls back
with nothing destroyed, cleared or recorded. A disabled trigger is admitted; enabling it refuses the
next erasure. Hibernate Envers is supported when every `@Shredded` and `@BlindIndex` field is
`@NotAudited` and Envers is registered as docs/index.md "Using Hibernate Envers" shows. `@Temporal`
history on an entity with a blind index is refused in 0.2.0, in a history table (Hibernate 7.4.5
keeps an excluded column there too) and in the table itself.

**A 0.1.1 installation with Hibernate Envers meets these refusals in this order**, one per
startup, so plan the changes for one window. A running 0.1.1 install already has `@NotAudited`
ciphertext and Envers registered manually (0.1.1 itself refuses an audited `@Shredded` field and
Envers' auto-registered listener, both `SHRED-CONFIG-001`), so those two shapes cannot be present.
Measured on a 0.1.1 install upgraded to 0.2.0, after the schema steps of this guide: 1.
`SHRED-CONFIG-001`, a mapping that names no schema: set `hibernate.default_schema` or
`@Table(schema = ...)`. 2. `SHRED-SCHEMA-010` from the mapping, Envers audits a `@BlindIndex` field:
mark every `@BlindIndex` field `@NotAudited`. 3. `SHRED-SCHEMA-009` from mapping admission (a
column type, a table that is a partition or inheritance child): the rows of the table above, when
your tables have them. 4. `SHRED-SCHEMA-010` from the catalogue, in one message: every trigger on
the table, the blind-index column still in each `<table>_aud` and `<table>_history` table (clear and
drop it: `UPDATE <table>_aud SET <column> = NULL; ALTER TABLE <table>_aud DROP COLUMN <column>;`),
and the planner statistics (step 3a). 5. `SHRED-SCHEMA-010` for a trigger alone, once the rest is
clean: drop it, or acknowledge it with the hook that clears what it writes. Then the application
boots, with one WARN at every startup naming each acknowledged copy and its hook. Steps 1 and 2
are code and configuration and can ship in one release; 3 to 5 are database changes for the window.

Admitted with a WARN at startup: an `UNLOGGED` table or partition (the erasure is sound; a crash
empties it, residue included). Admitted: a domain over `text` or `varchar` as tenant or subject,
and any identifier column type whose equality is `pg_catalog`'s (numeric, `uuid`, text, an enum).

Each erasure now takes `LOCK TABLE ... IN SHARE UPDATE EXCLUSIVE MODE` on every table it clears, so
the set of partitions and inheritance children cannot change between the check and the `UPDATE`.
It does not block your application's reads or writes. It does make two erasures of the same table
run one after the other, and an erasure waits behind a manual `VACUUM`, `ANALYZE` or
`CREATE INDEX CONCURRENTLY` on that table. An erasure also waits behind an autovacuum run to prevent transaction ID wraparound, which, unlike an ordinary autovacuum, does not give way to a waiting lock, for as long as that run takes; while it waits it holds the subject's advisory lock and key rows, and later erasures of the same table queue behind it. Set a `lock_timeout` on the erasure's connection if that wait must be bounded. When that bound fires, or the database picks the erasure as a deadlock victim, the erasure is refused with `SHRED-ERASURE-LOCK-WAIT` (SQLState `55P03` or `40P01`): the lock wait was exceeded, the erasure was not performed, nothing was destroyed, cleared or recorded, and the call can be retried once the other session has finished. It is not a key-store outage.

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

Then list what step 3a will have to change, for each blind-index column (here
`public.customer.email_idx`; repeat per column):

```sql
-- the table and every partition or inheritance child, at any depth (partitions are in
-- pg_inherits too); every query below that names "fam" reads it, so run them in this session
CREATE TEMPORARY TABLE fam AS
  WITH RECURSIVE t(relid) AS (
    SELECT 'public.customer'::regclass::oid
    UNION
    SELECT i.inhrelid FROM pg_catalog.pg_inherits i JOIN t ON i.inhparent = t.relid
  ) SELECT relid FROM t;
-- the statistics target (16: -1 is the default; 17: NULL is the default), on the table and
-- every partition or inheritance child; anything but 0 is refused
SELECT a.attrelid::regclass, a.attname, a.attstattarget
  FROM pg_catalog.pg_attribute a
 WHERE a.attrelid IN (SELECT relid FROM fam) AND a.attname = 'email_idx';
-- statistics already stored, on the table or on any member of the family: any row is refused
SELECT schemaname, tablename, attname, inherited FROM pg_catalog.pg_stats
 WHERE (quote_ident(schemaname) || '.' || quote_ident(tablename))::regclass
       IN (SELECT relid FROM fam)
   AND attname = 'email_idx';
-- expression indexes and extended statistics on the family: refused when they read the column
SELECT indexrelid::regclass, pg_catalog.pg_get_indexdef(indexrelid) FROM pg_catalog.pg_index
 WHERE indrelid IN (SELECT relid FROM fam) AND indexprs IS NOT NULL;
SELECT stxrelid::regclass, stxname FROM pg_catalog.pg_statistic_ext
 WHERE stxrelid IN (SELECT relid FROM fam);
-- what depends on the column (views, policies, generated columns): decides step 3a's shape
SELECT pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid) FROM pg_catalog.pg_depend d
  JOIN pg_catalog.pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
 WHERE d.refclassid = 'pg_catalog.pg_class'::regclass
   AND d.refobjid IN (SELECT relid FROM fam) AND d.deptype <> 'i'
   AND a.attname = 'email_idx';
```

Then list the copies 0.2.0 refuses (`SHRED-SCHEMA-010`), each non-empty result a finding (the
leftover-table query lists ordinary tables only, so a partition of the table or a materialized view
is not a false finding):

```sql
-- triggers and rules on the table and every partition or child
SELECT tgrelid::regclass, tgname, tgenabled FROM pg_catalog.pg_trigger
 WHERE NOT tgisinternal AND tgenabled <> 'D' AND tgrelid IN (SELECT relid FROM fam);
SELECT ev_class::regclass, rulename FROM pg_catalog.pg_rewrite
 WHERE rulename <> '_RETURN' AND ev_class IN (SELECT relid FROM fam);
-- publications carrying the table or any member of its family (a partitioned table published
-- without publish_via_partition_root is reported as its partitions), with their column lists
-- (NULL: every column)
SELECT p.pubname, p.pubupdate, t.relid::regclass, t.attrs
  FROM pg_catalog.pg_publication p, pg_catalog.pg_get_publication_tables(p.pubname::text) t
 WHERE t.relid IN (SELECT relid FROM fam);
-- logical slots of this database that decode without a publication
SELECT slot_name, plugin, active FROM pg_catalog.pg_replication_slots
 WHERE slot_type = 'logical' AND database = current_database() AND plugin <> 'pgoutput';
-- foreign keys on the table or any member of its family, either side
SELECT conname, conrelid::regclass, confrelid::regclass FROM pg_catalog.pg_constraint
 WHERE contype = 'f'
   AND (conrelid IN (SELECT relid FROM fam) OR confrelid IN (SELECT relid FROM fam));
-- leftover audit or history tables holding a column of the index's name (ordinary tables
-- outside the family; a materialized view is found by the dependents query above)
SELECT a.attrelid::regclass FROM pg_catalog.pg_attribute a
  JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
 WHERE a.attname = 'email_idx' AND NOT a.attisdropped AND c.relkind = 'r'
   AND a.attrelid NOT IN (SELECT relid FROM fam);
```

A materialized view over the column is found with the dependents query above (a `_RETURN` rule of
a relation whose `relkind` is `m`).

The `fam` table lists partitions and legacy inheritance children at any depth, so the queries above
cover both; it vanishes with the session. An index or statistics object whose definition does not mention the blind-index
column, and a dependent that is an index or a constraint, are not in the way.

Mapping checks for question 5, run as the runtime role (substitute its name; both of the last two
columns must be true, and `rowsecurity` false unless `bypassrls` is true):

```sql
SELECT c.relrowsecurity AS rowsecurity, c.relforcerowsecurity AS forced, r.rolbypassrls AS bypassrls,
       pg_catalog.has_table_privilege(r.oid, c.oid, 'SELECT') AS can_select,
       pg_catalog.has_table_privilege(r.oid, c.oid, 'UPDATE') AS can_update
  FROM pg_catalog.pg_class c, pg_catalog.pg_roles r
 WHERE c.oid = 'public.customer'::regclass AND r.rolname = '<runtime role>';
```

Each mapped table with a blind index must have no parent:

```sql
SELECT inhparent::regclass FROM pg_catalog.pg_inherits
 WHERE inhrelid = 'public.customer'::regclass;   -- must return no row
```

**A table that was ever a partition or an inheritance child** (detached, or `NO INHERIT`) left its
blind-index values in the former parent's `inherited` statistics, and nothing 0.2.0 reads can see
them there; `ANALYZE` of the former parent does not clear them once it has no child left. Clear
them on the former parent, as for step 3a: on PostgreSQL 18, as its owner,
`SELECT pg_catalog.pg_clear_attribute_stats('<schema>', '<parent>', '<column>', true);` for each
blind-index column; on 16 and 17, a superuser deletes the parent's `pg_statistic` rows for that
column with `stainherit` true, and the `pg_statistic_ext_data` rows with `stxdinherit` true of any
extended statistics on the parent that cover it, counting the rows first as in step 3a.

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

### 3a. Turn off and clear planner statistics on every blind-index column

As the owner role from step 2. The statements are compatible with 0.1.1, which never reads
statistics, so this step can run days before the 0.2.0 deploy with 0.1.1 live. The startup refusal
(`SHRED-SCHEMA-010`) prints the exact statements for your schema, with each column's actual type;
for a column with no dependents they are:

```sql
SET search_path = pg_catalog, pg_temp;
SET lock_timeout = '5s';
ALTER TABLE public.customer ALTER COLUMN email_idx SET STATISTICS 0;
ALTER TABLE public.customer ALTER COLUMN email_idx TYPE bytea USING email_idx;
```

The pinned `search_path` makes every name in the statements mean what the message meant: the
message reads every definition with the same path, so each name outside `pg_catalog` is printed
schema-qualified and cannot re-bind to a same-named table or function on your session's path. The
`SET STATISTICS 0` statement stops every future `ANALYZE` from sampling the column; the `TYPE`
statement deletes the statistics already stored. Measured on PostgreSQL 16 and 17: the second does not rewrite the table or its plain
indexes, and with the target at 0 no rows come back across a restart, `ANALYZE`, `ANALYZE <table>
(<column>)` and `VACUUM ANALYZE`. Each `ALTER TABLE` takes an `ACCESS EXCLUSIVE` lock: it waits for
running queries on the table and blocks new ones behind it, hence the `lock_timeout`; on a timeout,
retry. On a partitioned or inherited table run both on the parent: they reach every partition and
child. Then:

- **an expression index that computes over the column** (`ON customer (substring(email_idx ...))`)
  keeps its own statistics of the expression: `DROP INDEX` it. A plain index on the column is the
  supported lookup shape;
- **extended statistics covering the column**: `DROP STATISTICS`;
- **a stored generated column computed from the column** (`... GENERATED ALWAYS AS
  (lower(email_idx)) STORED`) holds the derived values and has its own statistics: it needs the same
  `SET STATISTICS 0`, and it blocks the `TYPE` statement (below).

**When views or row level security policies depend on the column**, the `TYPE` statement fails
(`cannot alter type of a column used by a view or rule`, `... used in a policy definition`). The
startup refusal then prints one transaction that drops them, runs the two statements and re-creates
them from their catalogue definitions (`pg_get_viewdef`, the view's options, owner, grants and
comment; the policy's command, roles, `USING` and `WITH CHECK`). One transaction, so the table is
never readable without its policies, and any failure rolls everything back; it opens with
`SET LOCAL search_path = pg_catalog, pg_temp` for the reason above. A view is not re-created, but
named (below), when default privileges for relations exist in its schema or globally: `CREATE VIEW`
would apply them, and the view would carry grants it never had.

**When the column has a dependent the message does not re-create** - a stored generated column, a
view other views depend on, a view with triggers, rules, column privileges or column comments, a
view under default privileges, a materialized view, a rule, a trigger with a column list or `WHEN`
clause, a SQL-standard function body - the message prints the `SET STATISTICS 0` statements for the column and for each stored
generated column computed from it (they need no retyping), names the dependents, and leaves the
rows already stored to one of these:

- **PostgreSQL 18 and later**, as the table owner, after `SET STATISTICS 0` on the column and on
  each stored generated column computed from it:

  ```sql
  SELECT pg_catalog.pg_clear_attribute_stats('public', 'customer', 'email_idx', false);
  SELECT pg_catalog.pg_clear_attribute_stats('public', 'customer', 'email_idx', true);  -- a parent
  ```

  once per column (the blind-index column and each generated column computed from it) and per
  partition or child.

- **PostgreSQL 16 and 17**, a superuser deletes exactly those rows, after the owner's
  `SET STATISTICS 0` on the same columns. First the attnums, every descendant listed (a partition
  or child may number the column differently):

  ```sql
  SELECT a.attrelid::regclass, a.attname, a.attnum FROM pg_catalog.pg_attribute a
   WHERE a.attrelid IN (SELECT relid FROM pg_catalog.pg_partition_tree('public.customer'))
     AND a.attname IN ('email_idx', 'email_low');
  SELECT pg_catalog.count(*) FROM pg_catalog.pg_statistic
   WHERE (starelid = 'public.customer'::regclass AND staattnum = 4)
      OR (starelid = 'public.customer'::regclass AND staattnum = 6);
  ```

  then, with the count just read (here 2) written into the check, both `stainherit` values
  included:

  ```sql
  BEGIN;
  DO $$
  DECLARE n bigint;
  BEGIN
    DELETE FROM pg_catalog.pg_statistic
     WHERE (starelid = 'public.customer'::regclass AND staattnum = 4)
        OR (starelid = 'public.customer'::regclass AND staattnum = 6);
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n <> 2 THEN RAISE EXCEPTION 'expected 2 pg_statistic rows, deleted %', n; END IF;
  END $$;
  COMMIT;
  ```

Either way the control is not the step: 0.2.0 re-reads the catalogue at every startup and before
every erasure, and admits the column only when the target is 0 and no rows are left. New
installations add the `SET STATISTICS 0` line to the migration that creates each blind-index
column.

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
| `SHRED-SCHEMA-010` | a copy of a blind-index column exists outside the table: planner statistics (its target, stored rows, an expression index, extended statistics, or a generated column computed from it; step 3a did not run, or not on every column), Hibernate Envers or Hibernate's own `@Audited` / `@Temporal` writing it, an association keyed on it, a trigger, a rule, a materialized view, a foreign key, a publication, a non-`pgoutput` logical slot, or a leftover audit or history table. The message names each object and prints the remedy; see "Every installation: what your entity tables must be" |
| `SHRED-CONFIG-001` naming an entity and a schema | a `@Shredded` entity's mapping names no schema. See "Every installation: name the schema your entities live in" above |
| `SHRED-SCHEMA-009` | mapping admission refused a `@Shredded` entity's table or one of its columns. The message names the entity, the column and the catalogue fact. The change most installations meet is the column-type rule, a tenant or subject column that is not `text`, `varchar` or `char(n)` (a `uuid` subject, for one); see "Every installation: what your entity tables must be" above. The refusal reads, with your entity and column in place of the angle brackets: `@Shredded entity <entity>: the subject column <schema>.<table>.<column> is of type uuid. This module compares tenant and subject columns against the request's string, and only text, varchar and char(n) compare that string as written: another type parses it (a uuid or a number, so one spelling of a subject clears another subject's index), truncates it (name, "char"), lets a cast the application's role owns decide the comparison (an enum), or has no comparison with a string at all. Map the tenant and subject columns as text, varchar or char(n). A UUID or numeric subject id is stored in a text column.` The remedy for a `uuid` column is `ALTER TABLE <schema>.<table> ALTER COLUMN <column> TYPE text USING <column>::text;`, and the mapping then stores the id as a string |

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

### Every installation with post-erasure hooks: records name every hook they wait for

From 0.2.0 the erasure's own record lists every registered `PostErasureHook` as pending, and a
retry of a `PARTIAL` erasure answers the hooks that record (or the latest record after it) left
pending or failed, by name. A name no registered hook carries stays outstanding, recorded as
`not registered; outstanding since record <n>`, and the erasure stays `PARTIAL` until a hook of
that name runs and succeeds. Removing or renaming a hook therefore never closes an erasure it
had not finished. A `PARTIAL` record written by 0.1.x names no hook; its retry runs every hook
registered now, as 0.1.x did. 0.1.x had no acknowledged copies, so no such record can be waiting
for one. Hook names must be non-blank and unique; startup refuses otherwise.

### Acknowledging a trigger, a publication or a slot

When a trigger on a blind-indexed table, a publication that publishes `UPDATE`, or a logical slot
with a plugin other than `pgoutput` must stay, name it with the hook that clears what it keeps:

```yaml
shredding:
  jdbc:
    acknowledged-copies:
      - kind: trigger              # trigger | publication | replication-slot
        schema: public             # trigger only
        table: customer            # trigger only
        name: customer_history     # as pg_catalog stores it: unquoted names in lower case
        cleared-by: historyIndexScrubber   # PostErasureHook.name(), required
```

Each entry WARNs at every startup. Every erasure is recorded `PARTIAL`, naming the object, until
the hook succeeds; a retry runs it again. An entry whose object does not exist or admits nothing
refuses startup (and an erasure, if the object is dropped later). Rules, materialized views,
foreign keys, statistics and audit or history tables cannot be acknowledged.

## If you use the core module directly, without Spring

`JdbcSupport.initializeSchema(DataSource)` is unchanged in signature and is how an owner-run
migration applies the schema. Two things to add:

```java
VerifiedSchema schema = JdbcSupport.verifySchema(runtimeDataSource).schema();
var keys = new JdbcKeyProvider(runtimeDataSource, schema, masterKey, random, clock);
var store = new JdbcErasureStore(runtimeDataSource, schema, chain, blindIndexColumns, residual);
// or, with acknowledged copies (entry n is named shredding.jdbc.acknowledged-copies[n]):
var store = new JdbcErasureStore(runtimeDataSource, schema, chain, blindIndexColumns, residual,
    CopySignatures.defaults(),
    List.of(AcknowledgedCopy.trigger("public", "customer", "customer_history", "historyIndexScrubber")));
```

Build `ErasureService` on that store, or on a wrapper that forwards `acknowledgedCopies()`: the
store refuses every erasure whose record does not name its acknowledged copies.

`JdbcSupport.runtimeRoleOwnsErasureTable` is removed. It had no `schemaname` predicate, so it
answered about whichever copy of `shredding_erasure` `pg_tables` listed first, and it tested
ownership of one table when owning one guard function is enough to replace every guard.
`verifySchema` replaces it and refuses rather than reporting.

## Rolling back

**0.1.1 cannot run against the schema these steps produce.** 0.1.1 runs its bundled schema script with
the application's own credentials at every boot, with no property to skip it. After steps 2 and 4 the
application role owns none of the tables or guard functions and holds no `CREATE` on the schema, so
that script fails (`permission denied for schema ...`) and the rolled-back application does not
start. Rolling back the jar alone is therefore not enough. Choose one of two ways.

**A. Boot 0.1.1 as the owner role.** Give the rolled-back application the owner role's credentials
(`spring.datasource.username` / `password`) for the time it runs 0.1.1. That role owns the objects
and the schema, so the boot script runs and no statement has to be undone; going forward again is
switching the credentials back. The role must be able to read and write your own business tables;
a role that cannot is the reason to use B.

**B. Undo steps 2 and 4 for the application role.** As the owner role or a superuser:

```sql
ALTER TABLE    shredding_data_key                     OWNER TO <application role>;
ALTER TABLE    shredding_erased_subject               OWNER TO <application role>;
ALTER TABLE    shredding_erasure                      OWNER TO <application role>;
ALTER TABLE    shredding_erasure_anchor               OWNER TO <application role>;
ALTER FUNCTION shredding_erasure_append_only()        OWNER TO <application role>;
ALTER FUNCTION shredding_erasure_anchor_monotonic()   OWNER TO <application role>;
ALTER FUNCTION shredding_erasure_anchor_append_only() OWNER TO <application role>;
GRANT  CREATE ON SCHEMA <schema> TO <application role>;
```

(If step 2 also moved the schema to the owner role, `ALTER SCHEMA <schema> OWNER TO <application
role>` instead of the last line works too; the test does not run that alternative.) Variant A, and
the seven `ALTER` statements plus the `GRANT` of B, were executed against a 0.1.x install that had
been upgraded by steps 2 to 5; 0.1.1's boot script then ran to completion.

**What both variants cost.** In both, the whole application runs as a role that can replace the
guards: 0.1.1 has one `DataSource`, so under A every query the application runs, and anything that
can make it run SQL, runs as the owner of the four tables, the three guard functions and the schema,
and under B the application role owns them again. In either case that role can disable the
append-only trigger or replace a guard function, and delete from `shredding_erasure`, so the
append-only erasure log and the erasure tombstone are advisory for as long as 0.1.1 runs. Record that
in your processing documentation for that window, and do not present the log as append-only to a
supervisory authority in it. The variants differ only in effort: A has no statement to undo, B
returns ownership with the statements above. Neither variant needs the 0.2.0 properties: 0.1.1 ignores them, and
tolerates the changed guard bodies, `ENABLE ALWAYS`, a column already changed to `text`, and a
schema already named in a mapping. To go forward again, repeat steps 2 to 7.
