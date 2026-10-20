# Upgrading to 0.2.1

0.2.1 binds a `VerifiedSchema` to the DataSource it was verified on (finding C-PR-1), checks
on every connection that the DataSource still reaches the database it verified (finding C-PR-1b),
and judges the role each pool logs in as, not only the role it switched to (finding C-PR-1c).

## If you use the starter's default beans

Nothing changes. The default `JdbcKeyProvider` and `JdbcErasureStore` already wrote through the
DataSource the schema gate verified.

## If you build `JdbcKeyProvider` or `JdbcErasureStore` yourself

`JdbcKeyProvider` and `JdbcErasureStore` have new constructors that take the schema and no
DataSource. Use them:

```java
// In Spring
var keys = new JdbcKeyProvider(gate.schema(), masterKey, random, clock);
var store = new JdbcErasureStore(gate.schema(), chain, blindIndexColumns, residual);

// Without Spring
VerifiedSchema schema = JdbcSupport.verifySchema(runtimeDataSource).schema();
var keys = new JdbcKeyProvider(schema, masterKey, random, clock);
var store = new JdbcErasureStore(schema, chain, blindIndexColumns, residual);
```

The old constructors still work when you pass the same DataSource object that was verified. They
refuse with `SHRED-SCHEMA-011` otherwise, and they are removed in 0.3.0.

If you see that code, your store was writing to a database the module never checked. Either verify
that database with `JdbcSupport.verifySchema` (its owner applies the schema first), or point the
store at the verified one.

A wrapper around the verified DataSource also refuses. Drop the wrapper: the stores open their own
connections, so a Spring transaction proxy buys nothing here.

A `KeyProvider` or `ErasureStore` you implement yourself is your code and is not checked by the
module.

The log line of the starter's gate covers the gate's DataSource only. A store on a DataSource you
verified yourself is covered by that verification call.

## Every connection is checked against what was verified (C-PR-1b)

The module now checks, on every connection it takes, that the connection reaches the same
cluster, database, schema and login role it verified at startup. A DataSource that routes,
refreshes or is retargeted to another database is refused with `SHRED-SCHEMA-012`, and nothing is
written. Give the module a DataSource that always reaches one database. Failover to a physical
standby of the same cluster keeps working once the standby is promoted. A standby or read replica
that is still replaying is refused, for reads too: it can serve a data key the primary has already
destroyed.

The runtime role must be able to execute `pg_catalog.pg_control_system()`. PostgreSQL allows it
by default. If your database denies it, startup refuses with `SHRED-SCHEMA-005` and prints the
`GRANT` that fixes it. There is no mode that skips the check.

What it costs: one extra statement per write and per erasure. A read now runs in a short
read-only transaction of its own, so it pays one extra statement and a `COMMIT`. A read inside
your own transaction (Spring's `TransactionAwareDataSourceProxy` within `@Transactional`) runs
inside that transaction: the module does not commit it, roll it back or make it read-only.

A key write (creating, recording or rotating a key) does not run inside your transaction. It
needs its own, because it commits. A write on a connection that arrives inside your transaction
(the same `TransactionAwareDataSourceProxy` within `@Transactional`) is refused with
`SHRED-SCHEMA-008` before any statement, and your transaction is left as it was. Example: your
code inserts an order, then the first encrypted write for a new subject asks for a key. Before
this fix the module committed the order row, and your later rollback could not undo it. Now the
key write fails and your rollback works. Give the module's stores a plain `DataSource` (the
starter's default does), or request the key before you open your transaction.

Two smaller changes come with it:

- Verification sets its read-only `REPEATABLE READ` transaction with SQL (`SET TRANSACTION`)
  instead of `Connection.setReadOnly` and `setTransactionIsolation`. The connection's own settings
  are no longer touched. The module calls `setReadOnly` nowhere.
- `JdbcSupport.readVerified(VerifiedSchema, SqlWork)` is new and public, and `JdbcSupport.SqlWork`
  is now public. It is the starter's one way to read through the verified DataSource. You do not
  need it unless you write a component that reads the module's tables.

Example. A routing pool sends a call to the `reporting` database after startup:

```text
shredding: a connection from the verified DataSource no longer reaches what was verified at
startup (different: database; verified "app", got "reporting"). Nothing was written. ...
(SHRED-SCHEMA-012)
```

## The jdbc package is sealed

The core jar now seals the package `com.housedevinci.shredding.adapter.jdbc`. A class of yours in
that package fails to load with `sealing violation` on a plain classpath. Do not declare classes
there. The seal is not enforced by Spring Boot's executable-jar launcher. Under it, a class you
place in that package could still build a `VerifiedSchema` on any DataSource. That is deliberate
application code, in the same trust class as a `KeyProvider` of your own. Do not do it.

## Equality changed

`VerifiedSchema.equals` and `SchemaVerdict.equals` now include the identity of the DataSource the
schema was verified on, and the database it reached (C-PR-1b). Two verifications through two different DataSource objects are no longer
equal, even on the same database. Nothing in the module compares them; check your own code if it
does.

## The pool's login role is judged, and every role it can become (C-PR-1c)

The schema check now judges the role your pool logs in as, and every role it can become, not only
the role it switched to. A pool that logs in as the owner or a superuser and runs `SET ROLE` or
`SET SESSION AUTHORIZATION` in its init SQL is refused with `SHRED-SCHEMA-004`: any statement on it
can switch back. Log in as the runtime role, or as a login whose only membership is the runtime
role.

Startup also refuses when the login, or any role it is a member of (with or without INHERIT), is a
superuser, has CREATEROLE, is `pg_execute_server_program`, `pg_write_server_files` or
`pg_read_server_files`, holds any parameter grant (`GRANT SET` or `ALTER SYSTEM ON PARAMETER`), or
is a predefined role outside this list: `pg_signal_backend`, `pg_create_subscription`,
`pg_checkpoint`, `pg_use_reserved_connections`, `pg_stat_scan_tables`. In particular a runtime role
granted `pg_monitor`, `pg_read_all_stats`, `pg_read_all_settings` or `pg_read_all_data` refuses:
they can read other logins' passwords. Use a separate login for monitoring. The message names the
role and the membership; remove it with `REVOKE <role> FROM <member>`.

The check reads the login from `pg_catalog.pg_stat_get_activity`, which PostgreSQL lets every role
execute by default. If it was revoked, startup refuses with `SHRED-SCHEMA-005` and prints the
`GRANT`. On PostgreSQL 14 and earlier startup refuses with `SHRED-SCHEMA-005`: the module is
tested on 16 and 17.

Each store connection leaves one session setting, `shredding.login_checked`, on its server
backend. It records that the backend's login was checked, so the next calls skip that read. It
changes nothing else. `DISCARD ALL` and `RESET ALL` clear it, which only makes the next call read
the login again.
