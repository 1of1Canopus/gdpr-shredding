# Upgrading to 0.2.1

0.2.1 binds a `VerifiedSchema` to the DataSource it was verified on (finding C-PR-1), and checks
on every connection that the DataSource still reaches the database it verified (finding C-PR-1b).

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
