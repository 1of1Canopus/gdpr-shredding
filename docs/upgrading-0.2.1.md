# Upgrading to 0.2.1

0.2.1 binds a `VerifiedSchema` to the DataSource it was verified on (finding C-PR-1).

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

## The jdbc package is sealed

The core jar now seals the package `com.housedevinci.shredding.adapter.jdbc`. A class of yours in
that package fails to load with `sealing violation` on a plain classpath. Do not declare classes
there. The seal is not enforced by Spring Boot's executable-jar launcher. Under it, a class you
place in that package could still build a `VerifiedSchema` on any DataSource. That is deliberate
application code, in the same trust class as a `KeyProvider` of your own. Do not do it.

## Equality changed

`VerifiedSchema.equals` and `SchemaVerdict.equals` now include the identity of the DataSource the
schema was verified on. Two verifications through two different DataSource objects are no longer
equal, even on the same database. Nothing in the module compares them; check your own code if it
does.
