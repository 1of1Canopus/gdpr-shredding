# Security review - branch `docs/runtime-role-grants`

## 2026-09-26 - first pass (head 694def3)

Scope: PR 12, documentation only. `SECURITY-NOTES.md` gains a "Database roles" section with a
`GRANT` block for the application's runtime database role; `CHANGELOG.md` gains the matching
Unreleased entry. No file outside those two changed (`git diff --name-only origin/main...HEAD`
returns two paths, both `.md`), so the Java tree is byte-identical to `main` and the build and test
numbers are `main`'s. The Maven build was not re-run and no existing `CipherProbe*` test was
re-executed on this branch; a docs-only diff cannot change them, and none is claimed as passing
here.

Method: the block was not read, it was executed. A throwaway PostgreSQL 16 container (the digest
the module's own tests pin), the bundled `schema-postgresql.sql` applied by an owner role, a second
non-owner role granted **exactly** the five lines extracted mechanically from the `sql` fence of the
new section, then every SQL statement the module's JDBC adapters issue - grepped out of
`JdbcKeyProvider`, `JdbcErasureStore`, `JdbcSupport` and the blind-index clear path - run as that
role, plus the statements it must not be able to run. 28 adapter statements allowed, 20 refusals
confirmed, one failure. Probe: `cipher-probe-pr12-runtime-role-grants.sh` (internal).

### Verdict: NOT MERGEABLE

`C-12-1` is HIGH: the role the section prescribes cannot start the application, and the only role
that can start it is the one the module's own startup check warns about. The grant block itself is
close to right - every adapter statement runs under it, and both of the "easy to miss" grants the
section calls out are real, reproduced here - but the section presents a procedure that does not
work end to end, and the four over-grant findings contradict its own "Grant exactly this, no more".

### C-12-1 (HIGH, DESIGN STOP) - the prescribed non-owner role cannot start the application

The section tells the operator to run the application as a non-owner role with those five grants.
`ShreddingAutoConfiguration` calls `JdbcSupport.initializeSchema(dataSource)` unconditionally, on
the application's own `DataSource`, in two bean factory methods (`shreddingKeyProvider`,
`shreddingErasureStore`). There is no property and no condition guarding it. The bundled schema
needs privileges no grant can supply to a non-owner:

```
# runtime role, exactly the documented block
ERROR:  permission denied for schema public          (schema-postgresql.sql:45, CREATE TABLE)
# same role, with CREATE ON SCHEMA public additionally granted
ERROR:  must be owner of table shredding_data_key    (schema-postgresql.sql:47, CREATE INDEX IF NOT EXISTS)
```

`CREATE INDEX IF NOT EXISTS` and `CREATE OR REPLACE FUNCTION` both require ownership of the existing
object, so the "just grant CREATE" workaround is closed too (verified: a non-owner holding CREATE on
the schema is still refused `CREATE OR REPLACE FUNCTION shredding_erasure_append_only()` with
`must be owner of function`). The predictable operator response to a context that will not start is
to run as the owner, and an owner does `ALTER TABLE ... DISABLE TRIGGER ALL` and then deletes from
the log - verified in the same container: the triggers refuse the owner's `DELETE` and `TRUNCATE`
until the owner disables them, after which the delete succeeds. Control 8 (append-only erasure log)
therefore holds in no configuration an operator can actually run through the starter, which is the
module's shipped integration path. The core module used directly is unaffected: a caller that runs
`initializeSchema` once as the owner and then hands the adapters a non-owner `DataSource` works -
all 28 adapter statements pass under the documented block.

This needs a mechanism, not a paragraph, so it is a design stop rather than a fix list entry. The
property that must hold: **the role that runs the application never needs DDL privileges, and a
schema that has not been created by a privileged role is refused at startup rather than created.**
The paths it must cover: `shreddingKeyProvider`, `shreddingErasureStore`, and any other bean or code
path that reaches `JdbcSupport.initializeSchema`; the presence of all four tables, the sequence, the
two guard functions and the seven triggers; and `current_user` not being the owner. Secure default =
the application does not run DDL; the convenience mode (create the schema on boot, which implies an
owning role) is the explicit property and WARNs at every startup. Owner: the builder; one page,
reviewed before any code is written.

### C-12-2 (LOW) - `SELECT` on `shredding_erasure_seq_seq` is over-granted

No adapter statement reads the sequence. `shredding_erasure.seq` is a `bigserial`, so the insert
calls `nextval`, which needs `USAGE` alone. Verified: with `SELECT` revoked from the sequence, the
anchor advance and the log append with `RETURNING seq` both still succeed; the only statement the
grant enables is `SELECT last_value FROM shredding_erasure_seq_seq`, which no adapter issues.

Fix: in `SECURITY-NOTES.md`, "Database roles", change the line to
`GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO shredding_app;`.

### C-12-3 (LOW) - table-wide `UPDATE` on `shredding_data_key` is over-granted

`JdbcKeyProvider.recordEncryptions` is the only statement that updates this table and it touches
one column, `encryption_count`. The documented table-wide grant additionally lets the application
role, or anything that has taken it over, do all four of these (each verified as succeeding under
the documented block):

- `UPDATE shredding_data_key SET encryption_count = 0` - resets the counter that drives
  `shredding.crypto.max-encryptions-per-key`, so the rotation limit never fires;
- `UPDATE ... SET state = 'ACTIVE'` - reopens a non-active key row;
- `UPDATE ... SET wrapped_key = ...` - overwrites wrapped key material in place (the wrap AAD still
  binds tenant|subject|version, so this destroys rather than substitutes, but it is a write the
  module never makes);
- `UPDATE ... SET created_at = ...` - backdates the row.

A column grant is sufficient and was verified against every statement on the path:
`GRANT UPDATE (encryption_count)` still allows `recordEncryptions ... RETURNING encryption_count`,
`SELECT ... FOR UPDATE` on the key rows, the mint `INSERT` and the erase `DELETE`, and refuses all
four writes above with `permission denied for table shredding_data_key`.

Fix: `GRANT SELECT, INSERT, DELETE ON shredding_data_key TO shredding_app;` plus
`GRANT UPDATE (encryption_count) ON shredding_data_key TO shredding_app;`, with one sentence saying
`encryption_count` is the only column the module updates.

### C-12-4 (LOW) - table-wide `UPDATE` on `shredding_erased_subject` is over-granted

The section's reason for the grant is correct and was reproduced (see "not findings" below), but the
grant is wider than the row lock needs. Verified: with `GRANT UPDATE (erased_at)` only, the
`SELECT ... FOR SHARE` tombstone check and the tombstone `INSERT ... ON CONFLICT DO NOTHING` both
succeed, while `UPDATE shredding_erased_subject SET tenant = ...` is refused by privilege
(`permission denied for table shredding_erased_subject`) instead of relying on the append-only
trigger as the only line of defence.

Fix: `GRANT SELECT, INSERT ON shredding_erased_subject TO shredding_app;` plus
`GRANT UPDATE (erased_at) ON shredding_erased_subject TO shredding_app;`, and keep the existing
explanation of why any `UPDATE` privilege appears at all.

### C-12-5 (LOW) - the block is incomplete for any schema other than `public`

The five lines work in `public` only because PostgreSQL grants `USAGE` on schema `public` to
`PUBLIC` by default. Verified: the identical block applied to a second schema holding the same
tables gives the runtime role `ERROR: permission denied for schema shred2` on the first read. Two
further gaps in the same paragraph: the block's unqualified table names resolve against the
`search_path` of whoever runs the `GRANT`s, not the application's; and "no more" is only true from
PostgreSQL 15 on, since 14 and earlier leave `CREATE` on schema `public` granted to `PUBLIC`.

Fix: add `GRANT USAGE ON SCHEMA <schema> TO shredding_app;` to the block, state that the block is
written for the module's tables in the application's own schema and must be run with that schema on
the `search_path` (or the names qualified), and add the PostgreSQL 15 assumption with the
`REVOKE CREATE ON SCHEMA public FROM PUBLIC` remedy for older servers.

### C-12-6 (INFO) - the append-only refusal names the wrong table on the tombstone

Both tombstone triggers reuse `shredding_erasure_append_only()`, whose `RAISE` hardcodes the table
name, so a refused write on `shredding_erased_subject` reports
`ERROR: shredding_erasure is append-only (attempted UPDATE)`. Verified as the runtime role and as
the owner. The new section quotes exactly that line as its evidence for the tombstone table, where
it reads as a copy/paste error to any operator who checks, and during an incident it points the
responder at the wrong table.

Fix: in `schema-postgresql.sql`, change the `RAISE` to
`RAISE EXCEPTION '% is append-only (attempted %)', TG_TABLE_NAME, TG_OP;` (both the
`shredding_erasure_append_only` and `shredding_erasure_anchor_append_only` functions), and update
the quoted transcript in `SECURITY-NOTES.md`.

### C-12-7 (LOW) - the startup warning still prescribes the old, broken grant set

`ShreddingStartupCheck` tells the operator, in the log line that fires precisely when the
prescription was not followed, to "Run with a role that has only INSERT and SELECT on
shredding_erasure, shredding_erasure_anchor and shredding_erased_subject". After this PR that
instruction is known to be wrong - the same role also needs `UPDATE` on the anchor and on the
tombstone, `USAGE` on the sequence, and the key-table grants - and an operator who follows the log
line rather than the document lands in exactly the failure the PR documents. The comment above the
check repeats it.

Fix: in `ShreddingStartupCheck`, replace the enumeration with a pointer to the "Database roles"
section of `SECURITY-NOTES.md` (no grant list in the log line), and fix the comment at the same
place. Test: assert the warning text no longer contains an enumerated grant list.

### Attempted and closed without a code change (not findings)

- **`DELETE` on `shredding_data_key`.** Needed. `JdbcErasureStore` issues
  `DELETE FROM shredding_data_key WHERE tenant = ? AND subject = ?`; the erasure is a real row
  deletion, not an overwrite, and the statement fails without the grant. Not over-granted.
- **`UPDATE` on `shredding_erased_subject`.** The stated reason is accurate. With `SELECT` only,
  both `FOR SHARE` and `FOR KEY SHARE` on that table fail with
  `permission denied for table shredding_erased_subject`: PostgreSQL checks every row-locking
  clause against `UPDATE`, and there is no weaker lock that avoids it. C-12-4 narrows the grant to
  one column; it does not contradict the section's explanation.
- **"The triggers refuse those statements from any role including one that happens to hold the
  privilege."** True as written. The owner's `DELETE` and `TRUNCATE` on `shredding_erasure` and its
  `DELETE` on `shredding_erased_subject` are all refused by the trigger; only
  `DISABLE TRIGGER ALL` first lets the owner through, which is the point the surrounding paragraph
  makes.
- **Sequence reset by the runtime role.** Refused: `ALTER SEQUENCE ... RESTART` gives
  `must be owner of sequence`, and `setval()` gives `permission denied for sequence` even with the
  documented `SELECT` on it (`setval` needs `UPDATE` on the sequence, which the block does not
  grant).
- **Trigger removal or neutralisation by the runtime role.** All refused:
  `ALTER TABLE ... DISABLE TRIGGER` and `DISABLE TRIGGER ALL` give `must be owner of table`,
  `DROP TRIGGER` gives `must be owner of relation`, `SET session_replication_role = replica` gives
  `permission denied to set parameter`, `CREATE OR REPLACE FUNCTION` on a guard function gives
  `permission denied for schema public` (and `must be owner of function` once CREATE is granted),
  `DROP TABLE` gives `must be owner of table`.
- **Anchor rewriting by the runtime role.** The `UPDATE` privilege the block grants on the anchor is
  needed by the `ON CONFLICT DO UPDATE` append, and the monotonic trigger still refuses a head-hash
  rewrite that does not advance, a `row_count` rewind and any `keyed` flip. Verified.
