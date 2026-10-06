# SECURITY-NOTES — GDPR Shredding

What this module protects against, what it does not, and what an operator has to do themselves.
Written for the person who will be asked, in an audit, "and how do you know the data is gone?"

Every finding below is a **residual**: documented on purpose, not engineered away, because the
alternative would be a control that cannot be made true. The security review's spec review of 2026-09-08 is the
source; the numbered controls it defines are implemented and tested (see `docs/index.md`).

## What crypto-shredding actually claims

Each data subject's personal fields are encrypted under that subject's own 256-bit data key. To
erase, the key row is deleted. The ciphertext stays where it is, so the audit row, the accounting
row and the foreign key all survive; the personal data in them stops being readable.

That is a claim about **future access to live systems and to data-at-rest copies**. It is not a
claim that no plaintext copy exists anywhere.

## Residuals

### Wrapped-key resurrection
An insider who can read the key table can snapshot it before an erasure and restore the row
afterwards. The ciphertext never moved, so the plaintext comes straight back. This is the honest
bound of the whole technique and no amount of engineering inside this library closes it.
`probe_a_wrapped_key_row_restored_after_erasure_decrypts_the_value` asserts exactly this behaviour,
so nobody can later claim otherwise. Mitigate it operationally: separate the database role that can
read `shredding_data_key` from the role that runs the application, audit reads of that table, and
put the master key somewhere the same person cannot reach (a KMS, which is a Pro adapter).

### Backups, PITR archives, WAL, replicas and logical decoding slots
A base backup taken before the erasure holds the wrapped key. So does every WAL segment covering
the period, every streaming replica that has not caught up, and every logical-decoding slot.
The erasure is complete **only at `erasedAt + shredding.erasure.backup-retention`**, and the
erasure record states that date so the proof of erasure can print it. Set that property to your
real retention, not to a number that reads well.

### MVCC dead tuples
`DELETE` marks the row dead; the bytes stay in the heap page until `VACUUM` reclaims them, and a
`VACUUM FULL` or a page-level forensic read can still see them. This is also why the erasure is a
plain `DELETE` and not "overwrite, then delete": under MVCC the overwrite writes a *second* tuple
holding the same key and reclaims nothing, so it buys an assurance it cannot deliver.

### JVM memory
Heap dumps, core dumps and swap hold unwrapped data keys and decrypted plaintext. Key material is
held as `byte[]` and zeroised after use, never as `String`, but the JVM may have copied a buffer
before the wipe. Disable heap dumps on production, or treat a heap dump as personal data.

### Cache window across a cluster
Erasure evicts the local unwrapped-key cache immediately and publishes an invalidation, but another
node can hold the key for up to `shredding.data-key-cache.ttl` (default 60s). That window is real.
The proof of erasure states it. Shorten the TTL if 60 seconds is too long for you; there is no
setting that makes it zero on every node at once.

### The blind index
`@BlindIndex` makes equality lookups possible on an encrypted column, and equality lookups are a
leak. Even truncated to `shredding.blind-index.bits` (default 64) and even without any key, the
index is an equality and frequency oracle: identical values collide, so an attacker with the table
learns which rows share a value and how common each value is. Over a low-entropy field such as an
email address a full-width index would be an offline dictionary outright. Two consequences:

- the index is a **prefilter**; the query path always re-verifies by decrypting the candidates;
- **an erasure nulls the erased subject's blind-index columns**, always, with no property to turn
  that off. An index that survives an erasure keeps the erased subject searchable and linkable for
  ever, which defeats the product.

Do not put a blind index on a field you do not actually query by.

**The tenant binding (S-7, S-13, design addendum 3).** An erasure request names one tenant and one
subject. For it to reach the data key, the ciphertext and the index, all three have to be under one
tenant, so:

- the index is derived under **that row's own `tenantColumn` value**, the one value the erasure's
  `WHERE` can match, read out of the state array by the property `tenantColumn` was resolved to at
  startup (`tenantColumn` is a *column* name; the resolution must find exactly one basic `String`
  property mapped to it on the entity's primary table, or startup is refused with
  `SHRED-CONFIG-001` naming what it found);
- a **write is refused** (`SHRED-UNVERIFIED-WRITE`) when that value is null or blank, or when it is
  not the tenant the indexed field's data key is derived under. A tenant column holding something
  other than the tenant the value's key is under is erasable under no keying this module could
  choose; refusing it loudly, naming both values, is the outcome. An application whose acting
  organisation differs from the owning one declares `@Shredded(tenant = ...)` as the owning one -
  what its tenant column holds - and that shape works;
- the erasure **reads the cleared columns back inside its own transaction**: an index still
  populated for the erased subject refuses the erasure (`SHRED-ERASURE-004`) instead of recording
  it, and an index under a different tenant value for the same subject id is a WARN with the count.

**The subject binding (S-20, design addendum 3 change 8).** The same three rules apply, word for
word, to `subjectColumn` — the other half of the erasure's `WHERE`. It is resolved to a property at
startup under the same rules (exactly one basic `String` property on the primary table, or
`SHRED-CONFIG-001` naming what was found; the entity's *identifier* is refused explicitly, because
it is not in the state array, does not exist yet under `GenerationType.IDENTITY`, and is not a
string); its value is read out of the row at write time; and the write is refused with
`SHRED-UNVERIFIED-WRITE` when that value is null, blank, or not the subject the indexed field's data
key is derived under. `@Shredded(subject = "#{customer.externalId}")` with `subjectColumn =
"customer_id"` — the subject one association away — is the ordinary shape that used to write an
index no erasure could reach, and it is now refused at the write, naming both values.

**The invariant, in one line.** For a row to be erasable by one request, the tenant and subject its
data key was derived under, the tenant and subject its index was derived under, and the values in
its `tenantColumn` and `subjectColumn` are one pair.

**Residual.** A row whose tenant column is changed by a bulk update outside Hibernate (JPQL or
native `UPDATE t SET tenant_id = ?`) fires no listener and re-derives nothing, so it keeps an index
derived under its former tenant; the erasure for its new tenant then refuses rather than reporting
success, and the erasure for its former tenant reports the leftover in the WARN above. A tenant move
made *through* Hibernate is refused outright: the tenant is bound into every stored value's header.
The same is true of the subject column, and for the same reason: the subject is in every stored
value's header, so `refuseIfSubjectMoved` refuses a move made through Hibernate, and a bulk update
outside it fires no listener.

### Which table this module's statements address (S-21)

Every statement this module builds for a user table — the blind-index `UPDATE`, the two read-backs
that verify it, the post-hoc header check, the `IDENTITY` rebind and the subject-immutability
`SELECT` — is addressed at the table the Hibernate persister maps, **schema and all**, taken from
the persister at startup and rendered quoted per part (`"app2"."note"`). It used to be derived from
`@Table(name = ...)`, which ignores `schema`: which table those statements hit was then decided by
the runtime connection's `search_path`, so a same-named table earlier on the path took every one of
them, and an erasure could clear a stranger's column and report success while the real index
survived. `@Table(schema = ...)` and `hibernate.default_schema` are both supported; a
catalog-qualified table, and a table or schema whose identifier is not folded lowercase, are refused
at startup with `SHRED-CONFIG-001` rather than addressed by a guess.

**A mapping that names no schema is refused at startup.** It used to be the intended property
("this module addresses the table Hibernate addresses"), and what it cost was measured: with no
`@Table(schema)` and no `hibernate.default_schema`, the blind-index `UPDATE`, the module's own
same-text read-back and the read-back Hibernate renders are all unqualified, a table of the same
name in a schema ahead of the real one on the role's path takes all three at once, they agree with
each other, and the erasure reports `COMPLETE` over untouched residue. Startup now refuses with
`SHRED-CONFIG-001`, naming the entity and both spellings of the remedy. It is also what makes the
one-statement window below possible: that window leaves no role-writable schema on the path, so the
relation in the framework-rendered statement has to come from the mapping, and inside the window an
unqualified relation is an error rather than a decoy read.

This module's own tables (`shredding_*`) are qualified to the schema verified at boot.

### Which column this module's statements address (S-22, S-24)

Every column identifier this module interpolates — the blind-index `UPDATE`'s three columns, the two
read-backs that verify it, the post-hoc header check, the `IDENTITY` rebind and the
subject-immutability `SELECT` — is a `ColumnRef` built in **one** place: from the Hibernate
persister's own selection expression for that property, parsed by Hibernate's static
`Identifier.toIdentifier`. It renders exactly what Hibernate renders — bare when the mapping is
unquoted, `"`-wrapped when the mapping quotes — and at startup both renderings, Hibernate's and this
module's, must reproduce the mapping's expression character for character or startup refuses.

It used to be a `String` taken from `@Column(name = ...)` or from `@BlindIndex(subjectColumn = ...)`,
lower-cased by a hand-written `unquote`, and then quoted by a hand-written `quote` in the starter and
not quoted at all in the erasure store. Three consequences, all of them silent:

- a subject column named `user` — a reserved word the mapping must quote — was interpolated as
  `WHERE user = ?`, which parses, compares the connection's *role name*, and matches nothing. The
  erasure cleared no row, its own read-back was built from the same text and agreed with it, the key
  and the ciphertext were destroyed, the record said `COMPLETE`, and the HMAC of the erased plaintext
  stayed in the table as a correlator;
- a quoted `"Owner"` and a plain `owner` in the same table fold to one name, so an erasure asked for
  one addressed the other: a bystander's index cleared, the victim's kept;
- a `@Shredded` column the mapping quotes was addressed as an identifier with the quote characters
  *inside* the name, which boots cleanly and fails on whichever row is written first (S-24).

**What the annotations mean now.** `@BlindIndex(subjectColumn = ...)` and `tenantColumn` are
**lookup keys**, not identifiers: they are matched **case-sensitively** against the text of each
mapped column and then thrown away. There is no case-insensitive second pass, and none may be added
— that fold is how the erasure came to address a different column in the first place. The refusal is
therefore the whole control: it lists the entity's mapped columns verbatim *with their quoting* and
names the ones that differ from the given text only by case. A key that matches one column exactly
while another column of the same entity differs from it only by case is also refused: which was meant
cannot be read from the text. `@Shredded`'s own column is never matched by text at all — it is
resolved from the property name.

**Refused at startup, each by its real reason** (`SHRED-CONFIG-001`): a `@Formula`, on Hibernate's
`isFormula()` flag and never on the shape of the expression (`@Formula("owner_id")` is a plain
identifier); a `Column.assignmentExpression`, by the round-trip assertion; a `@ColumnTransformer` on
the subject, tenant or index column, which mis-addresses **by value** what the others mis-address by
name — the identifier is plain, the column stores something else, `WHERE col = ?` matches nothing and
`SET col = NULL` is not what Hibernate would write; a `@JoinColumn` named as the subject or tenant
column, said to be an association rather than reported as an unknown column; a composite identifier;
a name carrying a `"` character, asserted on the *parsed* text; and any dialect that is not
PostgreSQL, since `ColumnRef` renders `"` and folds by PostgreSQL's rules and no others.

**`hibernate.globally_quoted_identifiers`.** Supported for columns, quoted or unquoted, reproduced
verbatim — including the `globally_quoted_identifiers_skip_column_definitions=true` pairing Hibernate
documents for JPA, which leaves column expressions unquoted at boot. `hibernate.auto_quote_keyword`
is supported the same way. For **tables** the rule is unchanged: supported when the quoted parts are
lowercase, refused at startup by `TableRef` naming the setting otherwise.

### The erasure verifies itself against something it did not build (S-22, addendum 4 §4.5)

An erasure's `UPDATE` and a read-back written from the same three identifiers share one weakness: if
the identifiers are wrong, both are wrong together and agree with each other. So after the `UPDATE`,
**unconditionally** — not only when nothing was cleared, because a mis-addressed *tenant* column
clears a subset rather than nothing — the erasure runs a residual **Hibernate renders from the entity
mapping**: subject and tenant as HQL parameters, the index column reached through the persister's own
property. Above zero refuses with `SHRED-ERASURE-004`, rolls the whole transaction back, destroys no
key and appends no record.

Row counts are never a refusal predicate. The `UPDATE` ends `AND <col> IS NOT NULL`, so its count is
a *subset* of the subject's rows: a nullable index, a row written before the column existed, or a
retry after a partial failure all give fewer cleared rows than rows, with nothing wrong.
`blindIndexColumnsCleared` is a diagnostic.

**The check runs on the erasure's own connection.** A `StatelessSession` opened with
`.connection(c)` shares this connection, therefore this transaction and this snapshot, and cannot
flush — so it can never write a blind index back after the clear, and a pool of one does not deadlock
against the advisory lock and `SELECT ... FOR UPDATE` this transaction already holds. It never calls
`beginTransaction()` or `commit()`: with a provided connection `isTransactionInProgress()` already
returns true, so nothing in the API stops a one-line "fix" that would commit a half-done erasure —
index cleared, key destroyed, no record appended. Closing the session calls
`resetConnection(initiallyAutoCommit)`, which is a no-op **only because** `JdbcSupport.inTransaction`
set `autoCommit=false` on this connection first; that dependency is load-bearing.

**Concurrency, stated as intent.** The one divergence left is a row committed for the subject *after*
the `UPDATE`'s snapshot. It carries a live index for a subject whose key is about to be destroyed, so
it **refuses** the erasure — under READ COMMITTED, REPEATABLE READ and SERIALIZABLE alike. That is
the intended answer, not a race to retry away.

**The erasure's isolation level is pinned per transaction, never per session (C-25-1, C-25-4).**
`SET TRANSACTION ISOLATION LEVEL READ COMMITTED` is the transaction's first statement, ahead of the
advisory lock, and the level is read back; a failure is `SHRED-SCHEMA-008` and nothing runs. Because
it is transaction-scoped the pool's idea of the connection's level is never dirtied and nothing is
restored: an application that sets `SERIALIZABLE` in its init SQL keeps it. A connection handed over
inside a caller's transaction is refused with the same code, untouched.

**Two entities cannot share one of these checks (S-22, addendum 4 revision correction, E-1).** The
check above is keyed on `(table, index column)` — deliberately not on the subject/tenant axis, since
that axis is exactly what a mis-addressed erasure gets wrong. Two entities mapped to the same table
that index the same physical column resolve to the same key; without a collision check the second
one silently overwrites the first, and the erasure of one entity is then verified with the *other*
entity's query — the one net addendum 4 built specifically because the erasure's own statements
cannot check themselves, pointed at the wrong subject column for one of the two. This module has not
been shown to erase that mapping correctly, so the constructor refuses at startup
(`SHRED-CONFIG-001`), naming both entities, the shared table and the shared column, rather than
keeping only one of the two independent read-backs. Widening the key to every column of the blind
index (table, index column, subject column, tenant column) was rejected: it would make the lookup
miss precisely when the erasure's own columns are wrong, turning a mis-address into "no entity
mapping is registered" — the wrong message for the right problem.

### An unquoted reserved-word column mapping must be refused at startup, not discovered erasure by erasure (E-2)

The round trip in `ColumnRefs.of` proves this module reproduces the expression Hibernate's mapping
holds; it says nothing about whether that expression survives being interpolated **unqualified**.
Hibernate's own SQL always qualifies a column with its table alias (`n1_0.user`), where PostgreSQL's
grammar allows a reserved word after the dot. This module's `UPDATE` and `WHERE` do not qualify, so a
bare reserved word there is parsed as the keyword itself — `user` as `CURRENT_USER` — and matches
nothing. The independent read-back (S-22, addendum 4 §4.5) still catches the miss and refuses the
whole transaction, so no key is destroyed and no record is falsely appended — but every erasure of
that entity then fails, forever, with `SHRED-ERASURE-004`, whose message blames "a trigger, a rule, a
rewriting view" and never names the mapping that actually caused it. An Article 17 request that
cannot be executed, mis-diagnosed as a database problem.

`ColumnRefs.of` now refuses at startup (`SHRED-CONFIG-001`) any **unquoted** `ColumnRef` whose text
folds to one of PostgreSQL's reserved key words, naming `Entity.property`, the column, and the fix
(`@Column(name = "\"user\"")`). This cannot break a working application: Hibernate itself cannot
*write* such a column unquoted (`INSERT ... (user, ...)` is a syntax error at `user`), so any
application in this state is already broken for writes — the mapping can only exist against a legacy
table written by something other than this application.

**The keyword list, and why it is not `Dialect.getKeywords()`.** Hibernate's dialect keyword list
mixes reserved and non-reserved words; refusing on it would refuse a column named `value` or `name`,
which is ordinary and works unquoted today. `PostgreSqlReservedKeywords` instead vendors PostgreSQL's
own two reserved categories — `pg_get_keywords()` catcode `R` ("reserved") and `T` ("reserved, can be
function or type name"), the classes that cannot appear as a bare `ColId`, the exact grammar position
an unqualified column reference occupies — generated against PostgreSQL 16.14, the version this
module's tests pin. The list is a resource file, checked against a recorded SHA-256 at class-init, so
a hand-edited or corrupted copy is refused rather than silently under- or over-refusing mappings.

### The startup listener check proves position, not survival of Hibernate's own defaults (S-11, accepted residual)

**What `ShreddingStartupCheck` does and does not prove.** It proves, against the live
`EventListenerRegistry` after the `SessionFactory` is built, that this module's listener is
registered on all eight event types it registers for and is in the position it registered for -
first for `PRE_INSERT`, `PRE_UPDATE` and `POST_LOAD`, last for `POST_INSERT`, `POST_UPDATE`,
`POST_DELETE`, `FLUSH` and `AUTO_FLUSH`. It does not prove that the listeners Hibernate itself
seeded are still there. This module composes its integrator last on purpose, so an integrator
composed earlier can call `registry.setListeners(type, ...)` and replace a group's prior contents -
Hibernate's own `DefaultFlushEventListener` among them - before this module registers at all; our
listener is then added to the emptied group and measures as correctly positioned, because position
is measured against what remains. No check this module can make from inside the same JVM closes
that, and none of its own controls is removed by it: this module's listener is always registered
after the wipe and its presence is checked. What is lost is Hibernate's own behaviour, which fails
loudly - not this module's own write- or read-path checks (control 20 and the read-path controls
above are unaffected by this residual, which is why it stays a residual and not a design stop; the
one control an earlier integrator's `FLUSH` wipe removes is Hibernate's own flushing, which is an
application that does not work rather than an erasure that does not erase). Integrators on the
classpath are inside the trust boundary; review them as you would any other code you run.
`CipherProbeEarlierIntegratorWipesHibernateDefaultsTest` demonstrates and asserts this: after
another integrator wipes `FLUSH`'s prior listeners, this module's own listener is still present and
still last on `FLUSH`, and the startup check therefore passes.

### The read path: the converter accuses, it never authorises (fifth pass, design addendum)

Five review passes found the same shape of defect in five different places — C-17, C-18, C-20, C-26,
C-33, C-39, C-40. Every one of them was the read path treating *the presence of thread-local state*
as *permission to return plaintext*, and every one of them broke the moment that state outlived its
owner: an `Error` unwinding past a `finally`, a transaction-completion callback clearing a bracket
that was still open, a pooled thread carrying a frame into an unrelated call. Re-accounting for the
ownership four times did not close the class. The sixth design removes the authority instead.

> **Ambient state may accuse. It may never authorise.**

`ShreddedConverter.convertToEntityAttribute` no longer returns plaintext. It decodes the header,
decrypts, files `(entity, field, tenant, subject, rowId, plaintext)` in the open read region, and
returns a **placeholder**. `ShreddingEventListener.onPostLoad` — the one hook that knows the row
(`event.getId()`, the persister, the session) — verifies and installs the real value over the
marker.

What that buys, structurally rather than by accounting:

- **No state ⇒ a refusal, not a value.** A decrypt with no open read region is
  `SHRED-READ-UNSCOPED`, thrown before anything is returned: a hand-written DAO, a bare
  `EntityManager`, a `Stream` drained after the repository call returned, an `@Async` continuation
  on another thread, a `StatelessSession` (which fires no `PostLoad` at all).
- **Stale state ⇒ at worst a refusal.** A frame entry carries the token of the region that recorded
  it, and a drain happens only under the region currently in force. Residue an `Error` unwound past,
  or a decode from before an erasure, is discarded rather than installed, and the load that asked
  for it is refused. That is what turns "a stale value of the same row" and post-erasure residue —
  a false proof that a value is still readable — into `SHRED-READ-UNVERIFIED`.
- **Nothing leaks even when everything leaks.** A region left behind by a `StackOverflowError` holds
  bytes that only a verified, row-matched install could ever have used. `try`/`finally` cannot
  survive stack exhaustion — the `finally` has to *call* the pop, and that call throws again (C-32
  proved it) — so the argument no longer rests on unwind cleanup at all.

**The row is now part of the identity (C-34, format `SH1` v2).** Tenant and subject were the finest
grain the header and the AAD had, so two rows of the *same* subject held interchangeable
ciphertexts: an attacker holding `UPDATE` copied row A's column into row B and row B displayed A's
value as its own, with no error anywhere. The row's identifier — its canonical, type-tagged column
encoding, never `Object.toString()`, which cannot tell a `Long 1` from a `String "1"` — is bound
into both. A copy between two rows of one person is `SHRED-ROW-MISMATCH`; relabelling the header to
claim the other row breaks GCM authentication instead. **A v1 header is refused, not read**: a
dual-format reader would let the same attacker strip the row binding by writing a v1 blob.

**No unbound header exists.** `RowId` refuses an empty and an all-zero value. Under
`@GeneratedValue(IDENTITY)` the identifier does not exist when the converter binds, so the insert is
bound to a random 128-bit *unbound intermediate* carrying a tag no real identifier's encoding can
equal, and `onPostInsert` rebinds it to the generated key in one `UPDATE`, in the same transaction,
over raw JDBC (`session.doWork` — neither the session query API nor `flush()` is supported inside
the action queue). An intermediate captured by change data capture, an `AFTER INSERT` trigger or a
physical replica between the two statements is therefore bound to no row and verifies nowhere. A
rebind failure throws out of the flush and aborts the transaction: a row left bound to an
intermediate would be permanently unreadable while looking, to every application-level check, like a
successful write. The cost is two `encrypt` calls per shredded column on an `IDENTITY` insert, so
two ticks of control 3's per-key encryption counter.

**The placeholder is never `null`, and never persistable.** A `null` placeholder is silent
destruction on the types that have no erased sentinel — `LocalDate`, `BigDecimal`, a JSON column: an
entity whose install never ran would hold `null` in the field *and* in the persistence context's
loaded state, and the next ordinary (non-`@DynamicUpdate`) UPDATE would write `NULL` over a live
ciphertext with nothing to notice it. Each type gets a non-null constant, **compared by reference
identity**, carrying 128 bits drawn once per JVM run and rendered as ASCII with no control character
and no `%`, `{` or `}`, so it is log-safe and an attacker holding `UPDATE` cannot store a value that
reads back as one — and an equal-but-distinct instance is not accepted either. Writing one back is
`SHRED-PLACEHOLDER-001`, checked in the converter and again on the state array in the `Pre*`
listeners, before the blind indexes are written.

**The listener is prepended.** Hibernate's own `PostLoadEventListenerStandardImpl` is what invokes a
user's `@PostLoad` methods and `@EntityListeners` beans. While this module's listener was appended,
every one of those callbacks was handed the placeholder — silently, and in exactly the place an
application computes a derived field or fires an event. `POST_INSERT` and `POST_UPDATE` stay
appended, because the post-hoc header check must see what actually reached the database.

**Verification runs before either install.** Every awaiting field is checked first; only then is
anything written into the entity and the `EntityEntry` loaded state, together. So a refused row is
left holding placeholders, and a first-level-cache retry that dodges the eviction yields the marker
rather than the value. The eviction (C-27) stays as the second line: `refuseLoad` evicts the
instance before the exception leaves the method, so a second read of the same id in the same
transaction is a real load through this same check. The security review's C-27 fix text also asked for the
transaction to be marked rollback-only; that half was tried and reverted: the security review's own
C-27 probes catch the refusal inside the transactional callback and assert on a plain return value,
and marking the transaction rollback-only would make every one of them fail on
`UnexpectedRollbackException` at commit instead, outside the try/catch that catches the refusal -
one cannot both swallow the exception and cause the commit-time one that rollback-only exists to
raise.

**Mappings that loaded-state mutation cannot survive are refused at startup**, read off the runtime
persister rather than the annotations — `@SelectBeforeUpdate` does not exist as an annotation in
Hibernate 7 at all, and optimistic locking and natural ids can both arrive through `orm.xml` or a
mapped superclass:

| Mapping | Why it cannot hold |
|---|---|
| optimistic locking `ALL` or `DIRTY` | the UPDATE's `WHERE` is built from the loaded state, so it would carry the installed plaintext against a column holding ciphertext, and no update would ever match its row |
| select-before-update | `getDatabaseSnapshot` runs the converters again but fires no `PostLoad`, so the snapshot is placeholders compared against plaintext |
| a `@Shredded` column in the natural id | natural-id resolution and its cache read the column outside any load event — and a natural id that is personal data cannot be an index key in the first place |
| a non-basic identifier, including a **single-column** `@EmbeddedId` | it passes C-38's column count check but has no canonical byte form to bind to, and a guessed row binding is no binding |

**A `@Shredded` field must never participate in `equals`/`hashCode`.** Between the converter and the
install the field holds the placeholder, so an instance put into a `HashSet` or used as a `HashMap`
key before the install is unreachable afterwards. Dirty checking is unaffected — the install writes
the entity field and the loaded state together. The rule is in `README.md` and `docs/index.md`, and
`FrameworkMatrixTest` makes it checkable.

**Cost.** `onPostLoad` issues no SQL at all: which fields owe a decode is decided by reading the
placeholder off the entity, not by a query. A 200-row page costs **one statement against the
entity's table**, down from 201 (200 per-row re-reads plus the list query), measured by counting
`prepareStatement` on the real `DataSource`. The remaining 200 statements in that measurement are
`FieldCipher.decrypt`'s per-decrypt key-state check against `shredding_data_key` — control 7's, and
older than this design: the data-key cache holds key *material*, never *authority*, so every decrypt
re-reads the row that says whether the key may still be used. Memoising it per transaction would
remove it, but caching authority is a security decision, recorded for
the security review rather than taken here.

The write path pays more, not less, and deliberately: `refuseIfSubjectMoved` runs on **every**
update rather than only when a fresh scope was pushed, and a post-hoc header check runs after every
insert and every update, re-reading what was actually written and comparing every header against the
`(tenant, subject, rowId)` the row was written under. A row written under a residual scope — the
shape C-41 demonstrated — is refused inside the same flush and before the commit, rather than left

### The write path settles a debt; it does not perform a check (S-1)

The per-row post-hoc check above is fail-open by nature: it reads the row back inside the flush that
wrote it, and with `hibernate.jdbc.batch_size` set the `INSERT` is still in the JDBC batch, so there
is nothing to read. It returned without checking anything, for every row of every batch, on an
ordinary performance property. The security review's probe committed three rows of plaintext personal data.

So the control is no longer that check. **A bind incurs a verification debt** on the session -
`(entity, table, id column, id, expected tenant/subject/rowId)` - and the debt is settled at every
point where the batch has demonstrably executed and the transaction has not yet committed: the end
of every flush and auto-flush, and `beforeCompletion`, which runs after Hibernate's own commit-time
flush and covers `StatelessSession`, which fires no flush event at all. **Settlement is total or the
transaction aborts:** a debt whose row cannot be read back, a stored header that disagrees, and any
debt still outstanding at completion are all `SHRED-UNVERIFIED-WRITE` before the commit. A write with
no transaction has no settlement anchor and is refused at bind time.

A configuration knob can no longer remove this control - it can only make it refuse. The property
is *no row commits whose stored header is not bound to that row's own id, subject and tenant, at any
batch size*, and it is measured on seventeen write paths in `BatchedWriteVerificationTest` rather
than argued.

**Cost.** One `SELECT` with an `IN` list per entity per flush, plus the per-row belt. The ledger
holds one small record per written row until the flush that wrote it ends, so a `StatelessSession`
import that never flushes carries one record per row until the transaction commits (#26).

A row deleted in the same transaction discharges its own debt: inside one flush Hibernate executes
insertions before deletions, so an insert-then-delete of one row would otherwise be settled against
a row that legitimately no longer exists.
sitting in another subject's erasure scope. A write scope is also tagged with its session and a
per-push token, `ShreddingContext.require` compares the entity name (ignoring it *was* C-41), and a
scope still live when the next bind starts is by construction residue and is dropped rather than
consumed.

**Why the read side is not "checked before the key store is touched" the way CIPHER-01's fix text
asks for.** A JPA `AttributeConverter` is handed nothing but the column bytes: no entity, no
session, no row. Checked against the actual Hibernate loader bytecode this module builds against
(`EntityInitializerImpl`, Hibernate ORM 7.4, not assumed): every attribute converter on a row has
already run by the time the *first* Hibernate listener fires for that row, `PreLoadEventListener`
included. There is no hook that fires before a converter runs on read, unlike the write path, where
`PreInsertEvent`/`PreUpdateEvent` genuinely do fire before the SQL binds. The read-side check is
therefore necessarily two-phase: decrypt happens, then the check happens, then the value reaches the
caller. Under this design the second phase is also the *only* phase that produces a value at all, so
the property CIPHER-01 asks for — a moved ciphertext is never displayed — holds by construction.
What does not hold literally is "before it touches the key store", which this SPI makes unreachable
for a converter-based design (CIPHER-01).

**What is still a residual.** `ShreddingReadBracketCustomizer` refuses startup outright when more
than one `EntityManagerFactory` bean exists, on the reasoning that a region cannot vouch for a
Hibernate session it does not know is instrumented. That is defence in depth, not the primary
control — the primary control is that a converter with no region refuses — and it could not be
exercised by its own integration test: registering a second `EntityManagerFactory`-typed bean the
ordinary Spring way trips Spring Boot's own `@ConditionalOnMissingBean` on its auto-configured (and
therefore instrumented) factory (C-20). Region residue has its own section below.

Probes: `CipherProbeFifthPassTest` (C-33 P1, C-34 P2, C-35 P3), `CipherProbeBracketUnwindTest`,
`CipherProbeEvictionTest` (C-36), `CipherProbeFrameTest`, `CipherProbeReadScopeTest`,
`CipherProbeMatrixTest`, `CipherProbeMatrix2Test`, `FrameworkMatrixTest`,
`LoadedStateHostileMappingsTest`, `FieldCipherRowBindingTest`, `EncryptedValueV2Test`, `RowIdTest`.

### Region residue: a leaked region costs a refusal, never a value (S-4, addendum 2)

A decrypt is served only inside a region opened by the bracketed entry that is doing the reading, on
the same thread. There are two entries and no third: the Spring Data repository proxy
(`ShreddingReadBracketCustomizer`) and `ShreddingContext.withReadBracket(...)`. Each stamps the
thread with a fresh **entry epoch**, each region records the epoch in force when it was constructed,
and every region access - file a decode, drain one, count what is pending, close the region -
compares the two **for equality**. Not for age: a region can carry an epoch newer than the thread's
(an inner entry whose region an `Error` left behind), and "older is residue" would authorise it.

Consequences worth knowing when operating this:

- A region opened by `ShreddingContext.openRegion()` outside either entry - it is public,
  `@Deprecated`, and there is no reason for an application to call it - carries the distinguished
  "no entry" epoch. It can never serve a decrypt, on a thread that never entered *and* from inside a
  repository call, which is the case that matters: a user `@PostLoad` method or an
  `@EntityListeners` bean opening one would otherwise take every remaining decode of that call.
- Entering discards any region on top left by a call that never closed its own, at `WARN` with the
  count and the first `entity.field`. That log line is the only moment an operator learns an
  undisciplined region existed; it is never silent. It never discards the caller's own live region,
  so nested repository calls work unchanged.
- `REGIONS` and the epoch are plain `ThreadLocal`s. They must never become `InheritableThreadLocal`
  and must never be copied by a task decorator: an inherited epoch would match an inherited region
  and authorise an `@Async` continuation, which today is refused for free.

**The residual, stated.** A read that opens no region of its own, on a thread where an `Error`
skipped exactly the frame that restores the epoch, and before the next entry, still sees a matching
epoch. It is the same window `ShreddingContext.popWrite`'s javadoc concedes for write scopes and
that `CipherProbeBracketUnwindTest` measures at 0/200. Its cost is bounded: an ownerless region can
serve nothing but this row's own current value, verified by `onPostLoad` against this row's tenant,
subject and identifier, with the per-decrypt key-state check still in force. **A leaked region costs
a refusal, never a value.** (#21, S-4.) Probes:
`CipherProbeRegionEpochTest`, `CipherProbeRegionResidueTest`, `CipherProbeBracketUnwindTest`,
`CipherProbeReadScopeTest`.

### A `@Shredded` field inside an `@Embeddable` or an `@ElementCollection` is not supported (C-29)

The forward field scan (`ShreddedModel.allFields`) walks an entity class and its superclasses only -
never into an `@Embedded` component's own class, and never into the element type of an
`@ElementCollection`. The reverse metamodel scan (`refuseUnmodelledShreddedConverters`) used to stop
at the same boundary: it inspected an entity persister's own top-level `BasicValuedModelPart`
attributes only, so a `@Shredded` field declared inside either shape was invisible in *both*
directions - fully encrypted on write (whichever field's converter happened to put the entity in the
model pushed the write scope for the whole state array), and never checked on read at all, because
it is not in the `fields` list `onPostLoad`, the `@Immutable` check and the secondary-table check
are all built from.

Fixed by recursing: `EmbeddableValuedModelPart` (an `@Embedded` component, or an `@ElementCollection`
of embeddables via its `PluralAttributeMapping`'s element descriptor) is walked one level deeper
instead of skipped. The fix does not try to make either shape work - a `@Shredded` field nested
inside a component or a collection is refused at startup, naming its dotted path (for example
`Vault.secrets.token`, or `VaultWithNotes.notes[].token`), the same way a class-level `@Convert` was
already refused. Move the field - `@Shredded`, `@Convert` and all - onto the entity itself.

Probes: `CipherProbeEmbeddableScanTest.probe_a_shredded_field_inside_an_embeddable` (the security review's own,
`@Embedded`) and `probe_a_shredded_field_inside_an_element_collection_of_embeddables` (the maintainers'
mandated companion, `@ElementCollection` of an `@Embeddable`, in its own package so it cannot
accidentally exercise the first fixture's violation instead of its own).

### A `@Shredded` converter on a plural attribute's index/map-key is refused, not silently unmodelled (C-37)

C-29's recursion into `PluralAttributeMapping` walked `getElementDescriptor()` only. The index
descriptor - the map key of an `@ElementCollection Map<K, V>`, or the position of an
`@OrderColumn`-backed list - is a separate `ModelPart` and was never walked, so a `ShreddedConverter`
reached through a map-key `@Convert(attributeName = "key", ...)` was modelled by neither the forward
field scan nor the reverse one and started up unrefused. It was not a leak - the first write failed
closed with `SHRED-CONTEXT-001`, and a read left the frame undrained - but the startup contract did
not hold: the application found out in production instead of at boot. Fixed by walking
`getIndexDescriptor()` too when non-null, refused the same way as the element shape.

Probe: `CipherProbeScanDepthTest.probe_a_shredded_map_key_in_an_element_collection_is_refused_at_startup`.

### A `@Shredded` entity with a composite identifier is refused at startup, not on the first read (C-38)

`onPostLoad` and `refuseIfSubjectMoved` both return early when `getIdentifierColumnNames().length !=
1` - the load-time per-row re-read and the update-time subject-immutability check are both built
around a single-column id. Before this fix, a `@Shredded` entity with a composite identifier
(`@IdClass` or `@EmbeddedId`) started up and was then unusable: every read of a row carrying a stored
shredded value was refused with `SHRED-READ-UNVERIFIED`, including rows the application wrote itself
and nobody touched, because `onPostLoad` never drains the frame; writes go the same way, because
`save`'s merge has to read first. Fail-closed, but discovered in production rather than at boot - the
same class of unsupported mapping as the `@SecondaryTable` split just above, which already refuses at
startup for the analogous reason. Fixed: `ShreddedModel.scan` now refuses at startup for any entity
with at least one `@Shredded` field whose identifier maps to more than one column, naming the entity.

Fifth pass, finding item 7: the refusal is now on the identifier *mapping*, not only its column
count. A single-column `@EmbeddedId` has exactly one identifier column and so passed the check above,
but it is not a basic value: its Java value is a component object with no canonical byte form
`RowId` could bind a stored value to, and a guessed row binding is no binding.

Probes: `CipherProbeCompositeIdTest.probe_a_composite_id_shredded_entity_is_refused_at_startup`,
`probe_a_moved_ciphertext_in_a_composite_id_entity_is_never_displayed`, and
`LoadedStateHostileMappingsTest.a_single_column_embedded_id_is_refused_at_startup`.

### The subject-immutability check refuses when its own read-back finds no row (S-21b)

`refuseIfSubjectMoved` (control 14) re-reads a row's own stored shredded columns by id, from
`onPreUpdate` only — Hibernate is issuing an `UPDATE` for a row it believes already exists. Before
this fix, `readStoredShreddedColumns` returning `null` for "no row at that id" was treated the same
as "every shredded column is null" (the legitimate early return, CIPHER-14): the caller returned
without comparing anything. A `SELECT` that cannot find the row it was asked to verify is not
evidence the check passed. Fixed: `refuseIfSubjectMoved` now refuses with `SHRED-UNVERIFIED-WRITE`,
naming the entity, the row id and the table it looked in, whenever the read-back finds no row. The
only legitimate "not found" for a `@Shredded` entity is a brand-new row on insert, which never
reaches this method — insert has its own path (`onPreInsert`/`onPostInsert`).

This module's own tables (`shredding_data_key`, `shredding_erasure`, `shredding_erasure_anchor`,
`shredding_erased_subject`) are addressed as `"<verified schema>"."<table>"`, and the comparison in
this read-back names `pg_catalog` for its operator — see "What qualification covers, and what it
does not".

Probe: `CipherProbeSubjectMovedNotFoundTest.probe_the_subject_immutability_check_refuses_when_the_read_back_finds_no_row`.

### `@Shredded` is not supported inside an entity inheritance hierarchy (S-23)

`ShreddedModel.allFields` walks an entity class and every superclass to find its declared fields, so
that it also picks up a `@MappedSuperclass`'s fields for the one concrete entity that maps them - the
supported way to share a `@Shredded` field across entities. Before this fix, the same walk also
picked up a field declared on an *entity* ancestor (the root of an `@Inheritance` hierarchy, `JOINED`,
`SINGLE_TABLE` or `TABLE_PER_CLASS`): the field is then scanned once per concrete entity that inherits
it, each time against the one converter the field declares, under a different `entityName` each scan.
No converter pair can satisfy every scan - `(Root, field)` is refused when the subclass is being
scanned, `(Subclass, field)` is refused when the root is - so the shape is refused every time, but the
refusal named the converter's declared entity/field pair as if a developer could correct it. They
cannot: entity inheritance with a `@Shredded` field anywhere in the hierarchy is not a supported
mapping, under any `@Inheritance` strategy, because this module keys a shredded field's subject/tenant
expression, its `@Immutable` check, its secondary-table check and `onPostLoad`'s field list by one
entity name, and an inherited field's column is shared by more than one.

Fixed: `ShreddedModel.scan` now refuses at startup, before the converter check runs, when a
`@Shredded` field's declaring class is not the entity being scanned and that declaring class is
itself `@Entity`-annotated - naming the ancestor, the inheriting entity, and pointing at
`@MappedSuperclass` as the supported way to share the field. A field inherited from a plain
`@MappedSuperclass` (not itself an entity) is unaffected: it is never scanned as `type` under more
than one `entityName`, so it never had this problem.

**Limitation, not fixed:** a `@Shredded` field declared on an entity that another entity in an
`@Inheritance` hierarchy inherits it from is refused, under `JOINED`, `SINGLE_TABLE` or
`TABLE_PER_CLASS`. Declare the field, its `@Convert` and its own converter directly on each concrete
entity instead, or share it through a `@MappedSuperclass` (not an `@Entity` superclass). Documented
in `docs/index.md`.

**Correction (0.2.0).** An earlier text of this note, and of `docs/index.md`, said a `@Shredded`
field was refused anywhere in such a hierarchy. The refusal above is what the code does: a field
declared on the concrete subclass itself is scanned once, under that subclass's own entity name, and
is supported. Mapping admission checks the subclass's own mapped table - the table every statement
this module builds for it addresses - and nothing else: for `JOINED` that is the leaf's table and
its own key column (a renamed `@PrimaryKeyJoinColumn` included), for `SINGLE_TABLE` the shared table,
for `TABLE_PER_CLASS` the leaf's own table.
All three are measured, booted and erased in the test suite. A `JOINED` root's
table is addressed by no statement of this module and is not checked, even when it names no schema:
Hibernate 7 drops the root from the read-back it renders when no root column is referenced, and if
a later Hibernate stopped doing so the read-back would fail inside its window and the erasure would
roll back whole (finding C-18-1).

Probe: `CipherProbeTenthPassTest.probe_a_shredded_field_in_an_inheritance_hierarchy_is_refused_by_its_real_reason`.

### The starter's Testcontainers suite: bootstrap dialect resolution under container-count load (S-25)

The starter's test suite starts one `PostgreSQLContainer` per test class (32 at the tenth pass, one
more added since) rather than sharing a container, so a full run brings up and tears down that many
containers. The security review's tenth pass could not reproduce it (three consecutive full runs, 289/289 green)
but ruled it "fix required, not accepted": "Unable to determine Dialect" is Hibernate failing to get a
bootstrap connection for dialect resolution, and under CI load one container not yet accepting
connections before Hikari's default 30s `connectionTimeout` would produce exactly that symptom on
whichever probe's context happens to start first.

Fixed, two parts, no design change: every probe application's properties now pin
`spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect` (or the
`DynamicPropertySource`/`registry.add` equivalent), so dialect resolution never needs a bootstrap
connection at all - it cannot race the container regardless of how slow the container is to accept
connections. Every `@Container static final PostgreSQLContainer` also now declares
`.withStartupTimeout(java.time.Duration.ofMinutes(2))` explicitly, rather than relying on
Testcontainers' own default, so a slow pull or a loaded CI host gets more room before the container is
declared unhealthy.

**Deferred, not a design stop:** collapsing the 32+ per-test containers onto one reused singleton
container (the Testcontainers singleton pattern, with a fresh schema per test class for isolation) was
the follow-up the security review suggested "if it fits in under two hours." It does not: every one of the 32+
files declares its own `@Container` field and builds its own `SpringApplicationBuilder` context: a
shared container would still need each test's Spring context isolated by schema or database name,
which is a cross-cutting change to every one of those files' bootstrap, not a two-hour patch.
Deferred rather than attempted narrowly.

### A `@Shredded` field must not be mapped `@Basic(fetch = LAZY)` (documented, not reproduced)

Lazy fetching of a basic attribute is inert in Hibernate without bytecode enhancement, and none of
this module's three POMs configure an enhancement plugin, so there is no path here to attack it
today. In an application that does enable enhancement, the column would be fetched on first getter
access - for an entity handed back from a repository call, that is *after* the read bracket has
already closed, so the converter would find no open read region and refuse with
`SHRED-READ-UNSCOPED`: reasoned to be fail-closed, not reproduced under a real enhanced build.
Documented as a residual rather than left silent: a `@Shredded` field must not be mapped lazily.

### `@Immutable` on a `@Shredded byte[]` field silently discards an in-place mutation (C-21)
Every `@Shredded byte[]` field must carry `@org.hibernate.annotations.Immutable` (CIPHER-16): without
it, Hibernate deep-copies the *converted* value to build its dirty-checking snapshot, calling the
converter a second time outside the write bracket and failing an `IDENTITY`-strategy insert.

That annotation is what stops the deep copy - and the deep copy it stops is also what Hibernate's
dirty checking compares the live array against. With no snapshot copy, `b.getPayload()[0] = x` (an
in-place mutation of the array the field already holds) is compared against itself on the next
flush and is never seen as dirty: no exception, no log line, no `UPDATE`. This is not a bug to
engineer away - doing so means deep-copying the array again, which reopens CIPHER-16 - it is the
permanent, documented cost of the annotation the module requires. The only way to change a
`@Shredded byte[]` field once `@Immutable` is present is to assign it a whole new array
(`setPayload(newArray)`), never to mutate the one already there. `probe_an_in_place_mutation_of_an_immutable_byte_array_is_silently_discarded`
(`CipherProbeMatrixTest`, renamed from `..._is_persisted` at C-31 - the old name promised the
opposite of what the assertion has always checked) asserts the trap is real, not that it has been
fixed.

### Erased subjects are tombstoned, and the tombstone holds no key material
`shredding_erased_subject` records `(tenant, subject, erased_at)` and nothing else. There is no key
in it, wrapped or otherwise: the key rows are deleted outright, exactly as control 6 requires, and
this table is not a copy of them.

It exists for one reason. A write that was merely blocked on the erasure's `SELECT ... FOR UPDATE`
resumes the moment the erasure commits, finds no key row, concludes the subject has no key yet, and
mints a fresh one - undoing the erasure inside a millisecond, with nothing in the erasure log to say
so. Found by `probe_concurrent_write_encrypts_under_a_destroying_key`. With the tombstone,
`JdbcKeyProvider.mint` refuses for an erased subject and the racing write fails with
`SHRED-ERASED-001`.

The tombstone is therefore part of what makes control 11 enforceable at all, not a weakening of
control 6. It does mean the set of erased subject ids is retained: an id, never a key, and the same
id the audit and accounting rows already carry, which is the whole point of the technique.

### The subject/tenant SpEL expression can still read `getClass()`
`SimpleEvaluationContext.forReadOnlyDataBinding()` blocks bean references, `T()` type references,
constructors and method invocation - all four verified live by
`probe_spel_expression_reaches_a_bean_or_a_static_type`, and RED when swapped for
`StandardEvaluationContext`. It still permits ordinary property navigation through `getClass()`
(`#{class.name}` resolves), because `getClass()` is a real, harmless JavaBean-style getter as far
as the evaluator is concerned. Not exploitable today: `@Shredded(subject=...)` and
`@Shredded(tenant=...)` are written by the application author in its own source, at compile time,
never supplied by configuration or by a request. This is recorded so that nobody later accepts a
subject or tenant expression from an external source - configuration, a request parameter, a
plugin - without revisiting this control (I1).

### What a proof of erasure attests
That a key was destroyed and when, chained and anchored so a later rewrite is detectable. It does
**not** attest that no plaintext copy exists in an application log, a CSV export, a search index, a
support ticket or a PDF the application itself produced. Those are the application's problem, and
`PostErasureHook` is the seam for dealing with them - which is why a failed hook makes the erasure
`PARTIAL` and never `COMPLETE`.

### Planner statistics are a copy of the blind index (SHRED-SCHEMA-010)

`ANALYZE` (autovacuum included) stores sampled values of every column in `pg_statistic`: most common
values and histogram bounds. `pg_stats` shows them to any role with `SELECT` on the column, and an
erasure's `UPDATE` does not touch them. Measured on PostgreSQL 16: the runtime role read 101 HMAC
values of a blind-index column back from `pg_stats`, an erased one among them, after the erasure
had cleared the row. `SET STATISTICS 0` alone stops future sampling and keeps the stored rows.

So mapping admission reads, for each blind-index column over the table and every partition and
inheritance child, each path by which statistics can exist, and refuses any of them with
`SHRED-SCHEMA-010` at startup and before every erasure's first statement:

- the column's statistics target is not 0 (PostgreSQL 16 stores the default as `-1`, 17 as `NULL`;
  `NULL` is not 0);
- `pg_stats` holds a row for it, `inherited` or not;
- an expression index computes over it, read from the stored expression tree (`pg_index.indexprs`),
  a whole-row reference included, or selects the rows it samples by it in its predicate (an
  expression index is sampled only from the rows its predicate selects). A plain partial index
  is admitted: PostgreSQL stores statistics for index expressions only (measured: 0 rows on 16 and
  17). A tree whose column references the reader cannot parse is `SHRED-SCHEMA-005`, never "reads
  nothing";
- an extended-statistics object covers it, by key or by expression (`pg_depend`; its data is
  invisible to a non-owner, so the check reads the definition);
- a stored generated column computed from it has any of the above. Measured on 16, 17 and 18: a
  `GENERATED ALWAYS AS (lower(email_idx)) STORED` column gets its own `pg_stats` histogram of
  derived values. A virtual generated column (18) stores nothing and cannot be given a target.

An expression index, an expression in extended statistics, or a stored generated column on the
table or a descendant (an expression index's predicate included) that calls a function or
operator outside `pg_catalog`, or one that is not immutable, is
`SHRED-SCHEMA-005`, whatever columns it names: the function body is invisible to the expression
tree, and an `IMMUTABLE` SQL function taking the row's identifier can return the blind index
(measured by the security review: the index's own `pg_stats` row held the index values while the
tree named only `id`). Not immutable covers `pg_catalog` too: `CREATE STATISTICS` accepts a
volatile expression, and `pg_catalog.query_to_xml` run from one stored every blind-index value in
`pg_stats_ext_exprs` (measured by the security review).

**A table with an ancestor is refused** (rule R-i, `SHRED-SCHEMA-009`). `ANALYZE` on a partitioned
or inheritance parent stores `inherited` statistics computed from every descendant's rows under
the parent's columns, readable by any role with `SELECT` on the parent, and the erasure's locks on
the child do not reach the parent (`ALTER TABLE ONLY <parent> ... SET STATISTICS` and `ANALYZE
<parent>` complete while an erasure holds the child, measured). Locking every ancestor would make
every erasure of every partition wait on the parent, so the shape is refused and the remedy is to
map the root, whose descendants the check already walks. A table cannot gain a parent during an
erasure: `ATTACH PARTITION` and `INHERIT` wait behind its locks (measured), and the next verdict
refuses.

**More than one parent is not supported** (R-i, security review C-24-9). A table holding
blind-indexed rows with two parents puts those rows into both parents' statistics, so mapping
either parent leaves the other holding the values. R-i therefore also refuses a mapped table any
of whose descendants, at any depth, inherits from a table outside the mapped hierarchy, naming
every parent. A second parent added after boot (`ALTER TABLE <descendant> INHERIT <other>`) waits
behind the erasure's locks, which recurse to descendants, and the next erasure refuses.

**A former parent keeps the values.** Detaching a partition, or `ALTER TABLE ... NO INHERIT`,
leaves the child's blind-index values in the former parent's `inherited` statistics, and `ANALYZE`
of the former parent does not clear them when it has no child left; autovacuum never analyzes a
partitioned table (measured by the security review). No catalogue trace links the former parent
to the table, so a detached table is admitted and this residue is the operator's to clear (upgrade
guide, step 1). For the same reason no refusal message offers either statement as a remedy.

The remedy the message prints is read with `search_path` pinned to `pg_catalog, pg_temp` and opens
with the same setting, so a view or policy re-created from it cannot re-bind a name to a
same-named object on the operator's path; a view under default privileges is named rather than
re-created, because `CREATE VIEW` would widen its grants.

A partition or child whose `pg_stats` rows the runtime role cannot see - no `SELECT` on the column,
or row level security that applies to the role, both of which `pg_stats` filters on - is
`SHRED-SCHEMA-005`.

The verdict cannot change under an erasure: `ANALYZE`, `ALTER COLUMN ... SET STATISTICS`,
`CREATE STATISTICS` and `CREATE INDEX CONCURRENTLY` take `SHARE UPDATE EXCLUSIVE` and `CREATE INDEX`
takes `SHARE`, all of which conflict with the erasure's locks on the table and its descendants.

Residuals, named:

- **Values written as literals into catalogue definitions** - an index predicate, a `CHECK`, a
  column default, a view's text - are operator-authored, never touched by an erasure, and not
  scanned by this module. The predicate-only partial index is admitted on that basis.
- **The superuser `pg_statistic` delete** that upgrade step 3a documents for 16 and 17 is the
  operator's statement, not the module's; the module's re-read at the next startup is the control.



The erasure's three legs - the blind-index `UPDATE`, the same-text read-back and the read-back
Hibernate renders - are built independently, but they all ask the entity's relation the same
question the same way. Six mapping shapes make all three agree on an answer that is false, measured
on PostgreSQL 16 with every name qualified and the window in force:

| the relation or column | what the three legs report | what is true |
|---|---|---|
| an auto-updatable view that hides the subject's row | 0 rows, cleared | the residue is in the base table |
| a row-level-security policy the runtime role is subject to | 0 rows, cleared | the residue is in the table |
| a foreign table over a remote view that hides the row | 0 rows, cleared | the residue is on the other server |
| `citext` tenant and subject | 0 rows, cleared | the application's own lookup finds the row |
| a domain carrying its own two-sided `=` (case-insensitive, say) | 0 rows, cleared | the same |
| a non-deterministic collation on tenant and subject | 2 rows cleared where 1 was asked for | another tenant's row was cleared |

Each was recorded `COMPLETE`. No comparison of counts can catch them: the residue is invisible to
every statement this module can issue through that mapping. The control is a refusal before the
first statement, from the one source the erasure does not share, the system catalogue.

**What is checked.** The relation must be an ordinary or partitioned table (`pg_class.relkind` `r`
or `p`); every partition and inheritance child, at every depth, must be one too, every leaf an
ordinary table and none temporary; the relation must not be temporary; the role must hold `SELECT`
and `UPDATE` on it; and if row level security is enabled the role must not be subject to it (it
owns the table and the table does not `FORCE` it, or the role has `BYPASSRLS`). The tenant, subject
and identifier columns must exist, their type (a domain chased to its base) must be a scalar base
type or an enum whose own default equality operator is `pg_catalog`'s, or that reaches one through
an implicit binary cast to a `pg_catalog` type whose own equality is (`varchar` does, `citext` does
not, because its own equality is read first), their declared type must carry no two-sided `=` of
its own outside `pg_catalog`, and their collation must be deterministic (a non-collatable type such
as `bigint` has none and is admitted). The tenant and subject columns must in addition resolve to
`text`, `varchar` or `char(n)` (below). Every blind-index column must exist, be nullable and not be
generated.

**Where it runs.** At startup, from an eager bean that runs after Hibernate's schema export, Flyway,
Liquibase and any `spring.sql.init` script: a table that is present and inadmissible fails the
context. A table that is absent at startup is a WARN naming the entity and the table, because a
table created after the application starts is an honest deployment. And again inside every
erasure's transaction, before the first statement that touches the table, with nothing cached: a
startup verdict is undone by one `ALTER TABLE ... RENAME` and one `CREATE VIEW` the runtime role is
allowed to perform. There, any refusal - absent included - is `SHRED-SCHEMA-009`, and no key is
destroyed, no index cleared and no record appended.

**The lock that keeps the verdict true until the `UPDATE`.** The erasure first takes `LOCK TABLE
... IN ROW EXCLUSIVE MODE`, the lock its `UPDATE` would take anyway, which conflicts with the
`ACCESS EXCLUSIVE` every way of dropping, renaming or replacing the relation needs; then `... IN SHARE
UPDATE EXCLUSIVE MODE`, which conflicts with `ATTACH PARTITION`, `DETACH PARTITION CONCURRENTLY`,
`CREATE TABLE ... INHERITS` and `ALTER TABLE ... INHERIT`. Without the second lock all four succeed
against the first, so the set of relations the `UPDATE` routes to could change after the verdict
described it - including gaining a foreign table over a hiding view. Measured on an ordinary table as
well as a partitioned one, which is why the second lock is taken on every table. Its cost: two
erasures of the same table run one after the other, and an erasure waits behind a manual `VACUUM`,
`ANALYZE` or `CREATE INDEX CONCURRENTLY` on that table. An erasure also waits behind an autovacuum run to prevent transaction ID wraparound, which, unlike an ordinary autovacuum, does not give way to a waiting lock, for as long as that run takes; while it waits it holds the subject's advisory lock and key rows, and later erasures of the same table queue behind it. Set a `lock_timeout` on the erasure's connection if that wait must be bounded. When that bound fires, or the database picks the erasure as a deadlock victim, the erasure is refused with `SHRED-ERASURE-LOCK-WAIT` (SQLState `55P03` or `40P01`): nothing is destroyed, cleared or recorded, it is not a key-store outage, and it can be retried. The application's own reads and
writes are not blocked. A `LOCK` that fails because the relation does not exist, is a foreign table, or may
not be locked by the role is the same refusal, reached one statement earlier.

**What it reads, and why that cannot be lied to.** Every statement is fully qualified and every
value is bound. The table and column texts go through `pg_catalog.parse_ident` in its strict,
one-argument form, which is PostgreSQL's own identifier folding and raises on text it cannot parse;
the relaxed form silently parses `app.t; DROP TABLE app.t` and is never used. Measured: the verdicts
are identical on a `search_path` where every function and operator the statements use has a lying
shadow ahead of `pg_catalog` and a relation of the same name sits in the first schema. A statement
that fails is `SHRED-SCHEMA-005`, never a pass.

**What it deliberately does not check.** The data. Triggers and rules on the table: one that undoes
the clearing leaves the index populated, both read-backs see it, and the erasure is refused with
`SHRED-ERASURE-004` - loud, so not an admission rule. The `@Shredded` data column's own type, which
nothing compares. Indexes, `CHECK` constraints and `NOT NULL` on tenant or subject. An unlogged
table, or an unlogged partition or child, is admitted with a WARN at startup: the erasure on it is
sound, and what a crash empties is the application's durability decision.

**Between a startup WARN and the first erasure.** On the one deployment the absent-table WARN exists
for - the table created after the context refreshes - the write path's three statements on the
application's connection (the `IDENTITY` rebind, the subject-immutability re-read and the
write-verification read-back) compare the identifier column with no verdict behind them yet. Each
fails loudly on the shapes above (a row count that is not 1), and the first erasure refuses until
the table is admissible.

**Tenant and subject columns are text-typed (clause C-i).** The erasure compares the tenant and
subject columns against the request's string. Only `text`, `varchar` and `char(n)` (the built-in
types, identified by oid, after following domains) compare that string as written, so those are
the only types admitted for them. Measured on the types the other rules admit: an enum's owner can
give it an implicit cast to `text` with its own function, after which the erasure, both read-backs
and the record agree on `COMPLETE` with nothing cleared; `name` and `"char"` truncate their input, so
a subject id longer than 63 bytes is never matched; `uuid` and numeric types parse the string, so
under `stringtype=unspecified` an erasure requested as `A0EEBC99-...` or `0042` clears the index of
the subject stored as `a0eebc99-...` or `42`, whose key survives, and under the driver's default
every erasure fails. A UUID or numeric subject id is stored in a text column. The identifier column
is compared with Hibernate's own typed binds and is held to the other rules only.

### Copies of the blind index outside the table (SHRED-SCHEMA-010)

Source: the audit-table coverage design (0.2.0 release-candidate findings RC-1, RC-2, RC-3). An
erasure clears the blind index in the admitted table and its partitions and children. A copy
anywhere else keeps the erased subject searchable with the application's own index secret, and the
record would say `COMPLETE`. Startup and every erasure refuse every copy the module can see: in
the mapping (Hibernate Envers, `@org.hibernate.annotations.Audited`, `@Temporal` history, an
association or element collection keyed on the column) and in the catalogue (any enabled trigger
or rule on the table or a descendant, a materialized view reading the column, a foreign key on it,
a publication carrying it, a logical slot of this database with a plugin other than `pgoutput`, a
leftover audit or history table found by name or by its revision columns). Nothing is
acknowledgeable in this release: a trigger the operator knows to be harmless must be disabled.

The catalogue check runs three times for each erasure's table: at startup, after the erasure's
locks, and after its `UPDATE` and read-backs. What remains:

- **The window between the last check and commit.** `CREATE MATERIALIZED VIEW ... AS SELECT
  <index>` and `CREATE PUBLICATION ... FOR ALL TABLES` are not blocked by the erasure's locks
  (measured). One created after the third check and before commit copies values from the last
  committed snapshot, which still holds the index this erasure is clearing. The next erasure of
  any subject on that table refuses. Measured on PostgreSQL 16: the third check refused a
  materialized view committed during the erasure 20 ms after it committed; an erasure with both
  checks takes about 55 ms on a small table, so the window is a few milliseconds.
- **Server logs with bound parameters** (`log_statement = all`, `log_min_duration_statement`,
  `auto_explain` with parameters, `pgaudit` with `log_parameter`) hold every index value written.
  Not visible in the catalogue; an operator setting.
- **A trigger on another table that reads this one.** A function body is not recorded in
  `pg_depend`, so nothing links it to the column.
- **`CREATE OR REPLACE FUNCTION`** of a function a disabled trigger names is not blocked by the
  erasure's locks; enabling the trigger is, and refuses the next erasure.
- **Values written as literals into catalogue definitions** (an index predicate, a `CHECK`, a
  column default, a view's text) are operator-authored, never touched by an erasure, and not
  scanned.
- **Operations, not structures**: `CREATE TABLE AS`, `SELECT INTO`, `INSERT ... SELECT`, `COPY
  TO`, `pg_dump`, an application's own code writing the value elsewhere, and a custom Envers
  `AuditStrategy` writing outside its audit table. No catalogue trace links them to the column.
- **`pg_temp` tables of other sessions**: session-lived and unreadable to this module.
- **Physical standbys, WAL archives and backups**: as in "Backups, PITR archives, WAL, replicas
  and logical decoding slots"; a logical slot with a non-`pgoutput` plugin is no longer a residual
  but a refusal.

## Threats the module does close, and how

| Threat | Control |
|---|---|
| Data key re-derivable from the master, making erasure a no-op | keys are 256 random bits, never derived (control 1) |
| Entity/field name collision in the AAD | length-prefixed canonical AAD (control 2) |
| Nonce reuse under one key | random 96-bit nonce, per-key counter, hard refusal at 2^32 and rotation (control 3). An `@GeneratedValue(IDENTITY)` insert encrypts each shredded column twice - once bound to the unbound intermediate, once to the generated identifier - so the counter advances twice per column on that path and rotations come twice as often for an `IDENTITY`-heavy workload |
| Plaintext fallback on an unrecognised column | strict format, typed error, no lenient parse (controls 4 and 17) |
| Master key in `/env`, `/configprops`, logs or `toString` | explicit exclusion, `byte[]` not `String`, never in a message (control 5) |
| Unprovable erasure or false proof | key deletion and the record in one transaction (control 6) |
| Key used after it was claimed by an erasure | state checked on read as well as write (control 7). Costs one `SELECT` against `shredding_data_key` per decrypt - 200 statements for a 200-row page, measured above under "Cost" - because the cache holds key *material*, never *authority* (the sixth pass): memoising this check per transaction would remove the statements but would cache authority, which is the one thing the read-path design took away from ambient state. Not removed. |
| Rewritten erasure log | module B's keyed-from-birth chain, anchor row, append-only triggers (control 8) |
| Enumerable subject hash in the log | HMAC pseudonym with an HKDF-separated pepper (control 9) |
| Erased subject still searchable | erasure nulls the blind-index columns (control 10) |
| Hibernate re-writing a shredded column on flush | write refusal plus a byte-identical sentinel round trip (control 11) |
| Second-level cache serving plaintext after erasure | startup refusal unless explicitly allowed (control 12) |
| Silent `null` reads | one policy per application, `null` requires an explicit property and WARNs (control 13) |
| SpEL reaching a bean or a static type | `SimpleEvaluationContext`, parsed at bootstrap (control 14) |
| Cross-tenant key reuse for the same subject id | tenant in the key PK, the wrap AAD, the value AAD and the index subkey (control 15) |
| KMS outage read as an erasure | `KEY_UNAVAILABLE` and `KEY_DESTROYED` are different failures (control 16) |
| Half-migrated plaintext column | core refuses it; the batch migrator is Pro (control 17) |
| Crypto supply chain | JDK only, no BouncyCastle, no provider install (control 18) |
| Erasure reported complete while work is outstanding | a failed hook makes it `PARTIAL` (control 19) |
| A batch size switching the write-side verification off | a bind incurs a debt the transaction cannot commit without settling; an unsettled debt is `SHRED-UNVERIFIED-WRITE` (control 20, S-1) |
| A racing write minting a fresh key for an erased subject | the `shredding_erased_subject` tombstone, holding no key material, protected by the same append-only triggers as the erasure log (CIPHER-04) |
| A write racing the *first* key mint for a subject surviving the tombstone | `pg_advisory_xact_lock(tenant, subject)` taken first, in the same transaction, by every path that mints or erases (CIPHER-03) |
| A decrypted value reaching a generated `toString` | a record entity fails startup; Lombok's generators are `SOURCE`-retained and cannot be detected at runtime, so the sample ships an ArchUnit rule for that case instead (CIPHER-06) |
| A ciphertext moved between two rows of the *same* subject displayed as the second row's own | the row's identifier is bound into the header and the AAD, format `SH1` v2; a copy is `SHRED-ROW-MISMATCH` and a relabelled header fails GCM authentication (C-34) |
| A v1 blob written over a v2 one to strip the row binding | v1 is refused, not read; the AAD layout version differs too, so the refusal is structural as well as checked (finding item 12) |
| An `IDENTITY` insert's pre-rebind bytes captured by change data capture, a trigger or a physical replica | the intermediate is a random 128-bit value under a tag no real identifier's encoding can equal, so it verifies against no row; a failed rebind aborts the transaction (finding items 5, 6) |
| An entity whose install never ran writing `NULL` over a live `BigDecimal`/`LocalDate`/JSON ciphertext on the next flush | the read placeholder is a non-null per-type constant compared by reference identity, and writing it back is `SHRED-PLACEHOLDER-001` (finding item 2) |
| A forged placeholder stored in the column so a read hands it back as an installed value | the marker carries 128 bits drawn per JVM run and is compared by identity, and the stored bytes are not `SH1` so the decode refuses first (finding item 3) |
| A user `@PostLoad` callback or `@EntityListeners` bean handed the read placeholder instead of the value | the module's `POST_LOAD` listener is prepended, ahead of Hibernate's own, which is what invokes those callbacks (finding item 8) |
| A refused row served intact from the first-level cache on the retry | verification runs before either install, so a refused instance holds placeholders, and `refuseLoad` evicts it as well (C-27, finding item 9) |
| A residual write scope pushed for one entity consumed by a bind of another | `ShreddingContext.require` compares the entity name, and a post-hoc header check after every insert and update refuses a row not bound to the scope it was written under, inside the same flush (C-41, finding items 13, 14) |
| An optimistic-lock, select-before-update or natural-id mapping making loaded-state install unsound | refused at startup, read off the runtime persister rather than the annotations (finding item 10) |
| A single-column `@EmbeddedId` slipping past the composite-id check and being bound to a guessed row identity | a non-basic identifier is refused at startup (finding item 7) |
| A ciphertext moved between rows, subjects or tenants displayed on read, or surviving its own subject's erasure | the row's stored header is checked against the row, on write and on read (CIPHER-01) |
| A repeat erasure of a subject with an outstanding `PARTIAL` reporting `COMPLETE` | the trail's actual last outcome is read back, and the hooks are re-run rather than assumed to have succeeded (CIPHER-02) |
| The unkeyed erasure log's pseudonyms computable from the module's own published constant | `shredding.subject-pseudonym.pepper` is a required secret whenever `unkeyed=true` (CIPHER-07) |
| A failed write leaving a stale tenant/subject on a pooled thread | the push is bracketed in `try`/`finally`, the stack is cleared at the transaction boundary by that session's own callback, and a scope still live when the next bind starts is dropped rather than consumed (CIPHER-08, C-41) |
| `sharedCache.mode=ALL` or the query cache serving plaintext after an erasure | the startup check reads the resolved JPA/Hibernate cache properties, not only the entity's own annotations (CIPHER-09) |
| An append-only trigger silently missing in a second schema on the same database | every guard resolves `tgrelid` against `current_schema()`, not a bare trigger name (CIPHER-05) |
| A scalar/`Tuple`/constructor-expression projection returning another subject's plaintext | the header-versus-row check moved into the converter, at the one place every decrypt goes through; a decrypt with neither a managed-entity read bracket nor an explicit read scope is refused (`SHRED-READ-UNSCOPED`, CIPHER-11) |
| A nulled subject-source column silencing the read-path check and letting a moved ciphertext through | an unresolvable subject on a row carrying any decoded shredded value is a refusal (`SHRED-SUBJECT-UNRESOLVED`), never a silent `return` (CIPHER-12) |
| A stale decoded-header entry from one read corrupting the next, unrelated load on the same thread | a frame entry carries the token of the region that recorded it, and a drain happens only under the region in force; a foreign-token entry is discarded and the load refuses (CIPHER-13, finding item 4) |
| The update-time subject-immutability check skipped because only the entity's *first* shredded column happened to be null | every shredded column of the entity is read and checked in one query; early return only when all of them are null (CIPHER-14) |
| An outstanding `PARTIAL` erasure hidden behind an earlier `COMPLETE` by a backwards application-clock step | `latestForSubject` orders by the log's own monotonic `seq`, never by `ts` (CIPHER-15) |
| `ShreddedBytesConverter` refusing its own entity's first insert under `@GeneratedValue(IDENTITY)` | the field is declared `@org.hibernate.annotations.Immutable`, which stops Hibernate deep-copying the converted value outside the write bracket; enforced at startup (CIPHER-16) |
| A mistyped subject expression (`#{#this}`, `#{#root}`) resolving to an identity hash and encrypting under a key nobody can ever ask an erasure for | `SubjectExpression` refuses a resolved value that is not a scalar type, and refuses an `Object.toString()`-shaped string (L12) |
| A repository `@Query`/interface projection, or a repository bound to a second, uninstrumented `EntityManagerFactory`, decrypting inside the read region with nothing that would ever verify it | the converter returns a placeholder, never the value, and `closeRegion()` throws `SHRED-READ-UNVERIFIED` if the region still holds an uninstalled decode, before the repository method's result reaches its caller (C-17, C-18, C-20) |
| A stale decoded-header entry recorded by one repository call surviving to be mistaken for a later, unrelated call's row | recording and draining happen against the region the *current* call opened, keyed by row as well as subject, and the region is checked and discarded when that call closes (C-22, C-26) |
| A column mapped by a `ShreddedConverter` through a class-level `@Convert(attributeName=...)` or an `orm.xml` mapping, invisible to the field-level `@Shredded` scan and so fully encrypted but never verified on read | `ShreddedModel.scan` walks the Hibernate runtime metamodel for every attribute whose converter is a `ShreddedConverter`, by whatever route, and refuses startup on any with no matching field-level `@Shredded` entry (C-19) |

## Operating notes

- **Back up the keys table separately from the data**, or use a KMS. A single backup that holds
  both is a backup that undoes every erasure it contains.
- **Run the application with a role that is not the schema owner, and do not let it run DDL.** The
  append-only triggers stop the runtime role from deleting or truncating the log tables; only the
  owner can disable a trigger. From 0.2.0 the application verifies this at startup and refuses to
  start if it does not hold. See "Database roles" below for the exact grants that role needs, and
  why leaving one out is not a smaller version of least privilege, it is a runtime failure.
- **Never store `shredding.erasure-log.hmac-secret` beside the datasource password.** If one
  compromise yields both, the chain key is not a second factor, it is decoration. Module B's rule.
- **Losing the master key erases everyone.** The startup health check reports whether it can unwrap
  a known key; wire it into your readiness probe.
- The erasure-log HMAC secret is **not** a data key and is **never** destroyed by an erasure.
  Destroying it would break the very record that proves the erasure happened.

### Database roles

The schema step (`schema-postgresql.sql`) must be applied **once, by an owner role**, or another
role that can create tables, functions and triggers. The application itself runs as a separate,
non-owner role, so that the append-only triggers on the log tables are load-bearing: an owner can
`ALTER TABLE ... DISABLE TRIGGER` or `CREATE OR REPLACE` a guard function into a no-op, and a
non-owner can do neither.

Until 0.1.1 that was advice the code made impossible to follow - the starter ran the schema DDL
with the application's own credentials on every boot, so the only role that could start it was the
owner. From 0.2.0 the application issues no DDL by default (`shredding.jdbc.initialize-schema` is
`false`), verifies the schema at startup instead, and refuses to start when the schema is missing,
wrong, unguarded, or when its own role could remove the guards. The upgrade steps for an existing
installation are in [docs/upgrading-0.2.0.md](docs/upgrading-0.2.0.md).

Grant exactly this, no more, with the module's schema on the `search_path` of whoever runs it (or
the names qualified):

```sql
GRANT USAGE                  ON SCHEMA <schema>                     TO shredding_app;
GRANT SELECT, INSERT, DELETE ON shredding_data_key                  TO shredding_app;
GRANT UPDATE (encryption_count) ON shredding_data_key               TO shredding_app;
GRANT SELECT, INSERT         ON shredding_erased_subject            TO shredding_app;
GRANT UPDATE (erased_at)     ON shredding_erased_subject            TO shredding_app;
GRANT SELECT, INSERT         ON shredding_erasure                   TO shredding_app;
GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor            TO shredding_app;
GRANT USAGE                  ON SEQUENCE shredding_erasure_seq_seq  TO shredding_app;
```

And take these away, which `GRANT` alone does not do:

```sql
REVOKE CREATE    ON SCHEMA   <schema> FROM shredding_app;
REVOKE CREATE    ON SCHEMA   public   FROM PUBLIC;   -- PostgreSQL 14 and earlier
REVOKE TEMPORARY ON DATABASE <db>     FROM shredding_app, PUBLIC;
REVOKE CREATE    ON DATABASE <db>     FROM shredding_app, PUBLIC;
```

Four of these are easy to miss, and each of them fails in a different way.

- **`shredding_erasure_seq_seq`.** `shredding_erasure.seq` is a `bigserial`; PostgreSQL names its
  backing sequence `<table>_<column>_seq`, so it is not covered by a table-level `GRANT ... ON
  shredding_erasure` at all. Without `USAGE` on it, every erasure write fails at insert time with
  `permission denied for sequence shredding_erasure_seq_seq` - the erasure never reaches the log,
  and the caller sees a hard failure rather than a silently missing row. `SELECT` on the sequence
  is deliberately **not** granted: no statement this module issues reads it.
- **`UPDATE (erased_at)` on `shredding_erased_subject`.** The application never issues an `UPDATE`
  against this table; the grant exists because minting a key takes `SELECT ... FOR SHARE` on it to
  serialise against a concurrent erasure, and PostgreSQL checks every row-locking clause (`FOR
  UPDATE`, `FOR SHARE`, `FOR NO KEY UPDATE`, `FOR KEY SHARE`) against the `UPDATE` privilege, not
  `SELECT`. A **column** grant is enough, and a table-wide one would let anything that took the
  role over rewrite a tombstone's tenant or subject.
- **`UPDATE (encryption_count)` on `shredding_data_key`.** The same shape and the same reason to
  keep it to one column: table-wide `UPDATE` would allow resetting the counter that drives
  `shredding.crypto.max-encryptions-per-key`, reopening a non-active key row, overwriting wrapped
  key material in place, or backdating a row - none of which the module ever does.
- **`TEMPORARY` and `CREATE` on the database.** These are not housekeeping. `TEMPORARY` lets the
  runtime role create `pg_temp.shredding_erasure` and, with unqualified SQL, divert its own appends
  into it; `CREATE` on a database is `CREATE SCHEMA`, which is the same attack with a permanent
  schema. From 0.2.0 every statement this module issues is qualified to the schema verified at
  boot, so neither buys a diverted write any more - but the privileges are refused at startup as
  well, because a role that holds them is one `SET search_path` away from shadowing anything else
  in your estate. **And the database must not be owned by the application role:** an owner
  re-`GRANT`s itself either privilege in one statement, so the `REVOKE` above does not bind it.
  Check with `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database();`.

The runtime role is never granted `DELETE` or `TRUNCATE` on `shredding_erasure`,
`shredding_erased_subject` or `shredding_erasure_anchor`, nor `TRIGGER` or `REFERENCES` on any of
the four tables. The append-only triggers refuse those statements from any role that holds the
privilege, but `TRIGGER` in particular is not covered by them at all: a non-owner holding `TRIGGER`
can add a trigger of its own to the erasure log.

A privilege can be held **directly, through a group role, through a predefined role such as
`pg_write_all_data`, or through `PUBLIC`**. An empty grep of your grant scripts therefore proves
nothing; check with `has_table_privilege('<role>', '<table>', '<privilege>')`, which is what the
startup verification uses.

### What startup verification does and does not prove

From 0.2.0, `ShreddingSchemaGate` refuses to start the application unless, in the schema
`current_schema()` resolves to: the four tables exist as permanent ordinary tables with exactly the
columns and constraints the bundled script creates; the erasure log's `bigserial` sequence is
present and owned by its column; the three guard functions exist with the **bodies from the bundled
script**, compared text for text, because `CREATE OR REPLACE FUNCTION` keeps the oid and every
identity check passes after a body swap; exactly the seven guard triggers exist, each pointing
through `tgfoid` at the right function, each at `ENABLE ALWAYS`, **each with no `WHEN` predicate
(`tgqual`) and no `UPDATE OF` column list (`tgattr`)** - a guard recreated `WHEN (false)` or
narrowed to one column is identical in every other column and fires never; there is no rewrite
rule, no row-level-security flag, no policy and **no inheritance child** on any of the four tables
(a child carries none of the parent's triggers while its rows are read and deleted through the
parent's name); and the runtime role is not
privileged in any of the senses above. A catalogue read this module cannot perform is a refusal,
not a warning: unverifiable is not clean.

Three things it does not prove, and they are named here rather than implied.

1. **It is a point in time.** An owner who disables a trigger or replaces a guard body at 03:00 is
   not noticed until the next restart. Periodic re-verification is future work; until then, audit
   `pg_proc` and `pg_trigger` from the owner's side and monitor DDL in the database audit log. The
   `REVOKE TEMPORARY`/`REVOKE CREATE` above are also grant-side, and a role that owns the database
   can restore them to itself after boot - which is why the verification refuses that role.
2. **`ENABLE ALWAYS` defends against a narrower actor than it looks.** It makes the guards fire for
   a replication apply worker, for a superuser session in `session_replication_role = replica`, and
   under `pg_restore --disable-triggers`. It does **not** defend against the table's owner, who
   needs none of those: `ALTER TABLE ... DISABLE TRIGGER` is already theirs.
3. **The expectation lives in the jar.** Guard bodies are compared against the bundled
   `schema-postgresql.sql`, so an attacker who can rewrite the deployed jar controls the
   expectation as well as the database. That, not "a guard body was rewritten", is what remains
   outside detection.

**The check does not ask the role it is judging.** A function name resolves along `search_path`
exactly as a relation name does, any role may run `ALTER ROLE <itself> SET search_path` (there is no
privilege to revoke), and an application role normally owns a business schema it can define
functions in. `pg_has_role`, `has_table_privilege`, `format_type` and `pg_get_constraintdef` written
bare are therefore predicates the subject of the check supplies the answer to. Verification's
transaction now pins its own `search_path` to `pg_catalog` for its own duration, reads the pin back
and refuses with `SHRED-SCHEMA-005` if it did not take, and every catalogue function, catalogue
relation and `regclass` cast carries a `pg_catalog.` prefix in any case - belt and braces, because
the pin is one statement a later edit can lose and a prefix is visible in every diff. The bundled
script and the erasure store's own `count(*)`, `now()` and `pg_advisory_xact_lock(...)` are
qualified for the same reason. **One leg is not covered and is named rather than implied:** the
Hibernate-rendered independent read-back is `count(*)` in HQL, which the framework renders
unqualified, so a role that defines its own `count` aggregate can make that one leg answer zero.
The erasure store's own same-text read-back runs over the same column in the same transaction, is
qualified, and refuses on its own.

### The health endpoint publishes the posture

`/actuator/health` gains two details from the gate's verdict rather than re-deriving them:
`schema`, the schema that was verified, and `runtimeRolePrivileged`, `yes` or `no`.

`runtimeRolePrivileged: yes` is a one-word statement that this application's append-only controls
are advisory - useful to an operator, and equally useful to anyone else who can read it. Health
details are hidden by default in Spring Boot; keep them that way on any endpoint that is reachable
without authentication. If you set `management.endpoint.health.show-details`, set it to
`when-authorized`, not `always`, and put the actuator on a port your ingress does not publish.

### What qualification covers, and what it does not

Every statement this module issues names its relation as `"<verified schema>"."<table>"`, so none
of them depends on `search_path` at parse time. Relation names are not the only names a statement
resolves, and from this release they are not the only ones qualified.

**Operators, functions, aggregates, types and casts.** A `search_path` decides an *operator* name
exactly as it decides a relation name, and order is no protection: PostgreSQL ships no `=` with
`varchar` on either side, so an `=(varchar, varchar)` created by a role in a schema it owns is an
exact-type match and is selected at step 2 of operator resolution whatever the path order. Measured:
with such an operator answering `false`, an erasure recorded `COMPLETE` with `keysDestroyed = 0`
while the data key was still in the table. Every operator in every statement this module builds is
now written `OPERATOR(pg_catalog....)`, every function and aggregate `pg_catalog....`, every cast
`::pg_catalog....`; the same holds in the bundled `schema-postgresql.sql`, which has no pin
available at all (an unqualified `CREATE TABLE` targets `current_schema()`, so `pg_catalog` cannot
be put first there), and in the three statements the starter builds on the application's **own**
Hibernate connection — the `IDENTITY` rebind, the subject-immutability re-read and the
write-verification ledger's read-back. Those three get qualification and no session mechanism, on
purpose: a transaction-local `set_config` there would re-point every later statement of the
application's transaction, including statements of entities this module knows nothing about.

Because `OPERATOR(...)` erases precedence — every qualified operator takes one generic precedence —
an expression with more than one operator token is fully parenthesised, and a drift gate in the test
suite refuses an unparenthesised pair.

**The guard functions resolve names only in `pg_catalog`.** A guard function is not `SECURITY
DEFINER`, so without a `search_path` clause its body resolves its operator names in the session of
whoever writes to the table — the session of the role the guard exists to constrain. Measured: a
role holding exactly the grant block below, owning nothing in the schema, rewrote the erasure
anchor's `row_count`, `head_hash` and `keyed` past the monotonic guard with three operators it
defined in its own schema. From this release the three guard functions carry
`SET search_path = pg_catalog, pg_temp`, their bodies are written with `OPERATOR(pg_catalog....)`
and explicit parentheses, and startup verification requires **both**: the body text against the
bundled script and `pg_proc.proconfig` against exactly `{"search_path=pg_catalog, pg_temp"}`. Each
is the other's backstop — `CREATE OR REPLACE FUNCTION` with no `SET` clause clears `proconfig` with
no error, which is what the exact comparison catches, and the clause says nothing about a name a
later edit adds, which is what the body comparison catches. A mismatch is `SHRED-SCHEMA-003` and
the remedy is to re-apply `schema-postgresql.sql` as the owner.

**The one statement a session still resolves, and the window it runs in.**

Exactly one statement of an erasure is not covered by qualification the way the rest are: the
**independent** blind-index read-back is rendered by Hibernate from the entity mapping, and HQL
offers no way to write `pg_catalog.count(*)` or an `OPERATOR(pg_catalog....)` comparison - there is
no name in that text for this module to qualify. It runs with the connection's `search_path`
**replaced** by `pg_catalog, pg_temp` for the width of that one statement and restored immediately
afterwards. For this leg the window is the only mechanism there is.

The **cross-tenant WARN** read-back is written by this module and every name in it is qualified:
`(<tenant> IS NULL OR NOT (<tenant> OPERATOR(pg_catalog.=) ?))` (finding C-A-6), over a two-part
relation. It runs **outside** the window (finding C-18-6): the session's path decides nothing in it,
so a window there could change no answer any test can observe, and a module-written statement
inside one would be held to a weaker reading of the name gate. An earlier spelling reached the
type's own equality through a grammar keyword, which has no `OPERATOR(pg_catalog....)` form, and the
window was first built around that. The tenant column is nullable, so a bare
`OPERATOR(pg_catalog.<>)` is not equivalent - `NULL <> ?` is `NULL`, which would drop exactly the
rows this WARN exists to find - and the spelled-out form above is equivalent for the non-null bound
value this always passes. What is at risk is the accuracy of a `WARN` line and never the erasure's
verdict: every refusing leg on the same column is qualified.

A replacement rather than a prefix, because order is not a defence: PostgreSQL ships no `=` with
`varchar` on either side, so an `=(varchar, varchar)` a role creates in a schema it owns is an exact
match and wins at step 2 of operator resolution whatever the path says. Only removing that schema
from the candidate set changes the answer. The window is six statements — capture, pin, read the pin
back, the statement, restore, read the restore back — because a pin that is not read back is a
fiction: in auto-commit `set_config(..., true)` returns the pinned value while the next statement
sees the old path, so an auto-commit connection is refused outright with `SHRED-SCHEMA-008`. The
restore **binds** the captured bytes: a role may put a quote and a statement terminator in its own
`search_path`, and a restore composed into statement text then leaves the control off and sends
attacker-supplied text as a second statement. A failure inside the window propagates itself with the
refused restore attached as suppressed, never replaced by an isolation code.

`SHRED-SCHEMA-008` is the only `SHRED-SCHEMA-*` code that is never a startup condition and never
means "re-apply the script": it means the connection was in auto-commit, or something moved
`search_path` inside the erasure's transaction. The erasure's whole transaction rolls back — no key
destroyed, no index half-cleared, no record appended.

**The window is one statement wide, and that is a property, not a style.** The erasure's own
`UPDATE` runs outside it, on the path the transaction arrived with, with every name in it qualified
by this module — so an application trigger whose body names a relation unqualified would still fire
and still succeed. Since 0.2.0 no enabled trigger on a blind-indexed table is admitted at all (see
"Copies of the blind index outside the table"); the property matters again once a trigger can be
acknowledged with the hook that clears what it copies. A window around the whole transaction would break that application. The test suite's
name gate checks the invariant: it refuses any statement of this module's own inside a window.

**The window needs the relation to come from the mapping, which is why startup refuses a
schema-less one.** Nothing role-writable is left on the bracketed path, so a relation name that is
not qualified cannot resolve in there at all. Keeping the application's own schema on the bracketed
path so an unqualified name still resolved would put that schema back in the candidate set and
re-open the operator-shadowing hole verbatim. The two controls are therefore one: the startup
refusal below, and this window.

**What a `SELECT` can still run inside the window.** Mapping admission (section above) refuses an entity
mapped to a view and a table whose row-level-security policy applies to the runtime role, so neither
a view's functions nor a policy's run in the window of an admitted erasure. A function a policy
calls on a table the role owns without `FORCE ROW LEVEL SECURITY` is not run either, because the
policy does not apply to the owner. What is left is the mapping's own SQL:
the text of a `@SQLRestriction` and of every auto-enabled `@Filter` condition on a `@BlindIndex`
entity is rendered by Hibernate into the windowed read-back, and an unqualified function, relation or
non-keyword type name in it does not resolve there. That is the commoner case, and it makes every
erasure of that entity fail, loudly and with the transaction rolled back whole (the data key is
still present afterwards), while the application itself reads and writes the entity normally. The
remedy is to schema-qualify every function, relation and non-keyword type those fragments name, for
example `@SQLRestriction("public.pr18_visible(owner_id)")`; a qualified function whose body resolves
names at run time needs the remedy below as well. A string-body `LANGUAGE sql` function (`AS $$ ... $$`) is parsed again each time it runs, on the
path in force then, so inside the window it behaves exactly like a plpgsql function and fails with
`relation "..." does not exist`. Only a SQL-standard body (`BEGIN ATOMIC ... END` or `RETURN ...`,
PostgreSQL 14 and later) binds its names when the function is created and is unaffected. If you
have a function of either kind that names something unqualified, give it its own clause:
`ALTER FUNCTION <fn> SET search_path = <schema>, pg_catalog` (the same mechanism this module gives
its own guards), or rewrite it with a SQL-standard body. The failure mode is availability of that one erasure, fail-closed, and it is
reported with the database's own message.
- The **mapping admission** - whether the relation a `@Shredded` entity names is a table this
  module can address and whose compared columns compare the way the application's own do - is read
  from the catalogue at startup and inside every erasure. See "Mapping admission" above.
- The application's **own** tables are reached through the entity mapping, and this module does not
  validate their contents on your behalf: the role owns its own data tables and can drop them, and
  that is not a control a library can hold. What is closed is the module's three legs and
  Hibernate's rendering disagreeing about *which* table they are talking about — the mapping must
  name a schema (`hibernate.default_schema`, or `@Table(schema = ...)`) or startup refuses.
- A `search_path` is still the operator's to set, and nothing here depends on it being sane. What
  these changes remove is the module's *dependence* on it.

