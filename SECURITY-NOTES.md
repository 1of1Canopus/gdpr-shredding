# SECURITY-NOTES — GDPR Shredding

What this module protects against, what it does not, and what an operator has to do themselves.
Written for the person who will be asked, in an audit, "and how do you know the data is gone?"

Every finding below is a **residual**: documented on purpose, not engineered away, because the
alternative would be a control that cannot be made true. Cipher's spec review of 2026-09-08 is the
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

### The read path: the converter accuses, it never authorises (fifth pass, `docs/plans/read-path-design.md`)

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
transaction is a real load through this same check. Cipher's C-27 fix text also asked for the
transaction to be marked rollback-only; that half was tried and reverted, with the evidence in
`QUESTIONS.md` #19.

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
remove it, but caching authority is a security decision and it is recorded in `QUESTIONS.md` for
Cipher rather than taken here.

The write path pays more, not less, and deliberately: `refuseIfSubjectMoved` runs on **every**
update rather than only when a fresh scope was pushed, and a post-hoc header check runs after every
insert and every update, re-reading what was actually written and comparing every header against the
`(tenant, subject, rowId)` the row was written under. A row written under a residual scope — the
shape C-41 demonstrated — is refused inside the same flush and before the commit, rather than left

### The write path settles a debt; it does not perform a check (S-1)

The per-row post-hoc check above is fail-open by nature: it reads the row back inside the flush that
wrote it, and with `hibernate.jdbc.batch_size` set the `INSERT` is still in the JDBC batch, so there
is nothing to read. It returned without checking anything, for every row of every batch, on an
ordinary performance property. Cipher's probe committed three rows of plaintext personal data.

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
import that never flushes carries one record per row until the transaction commits; that is
`QUESTIONS.md` #26.

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
for a converter-based design. See `QUESTIONS.md` CIPHER-01.

**What is still a residual.** `ShreddingReadBracketCustomizer` refuses startup outright when more
than one `EntityManagerFactory` bean exists, on the reasoning that a region cannot vouch for a
Hibernate session it does not know is instrumented. That is defence in depth, not the primary
control — the primary control is that a converter with no region refuses — and it could not be
exercised by its own integration test: registering a second `EntityManagerFactory`-typed bean the
ordinary Spring way trips Spring Boot's own `@ConditionalOnMissingBean` on its auto-configured (and
therefore instrumented) factory. See `QUESTIONS.md` C-20. Separately, a read region left behind by a
`StackOverflowError` is still *open* as far as `inReadBracket()` can tell, so a later call on that
pooled thread that opens no region of its own loses the `SHRED-READ-UNSCOPED` signal it should have
had. It cannot lose a value — the drain is token-checked and the converter returns no plaintext —
but the loudness is missing, and it is recorded in `QUESTIONS.md` for Cipher rather than claimed
closed.

Probes: `CipherProbeFifthPassTest` (C-33 P1, C-34 P2, C-35 P3), `CipherProbeBracketUnwindTest`,
`CipherProbeEvictionTest` (C-36), `CipherProbeFrameTest`, `CipherProbeReadScopeTest`,
`CipherProbeMatrixTest`, `CipherProbeMatrix2Test`, `FrameworkMatrixTest`,
`LoadedStateHostileMappingsTest`, `FieldCipherRowBindingTest`, `EncryptedValueV2Test`, `RowIdTest`.

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

Probes: `CipherProbeEmbeddableScanTest.probe_a_shredded_field_inside_an_embeddable` (Cipher's own,
`@Embedded`) and `probe_a_shredded_field_inside_an_element_collection_of_embeddables` (Dollar's
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

Fifth pass, Cipher item 7: the refusal is now on the identifier *mapping*, not only its column
count. A single-column `@EmbeddedId` has exactly one identifier column and so passed the check above,
but it is not a basic value: its Java value is a component object with no canonical byte form
`RowId` could bind a stored value to, and a guessed row binding is no binding.

Probes: `CipherProbeCompositeIdTest.probe_a_composite_id_shredded_entity_is_refused_at_startup`,
`probe_a_moved_ciphertext_in_a_composite_id_entity_is_never_displayed`, and
`LoadedStateHostileMappingsTest.a_single_column_embedded_id_is_refused_at_startup`.

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

## Threats the module does close, and how

| Threat | Control |
|---|---|
| Data key re-derivable from the master, making erasure a no-op | keys are 256 random bits, never derived (control 1) |
| Entity/field name collision in the AAD | length-prefixed canonical AAD (control 2) |
| Nonce reuse under one key | random 96-bit nonce, per-key counter, hard refusal at 2^32 and rotation (control 3). An `@GeneratedValue(IDENTITY)` insert encrypts each shredded column twice - once bound to the unbound intermediate, once to the generated identifier - so the counter advances twice per column on that path and rotations come twice as often for an `IDENTITY`-heavy workload (QUESTIONS #23) |
| Plaintext fallback on an unrecognised column | strict format, typed error, no lenient parse (controls 4 and 17) |
| Master key in `/env`, `/configprops`, logs or `toString` | explicit exclusion, `byte[]` not `String`, never in a message (control 5) |
| Unprovable erasure or false proof | key deletion and the record in one transaction (control 6) |
| Key used after it was claimed by an erasure | state checked on read as well as write (control 7). Costs one `SELECT` against `shredding_data_key` per decrypt - 200 statements for a 200-row page, measured above under "Cost" - because the cache holds key *material*, never *authority* (QUESTIONS #22, Cipher sixth pass): memoising this check per transaction would remove the statements but would cache authority, which is the one thing the read-path design took away from ambient state. Not removed. |
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
| A racing write minting a fresh key for an erased subject | the `shredding_erased_subject` tombstone, holding no key material, protected by the same append-only triggers as the erasure log (QUESTIONS #3, CIPHER-04) |
| A write racing the *first* key mint for a subject surviving the tombstone | `pg_advisory_xact_lock(tenant, subject)` taken first, in the same transaction, by every path that mints or erases (CIPHER-03) |
| A decrypted value reaching a generated `toString` | a record entity fails startup; Lombok's generators are `SOURCE`-retained and cannot be detected at runtime, so the sample ships an ArchUnit rule for that case instead (CIPHER-06) |
| A ciphertext moved between two rows of the *same* subject displayed as the second row's own | the row's identifier is bound into the header and the AAD, format `SH1` v2; a copy is `SHRED-ROW-MISMATCH` and a relabelled header fails GCM authentication (C-34) |
| A v1 blob written over a v2 one to strip the row binding | v1 is refused, not read; the AAD layout version differs too, so the refusal is structural as well as checked (Cipher item 12) |
| An `IDENTITY` insert's pre-rebind bytes captured by change data capture, a trigger or a physical replica | the intermediate is a random 128-bit value under a tag no real identifier's encoding can equal, so it verifies against no row; a failed rebind aborts the transaction (Cipher items 5, 6) |
| An entity whose install never ran writing `NULL` over a live `BigDecimal`/`LocalDate`/JSON ciphertext on the next flush | the read placeholder is a non-null per-type constant compared by reference identity, and writing it back is `SHRED-PLACEHOLDER-001` (Cipher item 2) |
| A forged placeholder stored in the column so a read hands it back as an installed value | the marker carries 128 bits drawn per JVM run and is compared by identity, and the stored bytes are not `SH1` so the decode refuses first (Cipher item 3) |
| A user `@PostLoad` callback or `@EntityListeners` bean handed the read placeholder instead of the value | the module's `POST_LOAD` listener is prepended, ahead of Hibernate's own, which is what invokes those callbacks (Cipher item 8) |
| A refused row served intact from the first-level cache on the retry | verification runs before either install, so a refused instance holds placeholders, and `refuseLoad` evicts it as well (C-27, Cipher item 9) |
| A residual write scope pushed for one entity consumed by a bind of another | `ShreddingContext.require` compares the entity name, and a post-hoc header check after every insert and update refuses a row not bound to the scope it was written under, inside the same flush (C-41, Cipher items 13, 14) |
| An optimistic-lock, select-before-update or natural-id mapping making loaded-state install unsound | refused at startup, read off the runtime persister rather than the annotations (Cipher item 10) |
| A single-column `@EmbeddedId` slipping past the composite-id check and being bound to a guessed row identity | a non-basic identifier is refused at startup (Cipher item 7) |
| A ciphertext moved between rows, subjects or tenants displayed on read, or surviving its own subject's erasure | the row's stored header is checked against the row, on write and on read (CIPHER-01, QUESTIONS #4) |
| A repeat erasure of a subject with an outstanding `PARTIAL` reporting `COMPLETE` | the trail's actual last outcome is read back, and the hooks are re-run rather than assumed to have succeeded (CIPHER-02) |
| The unkeyed erasure log's pseudonyms computable from the module's own published constant | `shredding.subject-pseudonym.pepper` is a required secret whenever `unkeyed=true` (CIPHER-07) |
| A failed write leaving a stale tenant/subject on a pooled thread | the push is bracketed in `try`/`finally`, the stack is cleared at the transaction boundary by that session's own callback, and a scope still live when the next bind starts is dropped rather than consumed (CIPHER-08, C-41) |
| `sharedCache.mode=ALL` or the query cache serving plaintext after an erasure | the startup check reads the resolved JPA/Hibernate cache properties, not only the entity's own annotations (CIPHER-09) |
| An append-only trigger silently missing in a second schema on the same database | every guard resolves `tgrelid` against `current_schema()`, not a bare trigger name (CIPHER-05) |
| A scalar/`Tuple`/constructor-expression projection returning another subject's plaintext | the header-versus-row check moved into the converter, at the one place every decrypt goes through; a decrypt with neither a managed-entity read bracket nor an explicit read scope is refused (`SHRED-READ-UNSCOPED`, CIPHER-11) |
| A nulled subject-source column silencing the read-path check and letting a moved ciphertext through | an unresolvable subject on a row carrying any decoded shredded value is a refusal (`SHRED-SUBJECT-UNRESOLVED`), never a silent `return` (CIPHER-12) |
| A stale decoded-header entry from one read corrupting the next, unrelated load on the same thread | a frame entry carries the token of the region that recorded it, and a drain happens only under the region in force; a foreign-token entry is discarded and the load refuses (CIPHER-13, Cipher item 4) |
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
- **Run the application with a role that has INSERT and SELECT on `shredding_erasure`**, not the
  owner. The append-only triggers stop the runtime role; only the owner can disable them.
- **Never store `shredding.erasure-log.hmac-secret` beside the datasource password.** If one
  compromise yields both, the chain key is not a second factor, it is decoration. Module B's rule.
- **Losing the master key erases everyone.** The startup health check reports whether it can unwrap
  a known key; wire it into your readiness probe.
- The erasure-log HMAC secret is **not** a data key and is **never** destroyed by an erasure.
  Destroying it would break the very record that proves the erasure happened.
