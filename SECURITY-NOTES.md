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

### A moved ciphertext is refused after the load that read it has already run
CIPHER-01 and QUESTIONS #4 (ruling (c)) are one fix. Control 14 forbids a persisted row's data
subject from changing, and control 2 requires that a ciphertext moved to another row, subject or
tenant does not decrypt. Both are enforced from the row's stored blob header, not from a cache of
what this process happened to load:

- **On write**, `ShreddingEventListener.onPreUpdate` fetches the row's *current* shredded column
  with a second query - one round trip, and only when a `@Shredded` field is actually dirty - and
  compares the header's subject and tenant against the value about to be written. A disagreement is
  `SHRED-SUBJECT-IMMUTABLE`, refused before anything is re-encrypted.
- **On read**, `onPostLoad` - once the whole entity is hydrated - independently re-reads the row's
  own stored shredded columns by id (fourth pass, C-26; see below for why this replaced the earlier
  "trust what the converter recorded" design), resolves the row's true subject and tenant the same
  way the write path does, and compares. A disagreement is `SHRED-SUBJECT-MISMATCH`, thrown from
  `onPostLoad`, which aborts the load: the entity is never returned to the caller that asked for it,
  and the refused instance is evicted from the persistence context so a second read in the same
  transaction cannot serve it from the first-level cache instead (C-27, below).

**Why the read side is not "checked before the key store is touched" the way CIPHER-01's fix text
asks for.** A JPA `AttributeConverter` is handed nothing but the column bytes: no entity, no
session, no row. Checked against the actual Hibernate loader bytecode this module builds against
(`EntityInitializerImpl`, Hibernate ORM 7.4, not assumed): every attribute converter on a row -
including every `@Shredded` field's `decrypt` -
has already run by the time the *first* Hibernate listener fires for that row, `PreLoadEventListener`
included. There is no hook that fires before a converter runs on read, unlike the write path, where
`PreInsertEvent`/`PreUpdateEvent` genuinely do fire before the SQL binds. The read-side check is
therefore necessarily two-phase: decrypt happens, then the check happens, then (only if it passes)
the value reaches the caller. The security property CIPHER-01 actually asks for - a moved
ciphertext is never displayed - holds: nothing is ever handed to application code without passing
the check. What does not hold literally is "before it touches the key store", which this SPI makes
unreachable for a converter-based design. See QUESTIONS.md CIPHER-01 for the full reasoning.

**Third pass (C-17/C-18/C-20/C-22, `docs/SECURITY-REVIEW-feat-shredding-core.md` "Third pass
(8095d2c)"): the recording is now per-bracket-frame, not a flat, thread-wide map.** Cipher's
re-verification found that the flat map above let a decrypt reached inside the read bracket - a
repository `@Query` scalar/`Tuple`/interface projection, or a repository bound to a second,
uninstrumented `EntityManagerFactory` - record its decoded header with nothing that would ever
drain it (a projection triggers no `onPostLoad` at all), and either return the value unverified or
have the stale entry mistaken for a later, unrelated row's header once *something* did drain it.
`ShreddingContext.pushReadBracket()` now opens a frame; `recordDecoded`/`takeDecoded` operate on the
frame currently on top of the stack, not a flat map; `popReadBracket()` closes the frame and throws
`SHRED-READ-UNVERIFIED` if anything in it was never drained - after the value was computed, but
before `ShreddingReadBracketCustomizer`'s proxy hands the repository method's result back to its
caller. The bracket now owes a debt rather than granting a permission: every scenario above is
refused rather than returned.

**This note used to claim the multi-row case above was closed. It was not - that was C-26, the
fourth pass's own finding, one level down from the third pass's fix.** Hibernate ORM 7.4 defers
every row's `PostLoadEvent` until the *whole* `JdbcValues` result set has been hydrated: for a
two-row query, both rows' converters run (and record) before either row's `onPostLoad` fires. The
third-pass frame recorded a decode keyed only by `entityName + "." + fieldName`, with no row
identity - so the second row's converter silently overwrote the first row's entry, and whichever
row's `onPostLoad` happened to drain first was verified on behalf of both. This was simultaneously a
leak (a ciphertext moved into a second row was returned, because the surviving entry happened to be
the honest first row's) and a false refusal (two genuine subjects in one `findAll()` could throw,
because the surviving entry belonged to the *other* row). `repository.findAll(Sort)` reaches it
directly; no join or nesting is required.

**The fix does not try to give the frame a row identity it cannot have** - `ShreddedConverter` is
still handed nothing but the column bytes, no session, no row. Instead `onPostLoad` independently
re-reads the row's own currently stored shredded columns by id - the same `SELECT ... WHERE id = ?`,
public header only, no key material, that `refuseIfSubjectMoved` already runs on the write path -
and compares those headers against the row's true subject and tenant. That comparison needs nothing
from the frame to be correct, so it cannot be fooled by which row's converter happened to run last.
The frame itself is reduced to what it can honestly do: `ShreddingContext.recordDecoded` keys a
*multiset* by `(entity, field, tenant, subject)` - the tenant and subject the header itself named at
decode time, since a row id is unavailable - and increments a count rather than overwriting a map
entry, so N legitimate rows sharing one subject can each record and later drain their own count.
`onPostLoad` drains the exact key its own fresh, per-row re-read names; `popReadBracket()` still
refuses when anything is left over, which is what keeps C-17/C-18/C-20 closed.

Probes: `CipherProbeFrameTest.probe_a_moved_ciphertext_in_a_second_row_of_one_result_set` (the leak),
`probe_two_rows_of_two_subjects_read_in_one_query` (the false-refusal mirror, strengthened per
Dollar's instruction to assert each row decrypts to its own value, not merely "no exception"), and
every third-pass C-17/C-18/C-20/C-22 probe, still green.

**A row refused by `onPostLoad` used to stay in the persistence context (C-27).** The exception
aborts the load in progress, but Hibernate had already registered the fully hydrated - decrypted -
entity in the session's first-level cache before `onPostLoad` ran. A second read of the same row's
id in the same transaction was a cache hit: no SQL, no converter, no `PostLoad`, nothing to refuse.
`refuseLoad` now evicts the instance before the exception leaves the method, so a retry is forced
back through a real reload and this same check every time. Cipher's fix text also asked for the
transaction to be marked rollback-only; that half was tried and reverted, with the reasoning and the
evidence in QUESTIONS.md #19 - `SimpleJpaRepository.findById`'s own `@Transactional` already does
the equivalent the moment its own call is the one that refuses, entirely independent of anything
this module does, and marking it explicitly here made every probe that catches the refusal and
keeps going fail on `UnexpectedRollbackException` instead of exercising the property being tested.

**What is still a residual.** `ShreddingReadBracketCustomizer` additionally refuses startup outright
when more than one `EntityManagerFactory` bean exists in the application context, on the reasoning
that a bracket cannot vouch for a Hibernate session it does not know is instrumented. This is
defence in depth, not the primary control - the primary control is the frame accounting above, which
does not depend on knowing anything about the factory - and it could not be exercised by its own
integration test: registering a second `EntityManagerFactory`-typed bean the ordinary Spring way
trips Spring Boot's own `@ConditionalOnMissingBean` on its auto-configured (and therefore
instrumented) factory, suppressing it entirely rather than letting both coexist. See QUESTIONS.md
C-20.

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

### A `@Shredded` field must not be mapped `@Basic(fetch = LAZY)` (documented, not reproduced)

Lazy fetching of a basic attribute is inert in Hibernate without bytecode enhancement, and none of
this module's three POMs configure an enhancement plugin, so there is no path here to attack it
today. In an application that does enable enhancement, the column would be fetched on first getter
access - for an entity handed back from a repository call, that is *after* the read bracket has
already closed, so the converter would see `ShreddingContext.inReadBracket() == false` and refuse
with `SHRED-READ-UNSCOPED`: reasoned to be fail-closed, not reproduced under a real enhanced build.
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
| Nonce reuse under one key | random 96-bit nonce, per-key counter, hard refusal at 2^32 and rotation (control 3) |
| Plaintext fallback on an unrecognised column | strict format, typed error, no lenient parse (controls 4 and 17) |
| Master key in `/env`, `/configprops`, logs or `toString` | explicit exclusion, `byte[]` not `String`, never in a message (control 5) |
| Unprovable erasure or false proof | key deletion and the record in one transaction (control 6) |
| Key used after it was claimed by an erasure | state checked on read as well as write (control 7) |
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
| A racing write minting a fresh key for an erased subject | the `shredding_erased_subject` tombstone, holding no key material, protected by the same append-only triggers as the erasure log (QUESTIONS #3, CIPHER-04) |
| A write racing the *first* key mint for a subject surviving the tombstone | `pg_advisory_xact_lock(tenant, subject)` taken first, in the same transaction, by every path that mints or erases (CIPHER-03) |
| A decrypted value reaching a generated `toString` | a record entity fails startup; Lombok's generators are `SOURCE`-retained and cannot be detected at runtime, so the sample ships an ArchUnit rule for that case instead (CIPHER-06) |
| A ciphertext moved between rows, subjects or tenants displayed on read, or surviving its own subject's erasure | the row's stored header is checked against the row, on write and on read (CIPHER-01, QUESTIONS #4) |
| A repeat erasure of a subject with an outstanding `PARTIAL` reporting `COMPLETE` | the trail's actual last outcome is read back, and the hooks are re-run rather than assumed to have succeeded (CIPHER-02) |
| The unkeyed erasure log's pseudonyms computable from the module's own published constant | `shredding.subject-pseudonym.pepper` is a required secret whenever `unkeyed=true` (CIPHER-07) |
| A failed write leaving a stale tenant/subject on a pooled thread | the push is bracketed in `try`/`finally`, and the stack is cleared at the transaction boundary regardless of which listener ran last (CIPHER-08) |
| `sharedCache.mode=ALL` or the query cache serving plaintext after an erasure | the startup check reads the resolved JPA/Hibernate cache properties, not only the entity's own annotations (CIPHER-09) |
| An append-only trigger silently missing in a second schema on the same database | every guard resolves `tgrelid` against `current_schema()`, not a bare trigger name (CIPHER-05) |
| A scalar/`Tuple`/constructor-expression projection returning another subject's plaintext | the header-versus-row check moved into the converter, at the one place every decrypt goes through; a decrypt with neither a managed-entity read bracket nor an explicit read scope is refused (`SHRED-READ-UNSCOPED`, CIPHER-11) |
| A nulled subject-source column silencing the read-path check and letting a moved ciphertext through | an unresolvable subject on a row carrying any decoded shredded value is a refusal (`SHRED-SUBJECT-UNRESOLVED`), never a silent `return` (CIPHER-12) |
| A stale decoded-header entry from one read corrupting the next, unrelated load on the same thread | `DECODED_READS` is drained in full by `onPostLoad` regardless of outcome and cleared at the transaction boundary alongside the write scope (CIPHER-13) |
| The update-time subject-immutability check skipped because only the entity's *first* shredded column happened to be null | every shredded column of the entity is read and checked in one query; early return only when all of them are null (CIPHER-14) |
| An outstanding `PARTIAL` erasure hidden behind an earlier `COMPLETE` by a backwards application-clock step | `latestForSubject` orders by the log's own monotonic `seq`, never by `ts` (CIPHER-15) |
| `ShreddedBytesConverter` refusing its own entity's first insert under `@GeneratedValue(IDENTITY)` | the field is declared `@org.hibernate.annotations.Immutable`, which stops Hibernate deep-copying the converted value outside the write bracket; enforced at startup (CIPHER-16) |
| A mistyped subject expression (`#{#this}`, `#{#root}`) resolving to an identity hash and encrypting under a key nobody can ever ask an erasure for | `SubjectExpression` refuses a resolved value that is not a scalar type, and refuses an `Object.toString()`-shaped string (L12) |
| A repository `@Query`/interface projection, or a repository bound to a second, uninstrumented `EntityManagerFactory`, decrypting inside the read bracket with nothing that would ever verify it | `popReadBracket()` throws `SHRED-READ-UNVERIFIED` if the bracket's frame still holds an undrained decode when it closes, before the repository method's result reaches its caller (C-17, C-18, C-20) |
| A stale decoded-header entry recorded by one repository call surviving to be mistaken for a later, unrelated call's row | recording and draining now happen against the frame the *current* bracket opened, not a bracket-wide map; the frame is checked and discarded when that bracket closes (C-22) |
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
