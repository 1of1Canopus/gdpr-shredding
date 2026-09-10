# GDPR Shredding

Crypto-shredding for Spring Boot and JPA. Each data subject's personal fields are encrypted under
that subject's own key; destroying the key **renders the data permanently unreadable. The row
survives**, and so do the foreign keys and the audit trail.

Regulators treat this as **pseudonymisation with key destruction**, not anonymisation and not
deletion. That is a genuine and useful control - it is Art. 32(1)(a) in one line, and it is what
lets an Art. 17(1) request be answered without dropping the rows an audit or an accounting rule
requires - but it is not a claim that the data is gone. The residual risks are listed in
`SECURITY-NOTES.md`, and the sources are under "Regulatory references" below.

## Quickstart

1. Add `com.housedevinci:gdpr-shredding-spring-boot-starter`.
2. Generate the three secrets and pass them through the environment:

```
export SHREDDING_MASTER_KEY=$(head -c 32 /dev/urandom | base64)
export SHREDDING_ERASURE_LOG_SECRET=$(head -c 32 /dev/urandom | base64)
export SHREDDING_BLIND_INDEX_SECRET=$(head -c 32 /dev/urandom | base64)   # only if you use @BlindIndex
```

3. Annotate the fields and write one converter per field (see below).
4. Call `ErasureService.erase(...)`.

The schema (`shredding_data_key`, `shredding_erased_subject`, `shredding_erasure`,
`shredding_erasure_anchor`) is created idempotently at startup under an advisory lock.

## Why one converter class per field

Hibernate hands an `AttributeConverter` nothing but the value, and resolves it through the managed
bean registry, which caches **one instance per class**. A single shared converter therefore cannot
know which entity and field it is protecting, and that pair is exactly what the AAD binds - it is
what stops a ciphertext being moved from `Customer.email` to `Customer.phone`. So each shredded
field gets a two-line converter:

```java
@Converter
public class CustomerEmailConverter extends ShreddedStringConverter {
  public CustomerEmailConverter() { super("Customer", "email"); }
}
```

The startup scan cross-checks every `@Shredded` field against the `@Convert` that maps it and
refuses to start if the names disagree. Base classes ship for `String`, `byte[]`, `LocalDate`,
`BigDecimal` and JSON-as-`String`. A `@Shredded` field must be a direct attribute of the entity: not
inside an `@Embeddable`, not inside an `@ElementCollection` - both are refused at startup (C-29) -
and not mapped `@Basic(fetch = LAZY)` (undocumented lazily by Hibernate's own bytecode-enhancement
requirement, which this module does not configure and has not tested against).

> **`ShreddedBytesConverter` (the `byte[]` base class) needs `@Immutable` on the field.** Hibernate
> treats `byte[]` as mutable and deep-copies the *converted* value - calling the converter a second
> time, outside the write-path bracket - to build the entity's dirty-checking snapshot; under
> `@GeneratedValue(strategy = GenerationType.IDENTITY)` that second call has no write scope and
> refuses the row's own first insert with `SHRED-CONTEXT-001`. Add
> `org.hibernate.annotations.Immutable` to the field and the startup scan requires it is there:
>
> ```java
> @Shredded(subject = "#{ownerId}")
> @Convert(converter = DocumentPayloadConverter.class)
> @Immutable
> @Column(name = "payload")
> byte[] payload;
> ```
>
> **`@Immutable` is what stops the deep copy - and the deep copy it stops is also what Hibernate's
> dirty checking compares the live array against (C-21).** With no snapshot copy, an in-place
> mutation of the array a `@Shredded byte[]` field already holds -
> `document.getPayload()[0] = x` - is compared against itself on the next flush and is never seen
> as dirty: no exception, no log line, no `UPDATE`. This is the permanent cost of the annotation,
> not a bug to fix later. **Assign a whole new array to change the value**
> (`document.setPayload(newArray)`); never mutate the one already there. Covered end to end (insert,
> read, erase, re-read) under both `IDENTITY` and `SEQUENCE` id strategies, and the in-place-mutation
> trap itself has its own probe (`CipherProbeMatrixTest`). See QUESTIONS.md #15 and C-21.

> Two lines per field is boilerplate, and we know it. An annotation processor that generates these
> converters from `@Shredded` alone is a later improvement, deliberately not in this release: the
> generated code would sit in the one part of the module that has to be obviously correct, and it
> buys convenience rather than a control. (Dollar's ruling on QUESTIONS #1, 2026-09-08.)

`LocalDate` and `BigDecimal` have no value that can stand for "erased". `0` and `LocalDate.EPOCH`
are deliberately not used: a zero balance is a fact and an erased balance is not. The rule is:

- under `shredding.erased-value.policy=sentinel` those fields read as `null`, and the startup check
  logs a WARN **naming every shredded field whose type cannot carry a sentinel**, so nobody
  discovers it from a null pointer;
- under `shredding.erased-value.policy=exception` they throw like every other type.

## How the write path finds the data subject

`PreInsertEventListener` and `PreUpdateEventListener` fire immediately before Hibernate binds the
state array, which is when the converters run; they evaluate the `@Shredded(subject = ...)` SpEL
against the entity and push a scope, and the `Post` listeners pop it. The read path needs no scope:
the tenant and subject travel inside the stored blob.

A converter reached with no scope - a bulk JPQL update, a criteria parameter, a detached write -
fails with `SHRED-CONTEXT-001` rather than guessing a subject.

The SpEL runs in a `SimpleEvaluationContext` (property reads only: no beans, no `T()` type
references, no constructors, no method calls), parsed once at bootstrap.

## How the read path verifies (C-23)

A decrypted `@Shredded` value is either verified against the row it came from or refused - never
handed back on the strength of "something upstream probably checked this."

**The converter never returns the value.** `ShreddedConverter.convertToEntityAttribute` decrypts,
files what it decrypted in the open *read region*, and returns a placeholder.
`ShreddingEventListener.onPostLoad` - the one hook that knows the row - checks each field against the
row's own tenant, subject and identifier, and only then installs the real value over the placeholder,
into the entity and into Hibernate's loaded state. Nothing that is not a managed entity load ever
receives a decrypted `@Shredded` value.

- **A Spring Data JPA repository call** (`repository.findByX(...)`, `Page`/`Slice`/`Streamable`
  returns, `findById`, derived finders, `Specification`) works transparently:
  `ShreddingReadBracketCustomizer` opens a read region around the whole call, and `onPostLoad`
  verifies and installs each loaded row before the call returns.
- **A raw `EntityManager` entity operation** - `find`, `getReference`, `merge`, `refresh`, an
  entity-returning JPQL or Criteria query - is not proxied by Spring Data and gets no region
  automatically. Wrap it:
  ```java
  Doc doc = ShreddingContext.withReadBracket(() -> entityManager.find(Doc.class, id));
  ```
- **A projection cannot be made to work, and there is no escape hatch.** A scalar, `Tuple`,
  constructor-expression or interface projection loads no entity, so nothing can ever verify which
  row its bytes belong to. `ShreddingContext.withRead(...)` used to let a caller vouch for one; it is
  removed, because a caller-supplied identity is exactly the ambient authority five review passes
  kept breaking. Select the entity and read the field off it.

**What is refused, and why.**

| Situation | Code |
|---|---|
| a decrypt with no open read region: a hand-written `@Repository` DAO holding its own `EntityManager`, an unwrapped `EntityManager` read, a `Stream<T>` drained after its repository call already returned, an `@Async` continuation on another thread, a `StatelessSession` (which fires no `PostLoad` at all) | `SHRED-READ-UNSCOPED`, at the decrypt |
| a decrypt inside a region that no entity load ever installs: a repository `@Query` scalar/`Tuple`/interface projection, a repository bound to an uninstrumented `EntityManagerFactory` | `SHRED-READ-UNVERIFIED`, when the region closes, before the value reaches the caller |
| a row holding another subject's or tenant's ciphertext | `SHRED-SUBJECT-MISMATCH` |
| a row holding another of the *same* subject's rows' ciphertext | `SHRED-ROW-MISMATCH` |
| an entity flushed while a `@Shredded` field still holds the read placeholder | `SHRED-PLACEHOLDER-001` |

In every case nothing decrypted is returned: the converter hands out a placeholder, not the value.

**Two rules for entity classes.**

1. **A `@Shredded` field must never participate in `equals` or `hashCode`.** Between the converter
   and the install the field holds the placeholder, so an instance put into a `HashSet` or used as a
   `HashMap` key *before* the install is unreachable afterwards. Dirty checking is unaffected: the
   install writes the entity field and the loaded state together.
2. **A `@Shredded` entity must have a basic, single-column identifier** - a numeric id, a `UUID`, a
   `String` or a `byte[]`. The identifier is bound into every stored value; a composite or embedded
   id, including a single-column `@EmbeddedId`, has no canonical byte form to bind to and is refused
   at startup.

Also refused at startup, because installing into the loaded state cannot be made sound with them:
optimistic locking `ALL` or `DIRTY`, select-before-update, and a `@Shredded` column that is part of
the natural id.

## Configuration

| Property | Default | What |
|---|---|---|
| `shredding.master-key` | **required** | base64, >= 32 bytes, environment only. No default, none generated, sample values refused |
| `shredding.dev-mode` | `false` | permits the in-memory key provider. WARNs at every startup |
| `shredding.allow-second-level-cache` | `false` | permits a `@Shredded` entity to be cached. WARNs at every startup |
| `shredding.erased-value.policy` | `sentinel` | `sentinel`, `exception`, or `null` (WARNs at every startup) |
| `shredding.crypto.max-encryptions-per-key` | `4294967296` | values one key may encrypt before rotation. Cannot be raised |
| `shredding.data-key-cache.ttl` | `60s` | how long a node may hold an unwrapped key; also the cross-node erasure window |
| `shredding.data-key-cache.max-size` | `10000` | unwrapped keys per node |
| `shredding.erasure-log.hmac-secret` | **required** | chain secret, >= 32 bytes. Never destroyed by an erasure |
| `shredding.erasure-log.hmac-key-id` | `k1` | key id inside the hashed material of every row |
| `shredding.erasure-log.hmac-keys.<id>` | empty | keyring for verification across a rotation |
| `shredding.erasure-log.unkeyed` | `false` | loud opt-out. WARNs at every startup |
| `shredding.blind-index.hmac-secret` | required with `@BlindIndex` | its own secret, never the data key or chain material |
| `shredding.blind-index.bits` | `64` | index width. A prefilter: the query path re-verifies |
| `shredding.erasure.backup-retention` | `30d` | the erasure is complete at `erasedAt + this`, and the record says so |

There is no fail-open property anywhere in this module.

## Error codes

| Code | Meaning |
|---|---|
| `SHRED-FORMAT-001` | stored bytes are not in the `EncryptedValue` format. Core never falls back to reading a column as plaintext |
| `SHRED-DECRYPT-001` | authenticated decryption failed: wrong key, wrong AAD, or tampered bytes. The message never says which |
| `SHRED-KEY-UNAVAILABLE` | the key store is unreachable. Retryable, 503, health DOWN. **Not** an erasure |
| `SHRED-KEY-DESTROYED` | the key is gone. Terminal |
| `SHRED-ERASED-001` | a write was attempted for a subject whose key is `DESTROYING`, `DESTROYED` or tombstoned |
| `SHRED-CONTEXT-001` | a converter ran with no write context |
| `SHRED-SUBJECT-IMMUTABLE` | the data subject of a persisted row changed |
| `SHRED-SUBJECT-MISMATCH` | a stored value's header names a different subject or tenant than the row it was read from (CIPHER-01) |
| `SHRED-ROW-MISMATCH` | a stored value's header names the right subject but a different row of it - a ciphertext copied between two of one person's rows (C-34) |
| `SHRED-PLACEHOLDER-001` | an attempt to persist the marker a `@Shredded` read returns before the verified value is installed; writing it would destroy the stored ciphertext |
| `SHRED-TENANT-MISSING` | no tenant in context, and there is no default tenant |
| `SHRED-CONFIG-001` | misconfiguration, naming the property |
| `SHRED-ERASURE-002` | the erasure log has rows but no anchor row |
| `SHRED-ERASURE-003` | this instance's keyed/unkeyed mode disagrees with the trail |
| `SHRED-ERASURE-004` | an erasure found a blind index still populated after clearing it; refused, not recorded |
| `SHRED-INVALID-001` | boundary validation failed |
| `SHRED-READ-UNSCOPED` | a `@Shredded` converter ran with no read region open - an unwrapped `EntityManager` or hand-written-DAO read, a `Stream<T>` drained after its repository call returned, an `@Async` continuation, or a `StatelessSession` |
| `SHRED-READ-UNVERIFIED` | a decrypt happened inside an open read region but no entity load ever installed it before the region closed - a projection, or residue from a region an error unwound past - see "How the read path verifies" above |
| `SHRED-SUBJECT-UNRESOLVED` | a row carries at least one shredded value and its data subject could not be resolved |
| `SHRED-EMF-UNINSTRUMENTED` | more than one `EntityManagerFactory` bean exists in the application context; the read bracket cannot tell which repository is bound to which, so every repository is refused rather than bracketed on the chance it is the wrong one |

The per-key encryption limit (`shredding.crypto.max-encryptions-per-key`) has no error code: reaching
it rotates to the next key version rather than refusing, so there is nothing a caller ever sees.

## The stored format

```
offset    len  field
0         3    magic "SH1"
3         1    format version 0x02
4         1    algorithm id   0x01 = AES-256-GCM / 96-bit nonce / 128-bit tag
5         4    key version    int32 big-endian
9         1    tenant id length
10        t    tenant id (UTF-8)
          1    subject id length
          s    subject id (UTF-8)
          1    row id length
          r    row id, canonical and type-tagged
          12   nonce
          4    ciphertext length
          n    ciphertext || 16-byte tag
```

Fixed offsets, no optional sections, a strict parse. Unknown magic, unknown version, truncation and
trailing bytes are all `SHRED-FORMAT-001`.

**Format v1 is refused, not read.** It bound tenant and subject but no row, so two rows of one
subject held interchangeable ciphertexts. There is no dual-format reader and no downgrade: either
would let anyone holding `UPDATE` strip the row binding by writing a v1 blob over a v2 one.

The row id is the identifier's column value under a one-byte type tag - `0x01` numeric (int64
big-endian), `0x02` `UUID`, `0x03` `String` (UTF-8), `0x04` `byte[]` - never `Object.toString()`,
which cannot tell a `Long 1` from a `String "1"`. Tag `0x7f` is the random 128-bit *unbound
intermediate* an `@GeneratedValue(IDENTITY)` insert binds before the database has generated the key;
`onPostInsert` rebinds it in one `UPDATE` in the same transaction, and it matches no real
identifier's encoding, so an intermediate captured by change data capture, a trigger or a replica is
bound to no row.

AAD, on every value: `sh1|<len>:layout|<len>:alg|<len>:tenant|<len>:subject|<len>:rowId|<len>:entity|<len>:field|<len>:keyVersion`.
Every field is length-prefixed, so no rewrite can move a boundary. Wrapped keys use
`sh1|<len>:layout|<len>:wrap|<len>:tenant|<len>:subject|<len>:keyVersion`.

## The erasure log

Module B's audit chain, adapted. Keyed from row 1 or unkeyed for ever, recorded once on an anchor
row that a trigger refuses to change; the key id is inside the hashed material, so key rotation is
data rather than a format break; `UPDATE`, `DELETE` and `TRUNCATE` are refused by triggers on both
the trail and the anchor.

`ErasureChainVerifier` reports `EMPTY`, `INTACT`, `INTACT_UNKEYED`, `BROKEN`, `ANCHOR_MISMATCH` or
`NO_ANCHOR`. `INTACT_UNKEYED` is deliberately a different word: an unkeyed trail's integrity rests
only on database privilege separation.

Run the application with a role that has `INSERT` and `SELECT` on `shredding_erasure`, not the
owner. Keep `shredding.erasure-log.hmac-secret` somewhere other than the datasource password: if one
compromise yields both, it is not a second factor.

## Blind index

`@BlindIndex(of = "email", subjectColumn = "customer_id", tenantColumn = "tenant_id")` on a separate
`byte[]` field. The write path fills it in with the same normalisation the query path uses; the
per-tenant subkey comes from HKDF over its own secret.

It is a **prefilter**. It is truncated (`shredding.blind-index.bits`, default 64), so the query path
must re-verify by decrypting the candidates - see `CustomerService.findByEmail` in the sample.

An erasure nulls the erased subject's blind-index columns. That is not configurable.

`tenantColumn` names a **column**, not a property; it is resolved at startup to the single basic
`String` property of the entity that maps to it (none, two, a non-`String` one, or one visible only
inside an `@Embeddable` are startup refusals). The index is derived under that row's own tenant
column value, and a write is refused (`SHRED-UNVERIFIED-WRITE`) when that value is null or blank, or
when it is not the tenant the indexed field's data key is derived under - one erasure request has to
reach the key, the ciphertext and the index together. So a query helper computes the index under the
tenant the row's tenant column holds, which is also the tenant it passes to the erasure.

`subjectColumn` works exactly the same way, and for the same reason: it is a **column** name,
resolved at startup to the single basic `String` property that maps to it, and a write is refused
when that column's value is null, blank, or not the subject the indexed field's data key is derived
under. `@Shredded(subject = "#{customer.externalId}")` with `subjectColumn = "customer_id"` — the
subject one association away — is refused at the write, naming both values, rather than writing an
index no erasure can reach. Naming the entity's **identifier** as `subjectColumn` is refused at
startup: the identifier is not in the state array the write path reads, under
`GenerationType.IDENTITY` it does not exist yet, and it is not a string. In one line: *for a row to
be erasable by one request, the tenant and subject its data key was derived under, the tenant and
subject its index was derived under, and the values in its `tenantColumn` and `subjectColumn` are
one pair.*

The erasure reads the columns back inside its own transaction: still populated means the erasure is
refused (`SHRED-ERASURE-004`), not recorded.

## Schemas

Every statement this module builds for one of your tables is addressed at the table Hibernate maps,
schema and all, taken from the persister at startup. `@Table(schema = "app2")` and
`spring.jpa.properties.hibernate.default_schema` both work. A catalog-qualified table, and a table
or schema whose name is not lowercase, are refused at startup rather than addressed by a guess. With
no schema in the mapping the statements are unqualified, exactly like Hibernate's own, and the
connection's `search_path` decides. This module's own `shredding_*` tables are unqualified: keep
them on the runtime role's `search_path`.

## The cross-node cache window

An erasure evicts the local unwrapped-key cache immediately. It does **not** publish a cluster-wide
invalidation in the free core, so another node may still read the erased subject's data for up to
`shredding.data-key-cache.ttl` (default 60s). That window is documented here, appears in
`SECURITY-NOTES.md`, and is implied by the `completeInBackupsAt` date the erasure record carries.
Cluster-wide invalidation ships in Pro alongside the KMS adapters.

## What fails at startup

- a `@Shredded` field with no `@Convert`, or one whose converter names another entity or field;
- a column mapped by a `ShreddedConverter` with no matching field-level `@Shredded` - a class-level
  `@Convert(attributeName = ...)` or an `orm.xml` mapping, which put the column in the write path but
  not in the read verification, the `@Immutable` check or the second-level-cache refusal (C-19), or a
  field nested inside an `@Embeddable` or an `@ElementCollection` of embeddables, which the forward
  scan cannot see either - not supported at all; move the field onto the entity itself (C-29);
- more than one `EntityManagerFactory` bean in the application context, once Spring Data JPA is on
  the classpath (C-20);
- a `@Shredded` entity that is `@Cacheable`/`@Cache`, unless `shredding.allow-second-level-cache=true`;
- a `@Shredded` entity that is a **record**, or is annotated `@Data`, `@Value`, `@ToString` or
  `@EqualsAndHashCode`: all of those generate a rendering over every field, so the decrypted value
  reaches the first log line that prints the entity. The sample ships an ArchUnit rule you can copy
  into your own test sources for the cases only your code can see;
- a subject expression that does not parse, or that reaches a bean, a static type, a constructor or
  a method call;
- a missing, short, non-base64 or sample-looking `shredding.master-key`;
- a missing `shredding.erasure-log.hmac-secret` without `unkeyed=true`, or both at once;
- `shredding.crypto.max-encryptions-per-key` above 2^32.

## Health

The health contributor reports `DOWN` when the key store is unreachable, and includes the erasure
log's verifier status. Wire it into readiness: a key store that is down must not look like an
application that is merely returning erased values.

## Free vs Pro

| | Free core | Pro |
|---|---|---|
| Envelope encryption, per-subject keys, erasure, erasure log | yes | yes |
| `JdbcKeyProvider` (keys table, master key from the environment) | yes | yes |
| Vault Transit, AWS KMS, Azure Key Vault, GCP KMS | - | yes |
| Master-key rotation and re-wrap job, key escrow policy | - | yes |
| Per-tenant master keys | - | yes |
| Erasure workflow: intake, identity verification, grace period | - | yes |
| Proof-of-erasure PDF/HTML for the DPO | - | yes |
| Admin UI: subjects, keys, erasure log, verification endpoint | - | yes |
| Retention rules (auto-erase after N days) | - | yes |
| Batch migrator for existing plaintext columns | - | yes |
| Cluster-wide data-key cache invalidation | - | yes |

## Regulatory references

Verified by Odin, 2026-09-08.

- **GDPR** Art. 17(1) (right to erasure) and Art. 32(1)(a) (security of processing:
  "pseudonymisation and encryption of personal data"), Regulation (EU) 2016/679, EUR-Lex
  CELEX:32016R0679. Recitals 26, 28 and 29 (pseudonymisation) and 83 (encryption as risk
  mitigation).
- **Article 29 Working Party, Opinion 05/2014 on Anonymisation Techniques (WP216)**, 10 April 2014,
  Section 4 "Pseudonymisation". Encryption with key deletion is a **pseudonymisation** technique,
  not anonymisation; deleting the key reduces linkability but does not by itself remove the
  residual risk of singling-out (Sections 4.1 to 4.3).
- **CNIL**, "Recherche scientifique (hors sante) : enjeux et avantages de l'anonymisation et de la
  pseudonymisation" (cnil.fr, accessed 2026-09-08). Deleting the key or the correspondence table
  reduces re-identification risk, but the remaining data can still allow indirect identification and
  "demeurent alors soumises au respect du RGPD".
- **ICO**, "Right to erasure" (ico.org.uk, accessed 2026-09-08), section "Do we have to erase
  personal data from backup systems?": "The key issue is to put the backup data 'beyond use', even
  if it cannot be immediately overwritten."

These are pointers for your DPO, not legal advice. What this library can attest to is stated in
`SECURITY-NOTES.md`, and it is narrower than "the data is gone".

## FAQ

**Is this legally erasure?** No, and do not let anyone tell your DPO otherwise. What the module does
is **crypto-shredding**: it renders the data permanently unreadable by destroying the subject's key;
the row survives. Regulators classify that as **pseudonymisation with key destruction**, not
anonymisation. WP216 Section 4 says encryption with key deletion is a pseudonymisation technique and
that deleting the key reduces linkability without removing the residual risk of singling-out; the
CNIL says the remaining data can still allow indirect identification and "demeurent alors soumises
au respect du RGPD"; the ICO's test for data you cannot immediately overwrite is that it is put
"beyond use". Whether that satisfies an Art. 17(1) request in your circumstances is your DPO's call
on your facts, and it is a much easier call to make when Art. 32(1)(a) is satisfied too. The
residual risks are listed in `SECURITY-NOTES.md`; read them before you answer the question.

**Does an erasure delete the row?** No. That is the point. The row, its id and every foreign key
pointing at it survive; only the key does not.

**What if I lose the master key?** Every subject is erased. Back the key store up separately from
the data, or use a KMS (Pro).

**Can I search an encrypted column?** By equality, through `@BlindIndex`, with the caveats above.
Range and prefix queries are not possible and will not be added: they leak order.

**Can I re-encrypt an erased subject's row?** No. `SHRED-ERASED-001`.

**Does it work without a tenant?** No. A data key is per `(tenant, subject)`; a missing tenant is an
error, not an empty string. Use a single constant tenant if you have one tenant.
