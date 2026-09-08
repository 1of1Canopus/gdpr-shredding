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
`BigDecimal` and JSON-as-`String`.

> **`ShreddedBytesConverter` (the `byte[]` base class) is not production-ready.** An entity with a
> `byte[]` `@Shredded` field and `@GeneratedValue(strategy = GenerationType.IDENTITY)` refuses its
> own first insert with `SHRED-CONTEXT-001`: Hibernate deep-copies a mutable attribute's value to
> build the entity's dirty-checking snapshot, which calls the converter a second time outside the
> write-path bracket. See QUESTIONS.md #15. Use `String`, `LocalDate`, `BigDecimal` or the JSON
> converter until this is fixed and covered by a regression test.

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
| `SHRED-SUBJECT-MISMATCH` | a stored value's header names a different subject or tenant than the row it was read from - a ciphertext moved between rows (CIPHER-01) |
| `SHRED-TENANT-MISSING` | no tenant in context, and there is no default tenant |
| `SHRED-CONFIG-001` | misconfiguration, naming the property |
| `SHRED-ERASURE-002` | the erasure log has rows but no anchor row |
| `SHRED-ERASURE-003` | this instance's keyed/unkeyed mode disagrees with the trail |
| `SHRED-INVALID-001` | boundary validation failed |

The per-key encryption limit (`shredding.crypto.max-encryptions-per-key`) has no error code: reaching
it rotates to the next key version rather than refusing, so there is nothing a caller ever sees.

## The stored format

```
offset  len  field
0       3    magic "SH1"
3       1    format version 0x01
4       1    algorithm id   0x01 = AES-256-GCM / 96-bit nonce / 128-bit tag
5       4    key version    int32 big-endian
9       1    tenant id length
10      t    tenant id (UTF-8)
10+t    1    subject id length
11+t    s    subject id (UTF-8)
11+t+s  12   nonce
23+t+s  4    ciphertext length
27+t+s  n    ciphertext || 16-byte tag
```

Fixed offsets, no optional sections, a strict parse. Unknown magic, unknown version, truncation and
trailing bytes are all `SHRED-FORMAT-001`.

AAD, on every value: `sh1|<len>:layout|<len>:alg|<len>:tenant|<len>:subject|<len>:entity|<len>:field|<len>:keyVersion`.
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

## The cross-node cache window

An erasure evicts the local unwrapped-key cache immediately. It does **not** publish a cluster-wide
invalidation in the free core, so another node may still read the erased subject's data for up to
`shredding.data-key-cache.ttl` (default 60s). That window is documented here, appears in
`SECURITY-NOTES.md`, and is implied by the `completeInBackupsAt` date the erasure record carries.
Cluster-wide invalidation ships in Pro alongside the KMS adapters.

## What fails at startup

- a `@Shredded` field with no `@Convert`, or one whose converter names another entity or field;
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
