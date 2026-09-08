# Plan — GDPR Shredding, free core

Spec: `SPEC.md`, binding section `### Cipher spec review (2026-09-08)` (19 controls, 19 probes).
Where the spec body and Cipher's section disagree, Cipher's section wins.

House precedent: `../B-agent-guard`. The erasure record chain is B's audit chain copied and
adapted (keyed from birth, key id inside the hashed material, length-prefixed canonical form,
external anchor row, triggers refusing UPDATE/DELETE/TRUNCATE, six verifier statuses).
Extracting a shared `housedevinci-chain` library is a later decision: QUESTIONS #2.

## 1. Module layout

```
gdpr-shredding-parent (pom)                     com.housedevinci:0.1.0-SNAPSHOT
  gdpr-shredding-core                           JDK-only domain + application + jdbc/memory adapters
  gdpr-shredding-spring-boot-starter            auto-config, JPA converters, Hibernate listeners, actuator
  gdpr-shredding-sample                         customer entity, erasure endpoint, Testcontainers proof
```

Package root `com.housedevinci.shredding`; sub-packages `api`, `domain`, `application`,
`adapter.jdbc`, `adapter.memory`, `autoconfigure`, `jpa`, `web`.

Java 21, Spring Boot 4.1.1 (same as B after its Dependabot bump), Maven multi-module.
Zero crypto dependencies anywhere (control 18): `AES/GCM/NoPadding`, `HmacSHA256`, and a
hand-written HKDF checked against RFC 5869 vectors, all from the JDK. No BouncyCastle.

## 2. Domain (JDK only; ArchUnit allows `javax.crypto..` and nothing else under `javax..`)

| Type | Purpose |
|---|---|
| `TenantId`, `SubjectId` | validated value objects, non-blank, bounded length, charset (control 14, 15) |
| `KeyState` | `ACTIVE`, `DESTROYING`, `DESTROYED` |
| `DataKey` | `(tenant, subject, version, wrappedKey, state, encryptionCount, createdAt)` |
| `Aad` | canonical, length-prefixed `sh1\|version\|alg\|tenant\|subject\|entity\|field\|keyVersion` (control 2) |
| `EncryptedValue` | strict binary format + codec, fixed offsets (control 4) |
| `Aes256Gcm` | encrypt/decrypt, 96-bit `SecureRandom` nonce, 128-bit tag (control 3) |
| `Hkdf` | RFC 5869 extract/expand |
| `Pseudonymiser` | HMAC subject pseudonym, pepper by HKDF info `sh/subject-pseudonym/v1` (control 9) |
| `BlindIndex` + `Normalisation` | versioned normalisation, per-tenant subkey `sh/blind-index/v1\|<tenant>`, truncated to N bits (control 10) |
| `ErasureRecord`, `ErasureChain`, `ErasureAnchor`, `ErasureOutcome`, `HookOutcome` | B's chain, verbatim shape (control 8, 19) |
| `ShreddingException`, `ErrorCodes`, `ErasedValue`, `ErasedValuePolicy` | typed errors with stable codes |

### `EncryptedValue` wire format (control 4)

```
offset  len  field
0       3    magic  0x53 0x48 0x31            "SH1"
3       1    format version                    0x01
4       1    algorithm id                      0x01 = AES-256-GCM/96-bit nonce/128-bit tag
5       4    key version                       int32 big-endian, >= 1
9       1    tenant id length  (bytes, 1..255)
10      t    tenant id         UTF-8
10+t    1    subject id length (bytes, 1..255)
11+t    s    subject id        UTF-8
11+t+s  12   nonce
23+t+s  n    ciphertext || 16-byte tag         n >= 16
```

Tenant and subject travel in the blob because an `AttributeConverter` sees only the column value
on the read path (see 4 below); both are re-bound in the AAD, so moving a blob between rows,
subjects or tenants fails to decrypt (probes 3, 15). An unknown magic, an unknown version, a
truncated blob or trailing bytes is `SHRED-FORMAT-001`, never a best-effort parse and never a
plaintext fallback (control 17, probe 16).

## 3. Application

- `KeyProvider` SPI. Two failure kinds, never conflated (control 16, probe 11):
  `KeyUnavailableException` (`SHRED-KEY-UNAVAILABLE`, retryable, health DOWN, HTTP 503) and
  `KeyDestroyedException` (`SHRED-KEY-DESTROYED`, terminal, `ErasedValue`).
- `DataKeyService`: unwrap + bounded TTL cache (`ttl` 60s, `max-size` 10000), state checked on
  read *and* write, per-key encryption counter with WARN at 2^31 and refusal at 2^32 →
  auto-rotate to version n+1 (control 3, 7, probe 18).
- `FieldCipher`: encrypt/decrypt one field value with the AAD bound to
  tenant, subject, entity, field, key version.
- `ErasureService.erase(request)`: `SELECT … FOR UPDATE` on the key rows, DELETE the key rows and
  INSERT the chained erasure record **in one transaction** (control 6, probe 12), idempotent;
  nulls the subject's blind-index columns in the same transaction (control 10, probe 7); evicts
  the local cache and publishes an invalidation; then runs `PostErasureHook`s — a failed hook makes
  the record `PARTIAL`, never `COMPLETE` (control 19, probe 19).
- `ErasureChainVerifier`: statuses `EMPTY` / `INTACT` / `INTACT_UNKEYED` / `BROKEN` /
  `ANCHOR_MISMATCH` / `NO_ANCHOR` (control 8, probe 14).
- Ports: `DataKeyStore`, `ErasureRecordStore`, `ErasureAnchor`, `BlindIndexEraser`,
  `TenantContext`, `Clock`.

## 4. Starter — how a field gets encrypted

`AttributeConverter` is the mapping mechanism the spec asks for, but Hibernate hands a converter
nothing but the value: no entity, no attribute name, no session. Two consequences, both design
decisions recorded in QUESTIONS:

1. **Entity and field name come from the converter subclass** (QUESTIONS #1). The user writes one
   `@Converter` class per shredded field extending `ShreddedStringConverter` (or the `byte[]`,
   `LocalDate`, `BigDecimal`, JSON variant) and passes `("Customer", "email")` to `super`.
   Hibernate caches one converter bean per class, so a shared generic converter could not carry a
   field identity at all. A startup check cross-validates every `@Shredded` field against the
   `@Convert` that maps it and fails startup on a mismatch.
2. **Tenant and subject reach the write path through a Hibernate event listener.**
   `PreInsertEventListener` / `PreUpdateEventListener` fire immediately before
   `EntityInsertAction` / `EntityUpdateAction` bind the state array, i.e. immediately before the
   converters run; the matching `PostInsert` / `PostUpdate` listeners pop. The listener evaluates
   the `@Shredded(subject=…)` SpEL against the entity in a `SimpleEvaluationContext`
   (property read-only: no beans, no `T()`, no constructors, no method calls), parsed once at
   bootstrap, parse failure fails startup (control 14, probe 9). The read path needs no context:
   tenant and subject are in the blob header.
   A converter invoked with no context (bulk JPQL, criteria parameter) fails closed with
   `SHRED-CONTEXT-001`.
   The listener also computes `@BlindIndex` columns into the state array, one code path shared by
   write and query (control 10).
- **Subject immutability** (control 14, probe 10): the resolved subject is compared with the one
  in the loaded blob on update; a change is `SHRED-SUBJECT-IMMUTABLE`.
- **Startup closes the leak paths** (control 12, probes 5, 6): a `@Shredded` entity that is
  `@Cacheable`/`@Cache` fails startup unless `shredding.allow-second-level-cache=true`; the same
  for the query cache. An ArchUnit rule flags a `@Shredded` field reaching a generated
  `toString`/`equals`/`hashCode`; the sample greps its log for the plaintext fixture.
- **Master key** (control 5, probe 17): `shredding.master-key`, required, base64, >= 32 bytes,
  no default, sample values rejected at startup, read as `byte[]` and zeroised, and excluded from
  actuator `/env` and `/configprops` by an explicit `SanitizingFunction`, not by name luck.

## 5. Properties (control defaults, all `shredding.*`)

| Property | Default | Control |
|---|---|---|
| `master-key` | none, required | 5 |
| `dev-mode` | `false` (WARN at every startup when on) | 1 |
| `erased-value.policy` | `sentinel` (`exception`, `null` allowed; `null` WARNs every startup) | 13 |
| `allow-second-level-cache` | `false` | 12 |
| `crypto.max-encryptions-per-key` | `4294967296` (higher rejected at startup) | 3 |
| `data-key-cache.ttl` / `.max-size` | `60s` / `10000` | 7 |
| `erasure-log.hmac-secret` / `.hmac-key-id` / `.hmac-keys.<id>` / `.unkeyed` | required / `k1` / empty / `false` | 8 |
| `blind-index.hmac-secret` / `.bits` | required when any `@BlindIndex` / `64` | 10 |
| `erasure.backup-retention` | `30d`, printed in the proof and in `SECURITY-NOTES.md` | residuals |

There is no fail-open property anywhere in this module.

## 6. Schema (PostgreSQL, `schema-postgresql.sql`, advisory-locked, idempotent — B's shape)

- `shredding_data_key` PK `(tenant, subject, version)` (control 15), `wrapped_key bytea`,
  `state`, `encryption_count`, `created_at`.
- `shredding_erasure` append-only, `key_id NOT NULL`, `prev_hash`, `hash UNIQUE`,
  triggers refusing UPDATE / DELETE / TRUNCATE.
- `shredding_erasure_anchor` single row, `keyed boolean NOT NULL`, monotonic + immutable-`keyed`
  trigger, append-only triggers.

## 7. Test list

Unit (core, no Spring): HKDF against the RFC 5869 vectors; `EncryptedValue` round trip and every
rejection; AAD canonical form; blind-index determinism and per-tenant separation; erasure chain
link/verify; `ErasureChainVerifier` statuses; key state machine.

Integration (Testcontainers Postgres, image pinned by digest, same digest as B):
`JdbcKeyProvider`, `JdbcErasureRecordStore` + anchor + triggers, erase-in-one-transaction,
concurrent write vs erase.

Starter: auto-configuration, property validation, startup refusals, actuator sanitisation.

Sample: create customer, prove the column is unreadable via raw SQL, erase, prove the row remains,
the field reads as `ErasedValue`, the audit row keeps `customer_id`, the chain verifies, and the
log holds no plaintext.

### Cipher's 19 probes (each written RED first)

| Probe | Where |
|---|---|
| `probe_a_wrapped_key_row_restored_after_erasure_decrypts_the_value` | core, jdbc — documented residual, asserted present in `SECURITY-NOTES.md` |
| `probe_field_and_entity_names_collide_in_the_aad` | core, domain |
| `probe_ciphertext_moved_between_rows_still_decrypts` | core, application |
| `probe_reading_an_erased_entity_rewrites_the_column_on_flush` | sample, JPA |
| `probe_second_level_cache_serves_plaintext_after_erasure` | starter, startup |
| `probe_entity_tostring_leaks_the_decrypted_value` | sample |
| `probe_blind_index_still_matches_the_erased_subject` | core, jdbc |
| `probe_blind_index_matches_the_same_value_across_tenants` | core, domain |
| `probe_spel_expression_reaches_a_bean_or_a_static_type` | starter |
| `probe_changing_the_subject_expression_moves_a_row_out_of_erasure_scope` | starter |
| `probe_key_store_outage_reads_as_erased` | core, application |
| `probe_crash_between_key_destruction_and_the_erasure_record` | core, jdbc |
| `probe_concurrent_write_encrypts_under_a_destroying_key` | core, jdbc |
| `probe_an_unkeyed_or_unanchored_erasure_chain_reports_intact` | core, application |
| `probe_tenant_b_decrypts_tenant_a_value_for_the_same_subject_id` | core, application |
| `probe_core_reads_a_plaintext_column_as_plaintext` | core, domain |
| `probe_master_key_appears_in_actuator_env` | starter |
| `probe_encryption_passes_the_per_key_2_32_limit` | core, application |
| `probe_a_failed_post_erasure_hook_reports_complete` | core, application |

The spec body's "100k encryptions, no nonce collision" property test is **not** written: Cipher
replaced it (a 100k draw from 2^96 collides with probability ~2^-64, so the test cannot fail).
Replaced by: the nonce source is `SecureRandom`, the per-key counter refuses at 2^32, and a
stubbed narrow RNG is detected.

## 8. Risks

1. Hibernate listener ordering is the load-bearing assumption of the write path. If a future
   Hibernate release moves converter binding away from the insert/update action, the context goes
   stale — hence fail-closed on a missing context rather than a silent default, plus an
   integration test that asserts the context is present for every shredded write.
2. Erasure must null blind-index columns in the erasure transaction; that needs table and column
   names, which come from the `@BlindIndex` annotation and are validated at startup.
3. The `AttributeConverter` constraint costs the user one small class per shredded field.
   Runtime generation is the alternative and is listed in QUESTIONS #1.
4. Coverage: the JaCoCo 80% line gate applies to `-core`. The starter's Hibernate wiring is
   exercised through the sample.

## 9. Order of work

1. plan (this commit, `main`)
2. branch `feat/shredding-core`: build skeleton, ArchUnit, hooks, CI
3. crypto primitives (HKDF, AES-GCM, AAD, `EncryptedValue`) + probes 2, 16
4. keys, `KeyProvider` SPI, cache, counter + probes 11, 15, 18, 3
5. erasure chain + store + anchor + verifier + probes 12, 14
6. `ErasureService`, hooks, blind index + probes 7, 8, 19, 13, 1
7. starter: converters, listeners, SpEL, properties, startup checks + probes 5, 9, 10, 17
8. sample + probes 4, 6
9. docs, `SECURITY-NOTES.md`, `CHANGELOG.md`, coverage, draft PR
