# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
[semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- **Envelope encryption for JPA fields.** `@Shredded` on a `String`, `byte[]`, `LocalDate`,
  `BigDecimal` or JSON field, mapped by a two-line `AttributeConverter` subclass that names the
  entity and field. AES-256-GCM with a random 96-bit nonce and a 128-bit tag; per-subject data keys
  of 256 random bits, wrapped under a master key.
- **`EncryptedValue`**, a strict self-describing binary format with fixed offsets, a magic, a format
  version, an algorithm id, the key version, tenant, subject, nonce and an explicit ciphertext
  length. Unknown magic, unknown version, truncation and trailing bytes are typed errors. There is
  no plaintext fallback.
- **Length-prefixed canonical AAD** binding every value to tenant, subject, entity, field and key
  version, and every wrapped key to tenant, subject and key version.
- **`KeyProvider` SPI** with `JdbcKeyProvider` (a keys table wrapped under a master key from the
  environment) and `InMemoryKeyProvider` (refuses to start unless `shredding.dev-mode=true`). The
  contract separates `KEY_UNAVAILABLE` from `KEY_DESTROYED`.
- **`ErasureService`**: `SELECT ... FOR UPDATE` on the key rows, delete them, null the subject's
  blind-index columns and append the chained erasure record, all in one transaction. Idempotent.
- **Erasure log**: append-only, hash-chained, HMAC-keyed from row 1 with the key id inside the
  hashed material, an external anchor row, and triggers refusing `UPDATE`, `DELETE` and `TRUNCATE`.
  `ErasureChainVerifier` reports `EMPTY` / `INTACT` / `INTACT_UNKEYED` / `BROKEN` /
  `ANCHOR_MISMATCH` / `NO_ANCHOR`.
- **`PostErasureHook`**, run after the destruction commits; a failed hook makes the erasure
  `PARTIAL`, never `COMPLETE`.
- **`@BlindIndex`**: equality lookups over an encrypted column, per-tenant HKDF subkey, versioned
  normalisation shared by the write and query paths, truncated to `shredding.blind-index.bits`, and
  nulled for the erased subject.
- **Startup refusals** for the plaintext leak paths: a second-level cached `@Shredded` entity, a
  converter naming the wrong field, an unparseable or overreaching subject expression, and a
  sample-looking or short master key.
- **Actuator**: the three secret properties are removed from `/env` and `/configprops` by name, and
  a health contributor reports the key store's reachability and the erasure log's status.
- **`SECURITY-NOTES.md`** stating the residuals the technique cannot close: wrapped-key
  resurrection, backups and WAL, MVCC dead tuples, heap dumps, the cross-node cache window and the
  blind index's equality oracle.
- Hand-written HKDF (RFC 5869) verified against the standard's own vectors. Zero crypto
  dependencies in `-core`.

### Security

- Data keys are random and never derived from the master key; a derived key would be re-derivable
  for ever and erasure would be a no-op.
- An erased subject is tombstoned, so a write that was merely blocked on the erasure's row lock
  cannot mint a fresh key and undo the erasure. Found by
  `probe_concurrent_write_encrypts_under_a_destroying_key`.
- The per-key encryption counter refuses at 2^32 and rotates to the next key version rather than
  risking a GCM nonce collision.
- There is no fail-open property anywhere in the module; every weaker mode WARNs at every startup.
