# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
[semantic versioning](https://semver.org/).

## [Unreleased]

### Changed
- **Licensing:** the free core switches from Apache-2.0 to the Functional Source License, Version
  1.1, ALv2 Future License (FSL-1.1-ALv2) - free to use, not as a base for a competing product,
  converts to Apache-2.0 two years after each version's release. Decision by Souhaile,
  2026-09-08; see `LICENSING.md` (portfolio-level) for the reasoning. `LICENSE` and `NOTICE`
  added at the repo root, `pom.xml` `<licenses>` updated, and `LICENSE`/`NOTICE` are now embedded
  in `gdpr-shredding-core` and `gdpr-shredding-spring-boot-starter`'s jars under `META-INF/`
  (same fix as agent-guard's M7). The reactor's own modules are excluded from the third-party
  licence scan by `groupId` (`excludedGroups`), not by licence name, since
  `com.housedevinci:gdpr-shredding-core` no longer matches the third-party allowlist.

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
- A `@Shredded` entity that is a record, or is annotated `@Data`, `@Value`, `@ToString` or
  `@EqualsAndHashCode`, fails startup: all of those generate a rendering over every field, so a
  decrypted value reaches the first log line that prints the entity.
- Under `shredding.erased-value.policy=sentinel`, the startup check WARNs naming every shredded
  field whose type has no value that can stand for "erased" (`LocalDate`, `BigDecimal`), which read
  as `null`. No fake sentinel is invented for them.

### Documentation

- Regulatory references verified and corrected. EDPB Guidelines 5/2019 (search-engine delisting
  only) and the CNIL's algorithm-guidance page are **removed**: neither addresses key destruction.
  The sources are now GDPR Art. 17(1) and 32(1)(a) with Recitals 26, 28, 29 and 83; A29WP Opinion
  05/2014 (WP216) Section 4 and 4.1 to 4.3; CNIL, "Recherche scientifique (hors sante)"; and the
  ICO's "Right to erasure" backups section.
- The product no longer describes itself as erasing, deleting or anonymising anything without
  qualification. What it does is render data permanently unreadable by destroying the subject's key,
  which regulators classify as **pseudonymisation with key destruction**. New FAQ entry, "Is this
  legally erasure?", answers the question honestly with the three sources.

### Fixed

Cipher's first PR review (`docs/SECURITY-REVIEW-feat-shredding-core.md`), 2026-09-08. Two HIGH, eight
MEDIUM, ten LOW/INFO, all closed.

- **CIPHER-01 (HIGH) / QUESTIONS #4** - a ciphertext moved into another subject's or another
  tenant's row decrypted and displayed, and survived the row owner's own erasure, because the read
  path trusted the blob's own header as the row's identity. `ShreddedConverter` now records what
  each field's header actually said; `ShreddingEventListener.onPostLoad` compares it against the
  row's true, resolved subject and tenant once the entity is hydrated and refuses
  `SHRED-SUBJECT-MISMATCH` before the entity is returned to any caller. The write path gets the
  matching half: `onPreUpdate` fetches the row's current header with a second query and refuses
  `SHRED-SUBJECT-IMMUTABLE` before re-encrypting. The bounded per-thread map this replaced is
  deleted. See QUESTIONS.md #13 for why the read-path check cannot fire "before the key store is
  touched" the way the literal fix text asked, and #14 for why the "skip when not dirty"
  optimisation was removed as unsound.
- **CIPHER-03 (HIGH)** - a write racing the *first* key mint for a subject could commit a live key
  after that subject's erasure committed, with the erasure log still reporting `COMPLETE`. Every
  path that mints or erases now takes `pg_advisory_xact_lock(tenant, subject)` first, in the same
  transaction, so the two can never both observe "no row, no tombstone" at once.
- **CIPHER-04 (MEDIUM)** - `shredding_erased_subject` gets the same append-only triggers as
  `shredding_erasure`: the runtime role's INSERT grant no longer also permits DELETE.
- **CIPHER-05 (MEDIUM)** - all four append-only trigger guards now resolve `tgrelid` against
  `current_schema()` instead of a bare trigger name, so a second schema on the same database is no
  longer silently left unguarded.
- **CIPHER-02 (MEDIUM)** - a repeat erasure of a subject with an outstanding `PARTIAL` record no
  longer reports `COMPLETE` on the strength of "no key left"; it reads the trail's actual last
  outcome, and if it is not `COMPLETE`, re-runs every hook and reports what they do now.
- **CIPHER-06 (MEDIUM)** - the Lombok half of the generated-rendering startup check was dead code
  (`lombok.Data` et al. are `SOURCE`-retained and never reach the class file); the claim is removed
  from the code and the docs, the record check stays, and the sample's ArchUnit rule is the
  documented reference for the Lombok case.
- **CIPHER-07 (MEDIUM)** - `shredding.erasure-log.unkeyed=true` fed the subject pseudonymiser a
  literal constant printed in this module's own source, making the pseudonym HMAC a public
  function. `shredding.subject-pseudonym.pepper` is now a required secret in that mode, and the
  unkeyed WARN names the consequence.
- **CIPHER-08 (MEDIUM)** - a write that never reached `PostInsert`/`PostUpdate` (a converter
  refusal, a constraint, a failure inside `writeBlindIndexes`) could leave a scope on a pooled
  thread for the next, unrelated write to inherit. The push is now bracketed in `try`/`finally`,
  and a transaction-boundary callback clears the whole stack regardless of how the write ended.
- **CIPHER-09 (MEDIUM)** - the cache startup check only ever looked at `@Cacheable`/`@Cache` on the
  entity class, missing `jakarta.persistence.sharedCache.mode=ALL`/`DISABLE_SELECTIVE` (which
  caches every entity regardless of annotation) and the query cache entirely. Both are now checked
  against the `EntityManagerFactory`'s resolved properties, under the same escape hatch and WARN.
- **CIPHER-10 / M8 (MEDIUM)** - `probe_tenant_b_decrypts_tenant_a_value_for_the_same_subject_id`
  stayed green with `tenant` removed from `Aad.forValue`, because relabelling the header's tenant
  fails the *wrap* AAD first. A new probe isolates the value AAD specifically, using a
  `KeyProvider` that hands back identical key material for every tenant.
- **L1** - the hexagonal-boundary ArchUnit rule for `domain` is now an allowlist
  (`java..`, `javax.crypto..`, the domain package itself), not a denylist that only holds for as
  long as somebody keeps adding to it.
- **L2** - the JaCoCo `prepare-agent`/`report`/`check` executions moved from `gdpr-shredding-core`'s
  own POM to the parent's `<build><plugins>`, so all three modules now produce a coverage report and
  are held to a gate: 80% line for the core and the starter, a 30% smoke gate for the sample. The
  starter's own tests previously never exercised `ShreddingEventListener`, `ShreddingContext` or
  the auto-configuration's bean graph at all (0% on those classes); `ShreddingIntegrationTest` now
  does, with local fixture entities and Testcontainers PostgreSQL.
- **L3** - `JdbcSupport.runtimeRoleOwnsErasureTable`, correct and tested but never called, is now
  called from `ShreddingStartupCheck` and WARNs when the runtime role owns the erasure tables.
- **L4** - the sample gets a real log-scan test (`LogScanTest`, `OutputCaptureExtension`) that
  drives create/read/erase/a failed write and greps the captured output for the plaintext fixture.
- **L5** - `JdbcErasureStore.markDestroying`, an `UPDATE` that no other transaction could ever
  observe before the row it marked was deleted in the same transaction, is removed along with the
  comment that claimed otherwise.
- **L6** - `ErrorCodes.KEY_EXHAUSTED`, declared and never thrown (`FieldCipher` rotates instead of
  refusing), is removed from the code and from the error-code table in the docs.
- **L7** - the sample's read endpoint now takes the tenant explicitly (`GET
  /customers/{tenantId}/{customerId}`) instead of looking up by `customerId` alone; the erasure
  endpoint is behind HTTP Basic (`SecurityConfig`, one user, a copyable shape not a real
  authorization model) and takes `requestedBy` from the authenticated principal, never from the
  request body.
- **L8** - `probe_master_key_appears_in_actuator_env` only ever called the `SanitizingFunction`
  bean directly; `CipherProbeActuatorEndToEndTest` now stands up the sample with `/env` and
  `/configprops` exposed and reads them for real.
- **L9** - `probe_second_level_cache_serves_plaintext_after_erasure` (renamed
  `the_startup_check_refuses_a_cacheable_shredded_entity`) asserted the refusal, not a cache
  actually serving plaintext; see CIPHER-09 above for the coverage gap it also had.
- **L10** - `JdbcErasureStore.decodeHooks` threw a raw `NumberFormatException` on a malformed
  `hook_outcomes` column; it now throws `SHRED-INVALID-001`, and `ErasureChainVerifier` reports
  `BROKEN` for a row that will not decode instead of letting the error escape unhandled.
- **I1** - recorded in `SECURITY-NOTES.md`: the subject/tenant SpEL evaluation context still
  permits reading `getClass()`, not exploitable today because the expression is written by the
  application author at compile time.
- **I2** - `MasterKey.REFUSED` now matches the whole (trimmed, case-folded) value exactly, not as a
  substring, so a genuine random key cannot be refused for merely containing a sample token.
- **I3** - `shreddingErasureChainVerifier` refuses at startup if `shredding.erasure-log.hmac-keys`
  repeats the active key id with a different secret, instead of silently letting the map entry
  replace it in the keyring.

### Security

- Data keys are random and never derived from the master key; a derived key would be re-derivable
  for ever and erasure would be a no-op.
- An erased subject is tombstoned, so a write that was merely blocked on the erasure's row lock
  cannot mint a fresh key and undo the erasure. Found by
  `probe_concurrent_write_encrypts_under_a_destroying_key`.
- The per-key encryption counter refuses at 2^32 and rotates to the next key version rather than
  risking a GCM nonce collision.
- There is no fail-open property anywhere in the module; every weaker mode WARNs at every startup.
