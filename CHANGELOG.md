# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
[semantic versioning](https://semver.org/).

## [Unreleased]

### Fixed (fifth pass at `2f72449`)

Cipher's fifth-pass review (`docs/SECURITY-REVIEW-feat-shredding-core.md`, `## Fifth pass
(2f72449)`), 2026-09-09. Two of Isis's own two LOW-severity corrections closed; the four HIGH/MEDIUM
findings (C-33/C-34/C-39/C-40/C-41) and the one LOW (C-35) in that pass are one design stop -
`ShreddingContext`'s thread-local ownership and clearing rules - out of scope for this pass and left
for Thor's design.

- **C-37 (LOW)** - the reverse metamodel scan's `PluralAttributeMapping` branch walked
  `getElementDescriptor()` only; `getIndexDescriptor()` - a `@Convert` on a map key, or an
  `@OrderColumn`'s list index - was never walked, so a `ShreddedConverter` reached that way was
  modelled by neither the forward field scan nor the reverse one and started up unrefused (the first
  write then failed closed with `SHRED-CONTEXT-001`, but only in production, not at boot). Fixed:
  `ShreddedModel.scanAttribute` now also walks the index descriptor when non-null. New probe:
  `CipherProbeScanDepthTest.probe_a_shredded_map_key_in_an_element_collection_is_refused_at_startup`
  (the class's other two probes, covering two-level `@Embeddable` nesting and an `@ElementCollection`
  of basic values, were already green - C-29's recursion is sound).
- **C-38 (LOW)** - a `@Shredded` entity with a composite identifier (`@IdClass`/`@EmbeddedId`)
  started up and was then unreadable: both `onPostLoad` and `refuseIfSubjectMoved` return early when
  `getIdentifierColumnNames().length != 1`, so every read of a row carrying a stored shredded value -
  including rows the application wrote itself and nobody touched - was refused with
  `SHRED-READ-UNVERIFIED`. Fail-closed, but discovered on the first read in production instead of at
  boot. Fixed: `ShreddedModel.scan` now refuses at startup, naming the entity, the same as the
  existing `@SecondaryTable` refusal. New probes in `CipherProbeCompositeIdTest`
  (`probe_a_composite_id_shredded_entity_is_refused_at_startup`,
  `probe_a_moved_ciphertext_in_a_composite_id_entity_is_never_displayed` - rewritten, per Cipher's
  fix text, to build its own context in the shape of `CipherProbeScanDepthTest` rather than share a
  class-level `@SpringBootTest` context that can no longer come up). QUESTIONS.md #20 reclassified to
  this finding and closed.

### Fixed (fourth pass at `0ba0f6f`)

Cipher's fourth-pass review (`docs/SECURITY-REVIEW-feat-shredding-core.md`, `## Fourth pass
(0ba0f6f)`), 2026-09-09. Two HIGH, one MEDIUM, three LOW, all closed; one INFO documented.

- **C-26 (HIGH, and its false-refusal mirror)** - the read bracket's frame keyed a decode by
  `entityName + "." + fieldName` alone, with no row identity. Hibernate ORM 7.4 defers every row's
  `PostLoad` callback until the whole result set is hydrated, so a second row's converter silently
  overwrote the first row's entry: `repository.findAll(Sort)` over two rows of one entity either
  returned a moved ciphertext (the surviving entry happened to belong to the honest row) or refused
  two entirely legitimate rows (the surviving entry belonged to the *other* subject). Fixed by
  having `onPostLoad` independently re-read each loaded row's own stored shredded columns by id -
  the same `SELECT ... WHERE id = ?`, header only, that `refuseIfSubjectMoved` already runs on the
  write path - rather than trusting anything the converter recorded; the frame itself becomes a
  multiset keyed by `(entity, field, tenant, subject)`, incremented on record and drained by the
  exact key a fresh per-row re-read names, so N legitimate rows of one subject can each record and
  drain their own count. `ShreddingContext.recordDecoded`/`takeDecoded` are now
  `recordDecoded`/`drainDecoded`, taking the entity and field separately plus the header's tenant
  and subject; `ShreddingContext.Decoded` is removed. New probes:
  `probe_a_moved_ciphertext_in_a_second_row_of_one_result_set`,
  `probe_two_rows_of_two_subjects_read_in_one_query` (`CipherProbeFrameTest`).
- **C-27 (HIGH)** - a row refused by `onPostLoad` had already been registered, fully hydrated, in
  the session's first-level cache; a second read of the same id in the same transaction was a cache
  hit that returned the intact, decrypted entity with no converter and no `PostLoad` involved.
  `ShreddingEventListener.refuseLoad` now evicts the refused instance from the persistence context
  before the exception leaves the method, forcing a retry back through a real reload and this same
  check. Cipher's fix text also asked for the transaction to be marked rollback-only; that half was
  tried and reverted - see QUESTIONS.md #19 for why, with evidence. New probe:
  `probe_a_refused_row_is_returned_on_the_retry_from_the_persistence_context`.
- **C-29 (MEDIUM)** - the reverse metamodel scan (`refuseUnmodelledShreddedConverters`) inspected an
  entity persister's own top-level `BasicValuedModelPart` attributes only; a `@Shredded` field
  declared inside an `@Embeddable` or an `@ElementCollection` of embeddables - invisible to the
  forward field scan too - was fully encrypted on write and never checked on read at all. The scan
  now recurses into `EmbeddableValuedModelPart` and a `PluralAttributeMapping`'s element descriptor,
  refusing startup on any nested `ShreddedConverter`, naming its dotted path. New probes:
  `probe_a_shredded_field_inside_an_embeddable` (Cipher's own), and Dollar's mandated companion
  `probe_a_shredded_field_inside_an_element_collection_of_embeddables` (`CipherProbeEmbeddableScanTest`).
- **C-30 (LOW)** - `probe_a_second_row_in_the_same_result_set_is_never_verified` asserted only
  `isNotBlank()` on a two-shredded-field fixture (`Doc`), which let the wrong field's collision
  throw first and never actually exercised the moved field. Rewritten on `Widget` (one shredded
  field) asserting the specific `SHRED-SUBJECT-MISMATCH` code (`CipherProbeReadScopeTest`).
- **C-31 (LOW)** - `probe_an_in_place_mutation_of_an_immutable_byte_array_is_persisted` renamed to
  `..._is_silently_discarded`: the assertion always checked the mutation is lost (correct, per the
  third pass's C-21 ruling), the name promised the opposite (`CipherProbeMatrixTest`).
- **C-32 (LOW)** - `ShreddingContext.withReadBracket` caught `RuntimeException` only; an `Error`
  unwound past both `discardReadBracket()` and `popReadBracket()`, leaving the frame on a pooled
  thread. Rewritten with `try`/`finally` and an explicit "did the frame already close?" flag, so
  every path - normal return, any `Throwable` - closes the frame exactly once.
- **INFO** - documented that a `@Shredded` field must not be mapped `@Basic(fetch = LAZY)`
  (`docs/index.md`, `SECURITY-NOTES.md`): inert without Hibernate bytecode enhancement, which this
  module does not configure or test against.

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

### Fixed (third pass at `8095d2c`)

Cipher's third-pass review (`docs/SECURITY-REVIEW-feat-shredding-core.md`, `## Third pass
(8095d2c)`), 2026-09-09. Four HIGH, three MEDIUM, two LOW, all closed.

- **C-17 / C-18 (HIGH)** - a repository `@Query` scalar projection, and the Spring Data interface
  projection shape its own documentation recommends, both reached a `@Shredded` converter with the
  read bracket open and returned a moved ciphertext: the bracket was an unconditional permission
  granted by the caller's identity ("inside a repository call"), not a proof that anything would
  verify it, and a scalar/interface projection triggers no `onPostLoad` at all. `ShreddingContext`'s
  read bracket now owes a debt instead: `pushReadBracket()` opens a frame, `recordDecoded` files
  into it, and `popReadBracket()` throws `SHRED-READ-UNVERIFIED` - naming the field, never the
  plaintext - if anything in the frame was never drained by a verifier, before
  `ShreddingReadBracketCustomizer`'s proxy hands the repository method's result back to its caller.
- **C-19 (HIGH)** - `ShreddedModel.scan`'s forward pass only ever looked at field-level `@Shredded`;
  a column mapped through a class-level `@Convert(attributeName = ...)` (or an `orm.xml` mapping)
  was fully encrypted by the write path - the entity was in the model via a different, properly
  annotated field - and completely invisible to read verification, the `@Immutable` check and the
  second-level-cache refusal. `ShreddedModel.scan` now additionally walks the Hibernate runtime
  metamodel for every attribute whose resolved JPA converter is a `ShreddedConverter`, by whatever
  route, and refuses startup on any with no matching field-level `@Shredded` entry, naming the
  entity and attribute.
- **C-20 (HIGH)** - a repository bound to a second, hand-built `EntityManagerFactory` with no
  `ShreddingIntegrator` registered against it got the read bracket same as any other, and nothing
  ever verified its decrypts (no `onPostLoad` listener exists on that session at all). Closed
  primarily by C-17/C-18's frame accounting: a decrypt on an uninstrumented factory's session is
  recorded into the bracket's frame and nothing drains it, so the bracket refuses on its own, by
  construction. `ShreddingReadBracketCustomizer` additionally refuses startup outright when more
  than one `EntityManagerFactory` bean is present in the context, as defence in depth; see
  QUESTIONS.md C-20 for why that half ships without its own dedicated integration probe.
- **C-22 (MEDIUM)** - the bracket's decode-recording map was flat and bracket-wide, not per call:
  a projection's undrained decode could survive to be mistaken for a later, unrelated repository
  call's row inside the same transaction. Falls out of C-17's frame accounting: each repository call
  gets its own frame, checked and discarded when that call's bracket closes, so nothing can leak
  into a later call's frame.
- **C-21 (MEDIUM)** - the startup message mandating `@Immutable` on a `@Shredded byte[]` field
  claimed "nothing shares state and the claim is honest." The opposite is true: `@Immutable` is what
  stops Hibernate's dirty-checking snapshot from being a deep copy, and that snapshot is exactly what
  an in-place mutation is compared against - with no copy, the mutation is invisible to Hibernate and
  silently never persisted. The message, `ShreddedModel`'s javadoc, `README.md`, `docs/index.md` and
  `SECURITY-NOTES.md` now say so; this is a documentation fix, not a behaviour change (making the
  mutation persist would mean deep-copying the array again, reopening CIPHER-16). See QUESTIONS.md
  C-21.
- **C-23 (MEDIUM)** - `SHRED-READ-UNSCOPED`'s message named only "a scalar, `Tuple` or
  constructor-expression projection", which is not what a `Stream<T>`-returning repository method or
  a hand-written DAO's `EntityManager` use actually are; both are refused correctly, just misnamed.
  The message now names all of the real causes and points to `withReadBracket`, which is now
  documented in `README.md` and `docs/index.md` ("How the read path verifies") with an example for
  each of the three ways a read is verified.
- **C-24 (LOW)** - `ShreddingContext`'s javadoc, on the security-critical class, named
  `ShreddingReadBracketRepositoryFactoryCustomizer`, a class that does not exist; corrected to
  `ShreddingReadBracketCustomizer`.
- **C-25 (LOW)** - `ShreddingReadBracketCustomizer`'s proxy opened a bracket for `toString`,
  `equals` and `hashCode` too, for no reason (none of them reach a shredded converter); it now skips
  every `Object` method. The `BeanPostProcessor` now also implements `Ordered`
  (`Ordered.LOWEST_PRECEDENCE`, documented in a comment).

### Fixed (re-verification at `96713f9`)

Cipher's re-verification (`docs/SECURITY-REVIEW-feat-shredding-core.md`, `## Re-verification
(96713f9)`), 2026-09-09. Three HIGH, three MEDIUM, four LOW, all closed.

- **CIPHER-11 (HIGH)** - CIPHER-01's fix closed the ordinary entity load, but a scalar, `Tuple` or
  constructor-expression JPQL projection runs the converter with no `onPostLoad` (or any other
  Hibernate load listener) ever reaching it, so a moved ciphertext decrypted and returned with
  nothing to verify its header against. The header-versus-row check moves into
  `ShreddedConverter.convertToEntityAttribute` itself, the one place every decrypt goes through: a
  decrypt with an explicit read scope (`ShreddingContext.withRead(...)`) is verified atomically,
  right there; a decrypt inside the read bracket a Spring Data JPA repository call opens
  automatically (`ShreddingReadBracketCustomizer`, a `BeanPostProcessor` over every `Repository`
  bean) or a raw `EntityManager` entity operation opens explicitly
  (`ShreddingContext.withReadBracket(...)`) defers to the existing `onPostLoad`, as before; a
  decrypt with neither is refused outright (`SHRED-READ-UNSCOPED`). `onPostLoad` stays as
  belt-and-braces for every managed entity load. See QUESTIONS.md #16 for why the
  `PreLoadEventListener` shape offered as the first alternative does not work in this Hibernate
  version, with bytecode evidence, and why a `RepositoryFactoryCustomizer` bean - the documented
  Spring Data extension point for this - was replaced with a `BeanPostProcessor` after it did not
  reliably reach every `@EnableJpaRepositories` factory.
- **CIPHER-12 (HIGH)** - `onPostLoad` `return`ed on any `RuntimeException` from resolving the row's
  subject, including on a row carrying an already-decrypted shredded value - exactly the row an
  attacker who nulled the subject-source column wanted through. An unresolvable subject on a row
  that decoded at least one shredded field is now a refusal (`SHRED-SUBJECT-UNRESOLVED`) with a
  WARN naming the entity, never plaintext. A row with no decoded shredded value still loads despite
  an unresolvable subject, matching the ruling's own carve-out.
- **CIPHER-14 (HIGH)** - the update-time subject-immutability check read only `fields.get(0)`'s
  column and returned early when it was null, so an entity whose *first* shredded field happened to
  be null and whose *second* held a live ciphertext got no check at all: the subject could be
  changed and the row left its original subject's erasure scope permanently. The verification query
  now reads every shredded column of the entity in one query against its one table; early return
  only when every one of them is null. `ShreddedModel.scan` also now refuses a shredded entity whose
  fields span more than one table, since that query assumes a single table.
- **CIPHER-13 (MEDIUM)** - a projection's decoded header, never drained by `onPostLoad` (nothing
  reaches it), could survive on the thread and be mistaken for a later, unrelated row's header.
  Falls out of CIPHER-11 mostly by construction (an unscoped read is refused before it ever reaches
  `recordDecoded`); `onPostLoad` also now drains every field's decoded entry up front, before
  deciding anything, and `ShreddingContext.clearAll()` clears the read bracket, the read-scope stack
  and `DECODED_READS` at the same transaction boundary that already cleared the write scope.
- **CIPHER-15 (MEDIUM)** - `JdbcErasureStore.latestForSubject` ordered `ts DESC, seq DESC`; `ts` is
  the application clock and a backwards step between two appends could return an older `COMPLETE`
  ahead of a later `PARTIAL`, hiding an outstanding erasure. Orders by `seq DESC` only - the log's
  own monotonic column.
- **CIPHER-16 (MEDIUM) / QUESTIONS #15** - `ShreddedBytesConverter` refused its own entity's first
  insert under `@GeneratedValue(IDENTITY)`. Declaring the field
  `@org.hibernate.annotations.Immutable` stops `AttributeConverterMutabilityPlan` deep-copying the
  converted value (a second, out-of-bracket converter call) to build the dirty-checking snapshot;
  `ShreddedModel.scan` now requires the annotation on every `byte[]` `@Shredded` field, naming it at
  startup rather than on whichever row is inserted first. Covered end to end under both `IDENTITY`
  and `SEQUENCE`. `docs/index.md`'s "not production-ready" warning is replaced with the
  `@Immutable` requirement.
- **L11 (LOW)** - `JdbcSupport.lockSubject`'s javadoc claimed a fixed salt gave its advisory locks a
  namespace separate from the schema step's and the chain-append lock's, which
  `pg_advisory_xact_lock(bigint)`'s single flat 64-bit space cannot give (any collision was already
  harmless, but the comment claimed a property the code did not have). Switched to the two-argument
  `pg_advisory_xact_lock(int4, int4)` form, which *is* a genuinely separate namespace, and to the
  same length-prefixed canonical pairing used elsewhere in this module rather than a
  `"|"`-delimited string.
- **L12 (LOW)** - `SubjectExpression.evaluate` accepted any non-null resolved value via
  `String.valueOf`, so `#{#this}`/`#{#root}` (permitted by
  `SimpleEvaluationContext.forReadOnlyDataBinding()`, which restricts property navigation but not
  which root object a bare reference resolves to) silently became the subject
  `"ClassName@identityHashCode"` - a different value every run, encrypting the row under a key no
  later erasure could ever name. Refuses a resolved value that is not a `CharSequence`, `Number`,
  `UUID`, `Enum` or date/time value, and refuses a resolved string with the exact
  `Object.toString()` shape.
- **L13 (LOW)** - `pom.xml`'s third-party licence allowlist comment still called Apache-2.0 "the
  licence of this project", stale since the FSL-1.1-ALv2 switch.
- **L14 (LOW)** - `LogScanTest` never asserted its output capture observed anything, so a logging
  misconfiguration that captured nothing at all would have read as a pass. Asserts the capture
  contains a known-benign sentinel (`ShreddingStartupCheck`'s own start-up line) before asserting
  the plaintext fixture's absence.

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
