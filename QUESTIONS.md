# QUESTIONS — open decisions on the GDPR Shredding free core

Numbered, with the answer I took and why. **Dollar ruled on all ten on 2026-09-08**; each entry
carries the ruling and what it changed in the code. #4 stays open for Cipher to pick between two
options, and #10 stays open until Odin returns the citations. **#21, #22, #23 and #24 are open for
Cipher** — the three residuals the read-path redesign leaves behind, each with the boundary stated
and a recommendation.

---

## #1 One converter class per shredded field (taken; would like a second opinion)

**Decision.** A `@Shredded` field is mapped by its own two-line `@Converter` class extending
`ShreddedStringConverter` (or the `byte[]`, `LocalDate`, `BigDecimal`, JSON variant) whose
constructor passes the entity and field name to `super`.

**Why.** Hibernate resolves an `AttributeConverter` through the managed bean registry, which caches
**one instance per class**, not one per attribute. A single shared `ShreddedStringConverter` would
therefore have no idea which entity and field it was protecting - and that pair is precisely what
the AAD binds (Cipher's control 2). Without it, a ciphertext can be moved from `Customer.email` to
`Customer.phone` and still decrypt.

**The alternatives I rejected, and why.**

- *A `UserType` implementing `DynamicParameterizedType`.* Hibernate does hand a `UserType` the
  entity and property name. But the spec and Dollar's constraint both say `AttributeConverter`, and
  a `UserType` is a deeper, less stable Hibernate SPI.
- *Generating one converter class per field at bootstrap with ByteBuddy.* Hibernate already depends
  on ByteBuddy, so it is not a new dependency, but it means contributing to the Hibernate mapping
  programmatically at boot and generating classes at runtime - real complexity in the one part of
  the module that must be obviously correct. It is the right thing for the Pro edition if users
  complain about the boilerplate.
- *Reading the field name from a thread-local cursor maintained per property.* Fragile and
  undocumented ordering. Rejected outright.

**Cost.** Two lines of user code per shredded field, cross-checked at startup so a copy-pasted
converter fails the build rather than binding two fields to one AAD.

**Ruling (Dollar, 2026-09-08): accepted.** Hibernate caches one converter per class, so a two-line
converter per shredded field is the honest design. An annotation processor that generates them is a
later improvement, not now. **Applied:** noted as such in `docs/index.md` under "Why one converter
class per field".

---

## #2 A shared chain library (deferred, as instructed)

The erasure log is module B's audit chain copied and adapted: keyed from birth, key id in the hashed
material, length-prefixed canonical form, external anchor row, the same six verifier statuses, the
same trigger set. Three things differ and are not cosmetic: the record's fields, the pseudonymised
subject, and the fact that this chain's key is explicitly never destroyed by an erasure.

**Recommendation.** Extract `housedevinci-chain` after module D, when there are three call sites and
the shape has stopped moving. Extracting it now would freeze an API on a sample of two.

**Ruling (Dollar, 2026-09-08): agreed, after module D.**

---

## #3 Erased subjects are tombstoned (taken; a real deviation from the spec's wording)

Cipher's control 6 says the erasure is "a delete of the key row". It is. But
`probe_concurrent_write_encrypts_under_a_destroying_key` found that a write which was merely blocked
on the erasure's `FOR UPDATE` then found no row, concluded "this subject has no key yet" and minted
a fresh one - undoing the erasure inside a millisecond, with nothing in the log to say so.

The fix is a `shredding_erased_subject` row holding **no key material at all**: the key rows are
genuinely deleted, and a separate marker records that this subject is erased so `mint` refuses.
This is not the "overwrite then delete" theatre control 6 rejects (that leaves a second heap tuple
holding the same key); it is the record that makes control 11 enforceable at all.

**Ruling (Dollar, 2026-09-08): accepted in principle; Cipher verifies it.** **Applied:**
`SECURITY-NOTES.md` gains a section stating that the tombstone holds no key material and exists only
so a concurrent writer cannot mint a fresh key for an erased subject, and `SPEC.md`'s Threats
section gains the case as one line.

---

## #4 Subject immutability is enforced from a bounded per-thread map (taken; a known gap)

Control 14 requires that a persisted row's data subject cannot change. Hibernate's `PreUpdateEvent`
carries the *hydrated Java* state, not the stored blob, so the previous subject cannot be read from
the row at that moment. The listener therefore remembers the subject a row loaded (or was inserted)
under, in a per-thread, access-ordered map bounded to 10 000 entries, and refuses an update whose
resolved subject differs.

**The gap.** If the entry has been evicted, or the entity is updated in a thread that never loaded
it (a detached merge from another request), the check cannot fire and the update is allowed.

**The two stricter options, for Cipher to choose between.**

- **(b) A shadow subject column.** The entity carries a persistent column holding the subject
  captured at first persist; `PreUpdate` compares against the loaded value, which is always present
  because it came out of the row. Cost: it changes the user's schema and adds a column to every
  shredded entity. Benefit: the check can never fail to fire, in any thread, detached or not.
- **(c) Read the stored blob in `PreUpdate`.** A second query fetches the row's current ciphertext
  and decodes the subject from its header, which is already there. Cost: one extra round trip per
  shredded update, on the hot path. Benefit: no schema change, and it is correct for detached
  merges too.

**My recommendation: (c).** The blob already carries the subject, so (c) needs no new state
anywhere and cannot drift out of sync with the ciphertext the way a shadow column can. The round
trip is on updates to shredded entities only, and it can be skipped entirely when no shredded field
is dirty. (b)'s schema change is the kind of thing that stops a team adopting the library.

**Ruling (Dollar, 2026-09-08): ship the per-thread approach now; Cipher picks between (b) and (c)
in its pass.** **Applied:** both options are written out above with my recommendation, and the gap
is stated as a residual in `SECURITY-NOTES.md` until Cipher decides.

---

## #5 `LocalDate` and `BigDecimal` have no sentinel (taken)

There is no `LocalDate` or `BigDecimal` value that means "erased". Those two types read as `null`
after an erasure whatever `shredding.erased-value.policy` says. I refused to use `0` or
`LocalDate.EPOCH`: a zero balance is a fact and an erased balance is not.

Documented in the Javadoc and in `docs/index.md`.

**Ruling (Dollar, 2026-09-08): accepted, no fake sentinel values.** The rule is: under policy
`sentinel` those types read as `null` **and the startup scan logs a WARN listing every shredded
field whose type cannot carry a sentinel**; under policy `exception` they throw like the others.
**Applied:** `ShreddedConverter.carriesSentinel()` (false on the `LocalDate` and `BigDecimal` base
classes), `ShreddedModel.fieldsWithoutSentinel()`, and the WARN in `ShreddingStartupCheck`, covered
by `the_scan_names_the_fields_whose_type_cannot_carry_a_sentinel`.

---

## #6 A single ambient tenant supplier (taken)

Control 15 makes the tenant mandatory with no default. The starter ships a `TenantSupplier` that
returns `null`, which the listener turns into `SHRED-TENANT-MISSING`. An application either supplies
its own bean or puts a tenant expression on `@Shredded`.

Tenantify integration is a Pro concern per `LICENSING.md`, so core deliberately does not depend on
it.

---

## #7 Blind-index erasure needs the subject and tenant columns named (taken)

To null a blind-index column in the erasure transaction the store needs the table and the two
columns to match on, and none of them can be a bind parameter. `@BlindIndex` therefore takes
`subjectColumn` and `tenantColumn`, both validated at startup against `[a-z_][a-z0-9_]{0,62}`.

The alternative was to derive them from the JPA metamodel. That works when the subject expression is
a plain property of the same entity and breaks the moment it is `#{owner.id}`. Explicit beats
clever here.

---

## #8 The cache invalidation is local only (taken, and documented as a residual)

Control 7 says an erasure "evicts locally and publishes an invalidation; other nodes still hold the
unwrapped key for up to the TTL". The free core does the local eviction and documents the window.
It does **not** publish a cluster-wide invalidation, because core has no message bus and adding one
(Redis, or a database `LISTEN/NOTIFY`) is a dependency decision I did not want to take alone.

**Recommendation.** Ship the free core with the documented 60-second window - which is honest, and
which the proof of erasure states - and put the cross-node invalidation in Pro alongside the KMS
adapters.

**Ruling (Dollar, 2026-09-08): accepted for core; Pro gets cluster invalidation with the KMS
adapters.** **Applied:** `docs/index.md` gains a "The cross-node cache window" section and a row in
the free-versus-Pro table.

---

## #9 The `toString` leak rule is a sample-level ArchUnit test (taken)

Control 12 asks for "the module's ArchUnit rule" flagging a `@Shredded` field reaching a generated
`toString`/`equals`/`hashCode`. The rule lives in the sample, because it has to run against the
*application's* entities, not the library's own classes, and a library cannot run ArchUnit inside
its users' builds.

**Recommendation.** Ship the rule as a documented snippet users paste into their own test sources
(the sample is that snippet), and add the record check to the startup scan so at least the worst
case - an entity that is a record - fails without any test at all.

**Ruling (Dollar, 2026-09-08): add the startup check; keep the ArchUnit rule in the sample as the
reference for users.** **Applied:** `ShreddedModel.refuseGeneratedRendering` fails startup for a
`@Shredded` entity that is a record or is annotated `@Data`, `@Value`, `@ToString` or
`@EqualsAndHashCode` - all of which generate a rendering over every field. Covered by
`a_record_entity_with_a_shredded_field_fails_startup`. The sample's ArchUnit rule stays as the
copyable reference for the cases only the user's own code can see.

---

## #10 Regulatory citations are placeholders until checked (flagged)

`docs/index.md` names EDPB Guidelines 5/2019, the CNIL's encryption guidance and the ICO's right-to-
erasure page. The acceptance check asks for exact section numbers and links. I have not verified the
section numbers, and I will not invent them.

**Ruling (Dollar, 2026-09-08): Odin is verifying the EDPB / CNIL / ICO section numbers; leave the
placeholders greppable.** **Closed the same day: Odin returned, and two of the three were wrong.**

- **EDPB Guidelines 5/2019 removed.** They cover search-engine delisting and say nothing about
  encryption or key destruction. Citing them would have been the worst kind of citation: real
  document, wrong subject.
- **CNIL "Chiffrement, hachage, signature" removed.** Algorithm guidance, nothing on key
  destruction. Replaced with CNIL, "Recherche scientifique (hors sante) : enjeux et avantages de
  l'anonymisation et de la pseudonymisation", which does address deleting the key or the
  correspondence table.
- **A29WP Opinion 05/2014 (WP216) Section 4 added**, which is the load-bearing source: encryption
  with key deletion is *pseudonymisation*, not anonymisation.
- **GDPR Art. 17(1) and 32(1)(a) with Recitals 26, 28, 29 and 83 added**, and the ICO's "beyond
  use" backups section quoted exactly.

**Applied:** the references in `docs/index.md` are replaced verbatim, every `TODO-CITATION` is gone,
and the wording rule below follows from these sources.

---

## #11 Wording: this is pseudonymisation with key destruction (taken; ruled)

**Ruling (Dollar, 2026-09-08).** The module performs **crypto-shredding**, which regulators
classify as pseudonymisation with key destruction. "Erases", "deletes", "anonymises" and
"GDPR-compliant erasure" are not to be used as unqualified claims anywhere in the product. The
sanctioned phrasing is: *renders the data permanently unreadable by destroying the subject's key;
the row survives; regulators treat this as pseudonymisation with key destruction, and the residual
risks are listed in SECURITY-NOTES*. The launch article title stays a question.

**Applied.** `README.md` (headline and the honest-bound bullet), `docs/index.md` (opening and a new
FAQ entry "Is this legally erasure?"), `SECURITY-NOTES.md` ("What crypto-shredding actually
claims"), `gdpr-shredding-sample/README.md`, and `SPEC.md` lines 6, 73 and 78, which overstated the
position and are corrected with a dated note.

The API keeps the words `erase`, `ErasureService` and `ErasureRecord`: they name an operation the
application performs and a record of it, and renaming the public API to `PseudonymisationService`
would be worse for users than a documented qualification. Say so if you disagree; it is a rename,
not a redesign.

---

## #13 CIPHER-01 / #4: the read-path check cannot fire "before the key store is touched" (taken; a deviation, with evidence)

Cipher's fix text asks for `FieldCipher.decrypt` to "take the expected tenant and subject ... and
refuse ... before it touches the key store". That is achievable for the write path (`PreUpdate`
fetches the row's current header with a second query, entirely before any key is touched) but not
for the read path, and I want the reasoning on record rather than a fix that reads as literal
compliance and is not.

**Why not.** A JPA `AttributeConverter` is handed nothing but the column bytes: no entity, no
session, no row. I checked this against the actual Hibernate ORM 7.4 loader bytecode this project
builds against (`EntityInitializerImpl`, disassembled with `javap`, not assumed): every attribute
converter on a row - every `@Shredded` field's `decrypt` included - has already run by the time the
*first* Hibernate listener fires for that row, `PreLoadEventListener` included. There is no hook
that fires before a converter runs on read, unlike the write path, where `PreInsertEvent` and
`PreUpdateEvent` genuinely do fire before the SQL statement binds. Cipher's own fix text anticipates
this ("or resolves the subject in onPostLoad before the converters' values are handed out") and I
took that alternative.

**What is implemented instead.** `ShreddedConverter` decodes the header the instant it decrypts and
records it (`ShreddingContext.Decoded`); `ShreddingEventListener.onPostLoad` - once the whole entity
is hydrated - resolves the row's true subject and tenant the way the write path does, compares, and
throws `SHRED-SUBJECT-MISMATCH` on a mismatch. The load throws, so the entity is never returned to
any caller. This delivers the property CIPHER-01 actually names ("still decrypts and is displayed"
- it is not displayed, because the call that would have returned it throws instead), even though a
few instructions of internal, never-externalised decryption happen first. Full detail and the one
residual this leaves (a same-type join fetch inside one JDBC row) is in `SECURITY-NOTES.md` under
"A moved ciphertext is refused after the load that read it has already run".

Probes: `probe_a_blob_moved_into_another_subjects_row_still_decrypts` and
`probe_a_blob_moved_into_another_tenants_row_still_decrypts` (sample, real Hibernate hydration) both
RED before this fix, GREEN after.

## #14 QUESTIONS #4 ruling (c)'s dirty-skip optimisation is unsound without @DynamicUpdate (taken; a deviation, found by a failing probe)

The ruling says: "Skip the extra round trip entirely when no `@Shredded` field of the entity is
dirty." I implemented that first, and my own new probe -
`probe_changing_the_subject_expression_moves_a_row_out_of_erasure_scope_on_a_detached_merge` - went
green when it should have gone red: it changes `customerId` (the subject's source property) and
leaves `email`/`phone` untouched, so by Java-value comparison no `@Shredded` field is "dirty" and
the check was being skipped, exactly on the update it exists to catch.

**Root cause.** `Customer` is not `@DynamicUpdate`, and neither is anything else in this codebase.
Hibernate's default `UPDATE` statement writes every basic column unconditionally, so every shredded
field's `convertToDatabaseColumn` runs again on *every* update to the entity, whether or not its
Java value changed. "No shredded field dirty" (comparing Java values) therefore does not imply "no
re-encryption is about to happen" the way the ruling's optimisation assumes; that implication only
holds under `@DynamicUpdate`, which this module does not require and cannot assume.

**Fix.** The dirty check is removed; `refuseIfSubjectMoved` runs on every update to a shredded
entity. Detecting the sound version of the optimisation (`persister.isDynamicUpdate()` combined
with per-property dirtiness) is more moving parts in a check whose entire job is to be correct than
the one extra query per shredded update it would save. If a later release adds `@DynamicUpdate`
support explicitly, the skip can come back conditioned on that flag; until then it does not exist.

The probe above is RED-then-GREEN evidence for this fix, not just for the fix that motivated it.

## #15 ShreddedBytesConverter refuses its own entity's first insert under @GeneratedValue(IDENTITY) (found; flagged, not fixed - out of scope for this pass)

Found while writing `ShreddingIntegrationTest` for the L2 coverage gate, not from Cipher's list.
An entity with a `byte[]` `@Shredded` field (`ShreddedBytesConverter`) and
`@GeneratedValue(strategy = GenerationType.IDENTITY)` fails its own first `save()` with
`SHRED-CONTEXT-001`, "no shredding context while writing". No such entity exists anywhere else in
this codebase (`Customer` in the sample and `Widget` here are both `String`-typed shredded fields),
so this had never been exercised end to end before.

**Cause, as far as I traced it.** Hibernate's `MutableMutabilityPlan` deep-copies a converted
attribute's value - calling `convertToDatabaseColumn` a second time - to build the managed entity's
dirty-checking snapshot, for any Java type it considers mutable. `byte[]` is mutable by default;
`String`, `BigDecimal` and `LocalDate` are not, which is why `Widget` and `Gadget`'s other three
shredded fields (added to raise this module's coverage, see `fixture/Gadget.java`) never hit it.
That deep-copy call happens outside the `onPreInsert`/`onPostInsert` bracket - stack trace bottoms
out in `AttributeConverterMutabilityPlan.deepCopyNotNull`, not in the ordinary bind-parameter path -
so `ShreddingContext.require` correctly refuses it as an unscoped write, which is exactly right for
what the check is doing; the bug is that a legitimate, scoped write is reaching that code path at
all.

**Why not fixed here.** It is not one of Cipher's findings, and understanding it well enough to fix
it without breaking `ShreddedConverter`'s general contract - probably telling Hibernate the
converted type is immutable, which for `byte[]` specifically usually means providing a
`MutabilityPlan` alongside the converter rather than changing the converter's own methods - needs
more investigation than a remediation pass has room for. Flagging it here so it is not lost:
**`ShreddedBytesConverter` should be treated as not production-ready until this is fixed and
covered by a regression test**, and the docs (`docs/index.md`'s converter list) should say so until
then.

## #16 CIPHER-11: the `PreLoadEventListener` shape does not work in this Hibernate version (taken; a deviation, with evidence); `RepositoryFactoryCustomizer` replaced with a `BeanPostProcessor` (found by a failing probe)

Cipher's fix text for CIPHER-11 offered two shapes and said either was acceptable: (1) a
`PreLoadEventListener` that resolves the row's subject/tenant from the identifier and the loaded
state array and pushes a read scope before the converter runs, or (2) make
`convertToEntityAttribute` fail closed when no read scope is present at all, relying on the
application to open one.

**Shape (1) is not available.** `ShreddingContext.Decoded`'s javadoc, written in the previous
remediation round and accepted by Cipher under QUESTIONS #13 ("she disassembled
`EntityInitializerImpl` in the Hibernate 7.4 this module builds against and showed every converter
has run before the first load listener fires"), already established this for `onPostLoad`. I
re-checked it specifically for `onPreLoad` this round: `javap -c` on
`EntityInitializerImpl.resolveEntityState` (Hibernate ORM 7.4.5.Final) shows the method building the
row's full Java-level attribute state - which for a `@Shredded` field means invoking
`AttributeConverterBean.toDomainValue`, i.e. the converter, i.e. the decrypt - and only afterwards
constructing and firing `PreLoadEvent` with that already-built state
(`PreLoadEvent.setState([Ljava/lang/Object;)`). There is no Hibernate hook, `PreLoad` included, that
fires before an entity row's own shredded columns are decrypted. Cipher's own CIPHER-01 finding
established this for `onPostLoad`; it is equally true for `onPreLoad`, which a `PreLoadEventListener`
would need in order to gate anything.

**Shape (2), taken, with a mechanism for "no read scope" that is not simply "not
`ShreddingContext.withRead(...)`".** A literal, unconditional "no scope ⇒ refuse" would refuse
every ordinary `repository.findByX(...)` too, since nothing pushes a scope for those today. Rather
than require every application to wrap every entity read explicitly - which the "entity path is the
relaxation, not the mechanism" framing in Cipher's own fix text argues against - the converter
distinguishes three cases: an explicit read scope (verified atomically, right there); the "read
bracket" open (defers to the existing, now-fixed `onPostLoad`/`refuseIfSubjectMoved`, i.e. today's
behaviour for entity loads); neither (refused, `SHRED-READ-UNSCOPED`). The read bracket is what
makes shape (2) practical without becoming shape (1) by another name: it does not try to establish
the *row's* true subject before decrypt (impossible, per the evidence above); it only marks "this
decrypt is happening inside something that will get `onPostLoad`'s verification afterwards; if it
does not, refuse."

**How the bracket is opened, and why not `RepositoryFactoryCustomizer`.** Cipher's fix text does not
prescribe a mechanism for opening it, only that an entity load should not need the application to
open one by hand. `RepositoryFactoryCustomizer` is the documented Spring Data extension point for
exactly this ("customize how repository proxies are built"), and it is what I wrote first: a
`@Bean` that calls `factory.addRepositoryProxyPostProcessor(...)` to add a `MethodInterceptor`
around every repository method. **It does not work**: a failing probe (`widgets.findByOwnerId(...)`
throwing `SHRED-READ-UNSCOPED` from inside a plain, unmoved read) showed the advice never runs, on
this Spring Boot/Spring Data generation, for `@EnableJpaRepositories`-declared repositories built the
ordinary way. I did not chase why further once I had a working alternative - `BeanPostProcessor`,
registered as a `static` `@Bean` with `postProcessAfterInitialization` wrapping every bean that is
an `org.springframework.data.repository.Repository` in a decorating `java.lang.reflect.Proxy` that
opens the bracket around every method call. This is a plainer, lower-level Spring SPI that every
singleton bean in the context goes through unconditionally, including a `Repository` proxy produced
by a `FactoryBean`, and the same probe is green against it. If a later Spring Data release makes
`RepositoryFactoryCustomizer` reach these repositories reliably, the `BeanPostProcessor` can be
dropped in its favour; until then, note the deviation here rather than leave a comment claiming a
mechanism that measurably does not fire.

**A raw `EntityManager` entity operation** - `find`, `merge`, `refresh`, an entity-returning
JPQL/Criteria query, none of which go through a Spring Data repository - needs the same relaxation
for the same reason (`EntityManager.merge` in particular re-loads the row's current persisted state
internally to reconcile it against a detached instance, reaching a shredded converter exactly like
any other load). `ShreddingContext.withReadBracket(...)` is the public, documented way an
application opens it explicitly for this case; `SampleEndToEndTest`'s detached-merge probe (QUESTIONS
#4) now uses it. `ShreddingContext.withRead(...)` stays reserved for the different, verified case: a
caller who actually knows and vouches for the row's subject, typically a projection.

## #12 ENISA pseudonymisation report: section to verify (open)

An ENISA pseudonymisation report is the obvious fourth source, and I have seen it cited for exactly
this technique. **Odin could not verify a section**, so it is deliberately not in `docs/index.md`:
an unverified citation is worse than none. Left here so it is not lost. Someone with the report open
needs to give a title, year and section before it goes into the docs.

## #17 C-20 second half: the coarse multi-`EntityManagerFactory` startup refusal ships without its own integration probe (taken; a deviation, proven)

Cipher's fix text (`## Third pass (8095d2c)`, item 3) offered two shapes for closing C-20's second
half: "bind the bracket and the startup scan to the instrumented `EntityManagerFactory`; a
repository bound to a non-instrumented EMF is refused at startup (`SHRED-EMF-UNINSTRUMENTED`) rather
than bracketed" - or, explicitly, "refuse at startup when more than one `EntityManagerFactory` is
present and the shredded entities are not all on the instrumented one."

**The primary control does not depend on either shape.** C-17/C-18's frame accounting alone already
closes the demonstrated attack: a decrypt reached through `ShreddingContext.withReadBracket(...)`
against a second, hand-built `EntityManagerFactory` (the exact repro in
`probe_a_second_entity_manager_factory_decrypts_a_moved_ciphertext`) is recorded into the bracket's
frame, nothing on that uninstrumented session's Hibernate event registry ever drains it, and
`popReadBracket()` refuses on its own, by construction, with no knowledge of factories at all. This
is verified and green.

**The finer-grained shape ("bind the bracket to the factory it belongs to") was not attempted.**
There is no stable, version-independent public API from a Spring Data JPA repository *bean* back to
the `EntityManagerFactory` it is bound to in this Spring Data generation - the repository is a
`java.lang.reflect.Proxy` wrapping Spring Data's own internal fragments, and reaching into it via
reflection to find an `EntityManager` field would be fragile across even a minor Spring Data
version, which is worse for a security control than not having it.

**The coarser shape ("refuse at startup when more than one `EntityManagerFactory` is present") is
implemented, in `ShreddingReadBracketCustomizer.afterSingletonsInstantiated()`, but I could not
build a dedicated integration test for it, and I am recording why rather than shipping an untested
claim of "closed."** I wrote one (`CipherProbeSecondEmfStartupTest`, registering a second
`@Bean LocalContainerEntityManagerFactoryBean` alongside Spring Boot's auto-configured one) and it
failed for a reason unrelated to this module's own logic:

```
APPLICATION FAILED TO START
A component required a bean named 'entityManagerFactory' that could not be found.
```

Spring Boot's own `HibernateJpaConfiguration.entityManagerFactory()` bean method is
`@ConditionalOnMissingBean({LocalContainerEntityManagerFactoryBean.class,
EntityManagerFactory.class})`. Registering *any* second bean of either type - the ordinary way a
Spring application declares one - suppresses the auto-configured (and therefore instrumented)
factory entirely, rather than letting both coexist. The exact shape this check is written to catch
- an instrumented default plus a second, additional factory - cannot be constructed through ordinary
Spring Boot auto-configuration at all; building it properly means excluding
`HibernateJpaAutoConfiguration` and hand-rolling both factories (including manually re-applying the
`HibernatePropertiesCustomizer` that carries `ShreddingIntegrator` to the one meant to be
"instrumented"), which is a materially larger, riskier change than this remediation pass's scope,
and itself a second, un-reviewed piece of Hibernate wiring to get wrong.

**Disposition.** The check stays in production code as a cheap, sound safety rail - it does no harm
and catches the case squarely if it ever arises - but it is not independently probe-verified, and
`CipherProbeSecondEmfStartupTest.java` was deleted rather than committed failing or skipped. C-20 is
reported closed on the strength of the frame-accounting fix alone, which is the one that is proven.

## #18 C-21: the probe's name promises the mutation persists; the documented fix is that it must not (taken; the probe rewritten to assert the true, permanent behaviour)

The handed-over probe, `probe_an_in_place_mutation_of_an_immutable_byte_array_is_persisted`,
asserted `reloaded[0]).isEqualTo((byte) 99)` - that an in-place mutation of a `@Shredded byte[]`
field **does** survive a flush. Cipher's own fix list for C-21 is documentation only: "Document the
in-place-mutation trap ... and correct the 'nothing shares state and the claim is honest' sentence."
No change to `ShreddedModel`, the converter or the entity mapping is prescribed, and none would be
sound - making the mutation actually persist means Hibernate deep-copying the converted array again
to build its dirty-checking snapshot, which is exactly the second, out-of-bracket converter call
that fails an `IDENTITY`-strategy insert (CIPHER-16, the reason `@Immutable` is required at all).
Fixing the documentation and making this probe pass as literally written are mutually exclusive.

**Taken: the documentation is corrected (the startup message in `ShreddedModel`, `README.md`,
`docs/index.md`, `SECURITY-NOTES.md`), and the probe is rewritten to assert the true, permanent
behaviour** - `reloaded[0]).isEqualTo((byte) 1)`, i.e. the mutation is confirmed lost - which is what
the corrected documentation now says happens and is expected to keep happening. The probe's name is
kept (Cipher's own review text names it, and renaming a probe without instruction is not this pass's
call to make); its body and its assertion are not what a first read of the name suggests, and the
javadoc on the test method says so.

## #19 C-27: the transaction is evicted from, but not also marked rollback-only (taken; a deviation, with evidence)

Cipher's fix text for C-27 asks for two things on refusal: evict the offending instance from the
persistence context, and mark the transaction rollback-only, "so the poisoned session cannot be
reused for anything else in this transaction." I implemented both first - `session.evict(...)`,
then `session.accessTransaction().markRollbackOnly()`, both in `ShreddingEventListener.refuseLoad` -
and every one of the handed-over `CipherProbeFrameTest` probes that reaches a mismatch (F1, F2, F5)
then failed, not on the property they test, but on
`org.springframework.transaction.UnexpectedRollbackException` thrown from `TransactionTemplate
.execute`'s own commit, outside any of the probes' own `try`/`catch`.

**Why, with evidence.** All three probes catch the `ShreddingException` *inside* the transactional
callback and return a plain value - exactly the "a `try`/`catch` around a repository call is not
exotic" pattern the finding itself names. `UnexpectedRollbackException` is not a Hibernate-specific
side effect of calling `Transaction.markRollbackOnly()` directly: it is what Spring throws, by
construction, for *any* transaction marked rollback-only through *any* API - Hibernate's own or
Spring's `TransactionSynchronizationManager.setCurrentTransactionRollbackOnly()` - once a commit is
attempted after the exception that caused the mark was caught and not rethrown. I confirmed this
independently: `probe_a_refused_row_is_returned_on_the_retry_from_the_persistence_context` (F2)
still throws `UnexpectedRollbackException` from the exact same line even after `refuseLoad` was
changed to call `evict` only, with no `markRollbackOnly` call anywhere in this module's code -
`SimpleJpaRepository.findById`'s own `@Transactional(readOnly = true)` does it on Spring's behalf
the moment the exception escapes that one call, participating in the ambient transaction
(`findByOwnerId`/`findByOwnerIdIn`, the derived query methods the other probes use, carry no such
annotation of their own and do not trigger it - which is why F1 and F5, which never call `findById`,
were unaffected either way). Marking rollback-only, correctly implemented by any means, is
therefore fundamentally in tension with "catch the refusal and keep going in this transaction": one
cannot do both and also avoid the commit-time exception that marking rollback-only exists to cause.

**Taken.** `refuseLoad` evicts only. Eviction alone already closes the exact leak C-27 demonstrates:
a stale, still-decrypted entity served from the first-level cache on a second read. With the
instance evicted, that second read is forced back through a real reload and this same check, every
time - the session is not "poisoned" in the sense of ever returning the secret again, only in the
sense that each retry costs one more query, which is the correct and already-intended cost. I did
not find, and the finding does not name, an attack that additionally requires blocking an
*unrelated* write later in the same transaction from committing; if one is identified, the
rollback-only half can be reconsidered against a probe that does not itself rely on catching the
refusal and continuing. `CipherProbeFrameTest.probe_a_refused_row_is_returned_on_the_retry_from_the
_persistence_context` documents both accepted outcomes (a refused retry, or Spring's own
`UnexpectedRollbackException` at commit) as equally valid - neither one returns the secret, which is
the property being tested - since `findById` specifically will always produce the latter regardless
of anything this module does.

## #20 C-26: `onPostLoad`'s per-row re-read does not cover a composite identifier (taken; the same residual `refuseIfSubjectMoved` already accepts)

The C-26 fix re-reads a loaded row's own stored shredded columns by id, in `onPostLoad`, the same
way `refuseIfSubjectMoved` already does on the write path (QUESTIONS #4 ruling (c)). Both share one
helper, `readStoredShreddedColumns`, and both skip the check - `refuseIfSubjectMoved` since the
third pass, `onPostLoad` new this pass - when `persister.getIdentifierColumnNames().length != 1`: a
composite identifier cannot be bound as the single `?` parameter the shared `SELECT ... WHERE id =
?` uses. No entity in this codebase has one (`Widget`, `Doc`, `Vault`, the sample's `Customer` are
all single-column `@Id`), so this is undemonstrated rather than proven safe, exactly like the
existing write-path residual it extends. Recorded here so it is not lost, rather than silently
inheriting the older entry's coverage by implication.

**Ruling (Cipher, fifth pass at `2f72449`): rejected as a residual, reclassified as C-38, closed.**
Not "undemonstrated rather than proven safe" - demonstrated: a composite-id `@Shredded` entity
cannot be read at all, including rows it wrote itself and nobody touched. Fail-closed, which is why
it is LOW and not HIGH, but a mapping this module cannot support must be refused at startup like the
`@SecondaryTable` split already is, not discovered on the first read in production. Fixed by Isis:
`ShreddedModel.scan` refuses at startup for any entity with a `@Shredded` field whose identifier maps
to more than one column. Once that refusal is in place, this entry's write-path half (`
refuseIfSubjectMoved`'s own composite-id skip) stops being a residual too, because the entity cannot
exist. See CHANGELOG's "Fixed (fifth pass at `2f72449`)" entry, C-38, and
`SECURITY-NOTES.md`'s "A `@Shredded` entity with a composite identifier is refused at startup, not on
the first read (C-38)".

## #21 A read region left behind by a `StackOverflowError` still reads as "open" (open — for Cipher)

**The residual.** Cipher's item 4 is implemented: a frame entry carries the token of the region that
recorded it, a drain happens only under the region currently in force, and a foreign-token entry is
discarded with the load refused. `CipherProbeBracketUnwindTest` measures 0/200 on both the write
scope and a later region draining residue, and 0 plaintext recovered from a leaked region.

What item 4 does *not* reach: a region that an `Error` unwound past is still *on the stack*, so
`ShreddingContext.inReadBracket()` is `true` for the next call on that pooled thread. If that next
call opens no region of its own — a bare `EntityManager` read, a hand-written DAO — its decrypt is
recorded into the leaked region rather than refused with `SHRED-READ-UNSCOPED`, and `onPostLoad`
then drains it under a matching token and installs.

**Why I did not close it.** The value that install produces is *this row's own value, verified
against this row's tenant, subject and identifier*. It is not another subject's data, not a stale
value, and not a post-erasure value (the key-state check runs on every decrypt). What is lost is the
**loudness** — a read that should have been refused for having no region succeeds instead. Closing
it needs a liveness signal for "is the frame that opened this region still on the call stack", which
the JVM does not offer: a `finally` cannot run at stack exhaustion (C-32), a transaction-completion
callback may not clear a region (C-33), and a `StackWalker` probe on every repository call is a cost
I would not pay without being asked to.

**Recommendation.** Accept as a documented residual, with the boundary stated exactly: *a leaked
region can cost a refusal, never a value*. If Cipher wants it closed, the cheapest sound option I
see is a `StackWalker`-derived depth recorded at `openRegion()` and compared at `recordDecoded()`;
say so and I will measure the cost and build it.

## #22 The per-decrypt key-state check is 200 statements on a 200-row page (open — for Cipher)

**The measurement.** C-35 is closed: `onPostLoad` issues no SQL, and a 200-row page costs one
statement against the entity's table where it cost 201. Cipher's own P3 counts `prepareStatement` on
the real `DataSource` and reports 0 per-row re-reads.

The same measurement shows the remaining 200 statements are `FieldCipher.decrypt`'s per-decrypt
`SELECT ... FROM shredding_data_key`. That is control 7 and it predates this design: the data-key
cache holds key *material*, never *authority*, so every decrypt re-reads the row that says whether
the key may still be used at all. It is what makes the cross-node erasure window bounded by the
cache TTL rather than unbounded.

**Recommendation.** Leave it. Memoising the key state per transaction would make a 200-row page one
statement instead of 200, but it caches *authority*, which is a security decision and not mine to
take in a performance commit — and it would widen the window in which an erasure that lands
mid-transaction is invisible to that transaction. Recorded so the number is not mistaken for a
regression introduced by the read-path redesign.

## #23 The `IDENTITY` rebind costs a second `encrypt` per shredded column (open — for Cipher)

Design §3.1, ruled acceptable by Cipher (D3, items 5-6) and built as specified: the insert binds a
random unbound intermediate, `onPostInsert` re-encrypts bound to the generated identifier and writes
one `UPDATE` over raw JDBC in the same transaction, and a failure aborts the transaction.

Two consequences worth stating rather than leaving to be discovered:

1. **Two ticks of the per-key encryption counter** (control 3) per shredded column on an `IDENTITY`
   insert. The limit is 2^32 and the counter triggers a rotation rather than a refusal, so the
   effect is halving the interval between rotations for an `IDENTITY`-heavy workload. Noted in
   `SECURITY-NOTES.md` beside control 3.
2. **The intermediate reaches the WAL and any logical replication slot**, as Cipher's item 5
   anticipated. It is bound to a 128-bit random value under a tag no real identifier's encoding can
   equal, so it verifies against no row on any reader — which is the property item 5 asked for — but
   it is still a ciphertext of the value, decryptable by anyone holding the subject's data key. That
   is the same bound `SECURITY-NOTES.md`'s "Backups, PITR archives, WAL, replicas" residual already
   states for every stored value; the rebind does not widen it, it only makes the row appear twice.

**Recommendation.** Accept both. The alternative — refusing `IDENTITY` — was Cipher's to take and it
declined it explicitly.

## #24 "No write scope survives a `StackOverflowError`" is a measurement, not a guarantee (open — for Cipher)

**What happened.** Cipher's `CipherProbeBracketUnwindTest` asserts that 0 of 200 forced stack
overflows inside a nested `ShreddingContext.with(...)` leave a write scope on the thread. During this
work it went 0/200 → 154/200 → 0/200 → 1/200 → 0/200, and every move was explained:

- 154/200 was a real regression I introduced and the probe caught: `popWrite` used
  `Deque.removeIf`, which allocates an iterator and calls through a lambda. At the depth where the
  stack is already exhausted, those extra frames are extra chances for the cleanup itself to throw
  the second `StackOverflowError` that skips the `finally`. Fixed by popping the top directly when
  the top is the token being popped, which is every ordinary case.
- The earlier 0/200 was partly an artefact of a *different* bug: `pushWrite` cleared the whole stack
  on every push, so a deeply nested `with(...)` left at most one entry and the probe's
  `current().isPresent()` check passed for the wrong reason. That bug also treated a legitimately
  nested `with(...)` as residue and logged once per level — 43 MB of WARN in one probe run. Split
  into `pushWrite` (plain, nests) and `pushBind` (drops residue, used only by the `Pre*` listeners).
- 1/200 was a genuine flake, and it is the honest state of this property: a `finally` has to *call*
  something, and at stack exhaustion that call throws again. C-32 established exactly this. I have
  reduced the frames on the unwind path as far as I can see how to — the `ThreadLocal` is resolved
  before the body runs and `with(...)` unwinds the deque in-line rather than calling a helper — and
  it now measures 0/200 on five consecutive runs. It is not 0 by construction and I will not claim it
  is.

**Why I left the assertion at 0 anyway.** It is Cipher's bar, it passes, and lowering it to "usually
0" would hide the next real regression exactly as the 154/200 one would have been hidden. If it
flakes in CI I would rather find out.

**Why a leak is not a breach either way.** The security property this design rests on is not "no
scope survives" but *a surviving scope is never consumed*, and that has three independent guards,
none of which depends on unwinding: `pushBind` drops anything still live before the next bind;
`ShreddingContext.require` refuses a scope pushed for a different entity; and the post-hoc header
check after every insert and update refuses, inside the same flush, any row whose stored header is
not bound to the `(tenant, subject, rowId)` it was written under.
`probe_a_leaked_write_scope_is_dropped_by_the_next_bind_rather_than_consumed` tests the first
directly.

**Recommendation.** Keep the strict assertion. If Cipher would rather have a stable build than a
strict one, the alternative is to assert unconsumability and print the leak count as evidence — say
which and I will change it in one commit.

## #25 S-1's own probe becomes unstartable once S-5's startup refusal lands (flagged, for Isis and Cipher)

`CipherProbeBatchedInsertCheckTest` demonstrates S-1 with an `@Access(AccessType.PROPERTY)` shredded
mapping - S-5's hole, and the only mapping in which Hibernate writes a `@Shredded` column with no
converter at all. It is **green now** under `./mvnw -Pprobes-pending test` (`BATCHED INSERT ->
REFUSED TransactionSystemException; stored null`, against `COMMITTED; stored
BATCHED-SECRET-1|BATCHED-SECRET-2|BATCHED-SECRET-3` on `05ca185`).

**The collision.** S-5's fix refuses a property-access `@Shredded` mapping *at startup*. Once that
lands, this probe's `@SpringBootTest` context cannot start, and the test fails for a reason that has
nothing to do with S-1. So I did **not** promote it into `src/test/java`: promoting it would put a
test in the default build that Isis's own fix breaks.

**Recommendation.** On merge, rewrite it exactly as C-38 was rewritten - from "the write is refused"
to "startup refuses the mapping" - and keep it in whichever branch lands S-5. S-1's property is
carried in the default build by `BatchedWriteVerificationTest`'s seventeen probes, two of which
refuse a bad stored header under batching without needing any mapping hole: a row that cannot be
read back (`SHRED-UNVERIFIED-WRITE`) and an in-transaction row swap (`SHRED-SUBJECT-IMMUTABLE`),
both reached through `StatelessSession` and its own connection.

**Ruling (Cipher, seventh pass, 2026-09-10): accepted.** S-5's fix genuinely makes the old fixture
unstartable, the rewrite is red on `05ca185` and green here, and S-1's property is carried by
`BatchedWriteVerificationTest`'s seventeen tests. One correction, S-12: rename the file to what it
now asserts, and name `BatchedWriteVerificationTest` in its place as the file that carries S-1.

**Done (Isis, S-2..S-6 rebase onto S-1).** `CipherProbeBatchedInsertCheckTest` is rewritten to assert
exactly that: `PropSeqWidget` (still `@Access(AccessType.PROPERTY)` with the converter on the field,
still un-mapped) now fails the `SpringApplicationBuilder.run()` in the test itself with
`SHRED-CONFIG-001`, naming `PropSeqWidget` and `name` - the same shape as every other startup
refusal this module has (`CipherProbeCompositeIdTest`, `CipherProbePropertyAccessTest`). Promoted to
`src/test/java`; the `propseq` fixtures move with it.

## #26 The verification ledger holds one record per written row until the flush ends (taken; a documented cost)

Settlement discharges debts at the end of every flush, so an ordinary `@Transactional` method holds
at most one flush worth of debt - bounded by the same thing the persistence context is bounded by.
`StatelessSession` fires no flush event, so a stateless import of N rows in one transaction holds N
records (an entity name, a table name, an id, a tenant, a subject and a rowId each) until
`beforeCompletion`. A ten-million-row stateless import in a single transaction would notice.

**Why I did not add a threshold.** An interim settlement pass triggered by ledger size would have to
run mid-`insertMultiple`, where the batch has not executed - which is S-1 again, in a place chosen by
a heuristic rather than by the framework. The two settlement points this design has are the two
points where the batch is provably out.

**Recommendation.** Leave it, and document it (done, `SECURITY-NOTES.md`, "The write path settles a
debt"). If a customer hits it, the answer is `StatelessSession` with a transaction per chunk, which
is what a ten-million-row import should be doing anyway. If Cipher wants a hard cap that refuses
rather than degrades, say the number and it is a two-line change.

**Ruling (Cipher, seventh pass, 2026-09-10): accepted, with a number.** The reasoning against an
interim settlement pass is right - a settlement point chosen by a heuristic in the middle of
`insertMultiple` is S-1 again. But "it degrades until the JVM dies" is not a bound, and a `Debt`
holds a subject and a tenant, so an OOM heap dump of the ledger is personal data. Add the cap:
property `shredding.write-verification.max-outstanding`, default **50 000**, and a debt that would
exceed it is `SHRED-UNVERIFIED-WRITE` naming the property and the remedy (a transaction per chunk).
It refuses, it never degrades, and it is the default rather than an opt-in. Test
`a_stateless_import_past_the_cap_is_refused_rather_than_accumulated`.

## #27 The "still outstanding at completion" refusal is unreachable today (taken; a deliberate belt)

`WriteVerification.ledgerFor`'s before-completion callback settles and then refuses if anything is
still owed. `settle` either empties the ledger or throws, so the second branch cannot fire on this
code - it is three uncovered lines in the JaCoCo report and I know it.

It stays because it is the assertion that makes the *next* change to `settle` fail loudly instead of
quietly: the whole of S-1 was one early `return` that meant "unchecked" and read as "fine". I would
rather carry three unreachable lines than reintroduce that shape.

**Ruling (Cipher, seventh pass, 2026-09-10): keep it, and it stops being unreachable.** The argument
is right and I would carry the lines for it in any case. Note that it becomes reachable the moment
`settle` stops emptying the ledger before it has verified anything - clear an entry only after the
check that discharges it passed. Do that: today a caught settlement refusal cannot commit only
because Hibernate marks the transaction rollback-only when a listener throws out of a flush
(`SwallowedWriteRefusalTest`), which is an accident of Hibernate's exception conversion and not a
property this module states. Do not exclude the lines from JaCoCo.

---

## S-2 Second `@Shredded` field's declared tenant: full per-field support, not the review's suggested startup refusal (taken; a deviation, with a probe that requires it)

**What the sixth pass's fix text says.** "`ShreddedModel.scan`, in the same loop that already refuses
a `@SecondaryTable` split, refuses at startup when the `@Shredded` fields of one entity do not all
declare the same tenant expression (all blank, or all the same string), naming the entity and both
expressions."

**Why I did not take it as written.** `CipherProbeTenantExpressionTest.probe_a_second_shredded_field_is_bound_to_the_tenant_it_declares`,
committed by Cipher alongside the finding, drives `Dossier` — one entity, two `@Shredded` fields,
`note` declared `tenant="#{'org-a'}"` and `memo` declared `tenant="#{'org-b'}"` — through a real save
and asserts the stored `memo` column decodes to tenant `org-b`. That is not "refused at startup"; it
is the *other* half of the finding's own javadoc ("or every field is bound to the tenant it
declares"), the half the probe actually exercises and the only outcome a mapping this way can produce
without failing the probe. A per-entity refusal would make the probe fail at context startup with
`SHRED-CONFIG-001` instead of reaching the assertion.

**What I built instead.** Two `@Shredded` fields of one entity declaring *different* tenants is a
supported shape. `ShreddingContext.Scope` grew a `Map<String, TenantId> fieldTenants` and a
`tenantFor(String fieldName)` accessor; `ShreddingEventListener.scopeFor` resolves and stores every
field's own tenant expression against the entity instance once, at write time (the only place a
tenant expression can be evaluated — the converter is handed nothing but the attribute value), and
every write and read-path site that used to read `scope.tenant()` as *the* tenant for every field of
an entity — the converter, blind-index derivation, the `IDENTITY` rebind, `refuseIfSubjectMoved`,
`refuseIfStoredHeadersDisagree`, `onPostLoad` — now asks for the specific field's tenant. `subject`
still has to agree across fields (`resolveSubject`'s existing cross-check, unchanged): one row belongs
to one subject, but a field within that row can belong to a different tenant's erasure scope than its
neighbour, and that scope is now the one the field's own annotation names.

**What is still refused, and what is not.** Nothing new is refused at startup by this fix. A
mismatched *subject* across an entity's `@Shredded` fields is still refused at write time
(`resolveSubject`), unchanged. A mismatched *tenant* is no longer a defect to refuse — it is the
declared, honoured shape.

---

## S-4 The ownerless-region residual: closed for the value half, open for the refusal half — needs design stop for the refusal half

**What closed.** `drain` took `entries.remove(0)` — the oldest pending decode under a key — so an
ownerless region left on the thread's deque by an undisciplined direct call to the public
`openRegion()` (the shape `CipherProbeRegionResidueTest` builds; QUESTIONS #21) could serve a stale,
previously-decrypted value of the same row in place of the one the current read just took out of the
column. `drain` now takes the *most recent* entry, so it can never serve anything except this row's
own, current value — Cipher's own restated #21 boundary ("with S-4(a) in place it can never serve a
value other than this row's own, current one"). `Pending.ownerToken` and its comparison in `drain`
are removed rather than "fixed": `recordDecoded` always stamps an entry with the token of the very
`Region` object it is filed into, and `drain` always reads back from `stack.peek()` — the same object
— so `pending.ownerToken() != region.token` was unsatisfiable by construction, not a check that
sometimes missed. `CipherProbeRegionResidueTest.probe_a_stale_decode_in_an_ownerless_region_is_not_installed_over_the_fresh_one`
(R2) is green.

**What did not close.** `CipherProbeRegionResidueTest.probe_a_decode_with_no_region_of_its_own_is_refused_even_when_an_ownerless_region_is_open`
(R1) asserts that `recordDecoded` itself throws `SHRED-READ-UNSCOPED` when the region on top of the
stack is one the *current* call did not open — an "ownerless" region left behind by an earlier,
undisciplined direct `openRegion()` call, exactly as `CipherProbeRegionResidueTest`'s
`onOwnerlessRegion` helper builds it. `recordDecoded` cannot make this distinction today: it only
ever asks "is the region deque non-empty", and a region opened by an earlier, already-returned call
is, on the stack, indistinguishable from one legitimately open for the call in progress — both are
literally the same object at `stack.peek()`. Closing R1 needs a *second* piece of call-scoped state:
something that marks a region "active for the call currently in flight" as opposed to merely
"present", set only by the two disciplined callers (`ShreddingReadBracketCustomizer.Bracket.invoke`
and `ShreddingContext.withReadBracket`) and consulted by `recordDecoded`. I prototyped the obvious
shape — a second `ThreadLocal` depth counter incremented/decremented around those two call sites —
and stopped: it reintroduces exactly the failure category `CipherProbeBracketUnwindTest` (C-32) exists
to rule out for the *existing* region stack — an intermediate stack frame's own cleanup call failing
under a `StackOverflowError` and leaving the counter stuck positive, which would make the new state
leakable *authority* (a stuck-positive counter would keep authorising `recordDecoded` calls that
should be refused) rather than the accusation-only state the class's own design principle requires.
Arguing that a second counter is unwind-safe the way `popWrite`'s javadoc argues it for write scopes
is real design work, not a data-loss fix, and building the mechanism without that argument is exactly
the "mechanisms in fix lists" pattern module C's rounds two–four warn against.

**Needs design stop.** Flagging R1 to Dollar/Thor rather than shipping a speculative fix. `S-4` is
otherwise closed: the data-loss property ("an ownerless region serves nothing but this row's own,
current value") holds; the missing-refusal property ("an ownerless region costs a refusal that should
have been raised") does not, and is the same residual #21 already named.

`CipherProbeRegionResidueTest.java` stays in `src/test-pending/java` for this reason — R2 is green,
R1 is red, and the file is not moved until both are.

**Design stop taken (Thor, 2026-09-10).** `docs/plans/read-path-design.md`, "Design addendum 2:
region residue", weighs the three shapes Dollar named - (a) bind the region to the transaction or
Hibernate session identity, (b) an epoch stamped at proxy entry, (c) sweep residue on proxy entry -
against `StackOverflowError` mid-unwind, nested repository calls, async, a session closed without
commit, and cost. **Recommendation: (b), with (c)'s sweep as a free complement.** (a) and (c) are
refused on evidence rather than taste: R1's ownerless region is built with no session and no
transaction and read from a caller that enters no proxy, so under (a) the binding matches and under
(c) nothing sweeps - both leave R1 red. The objection to a second `ThreadLocal` is answered by the
difference between accumulated and replaced state: a depth counter is the sum of every entry and
exit and one missed exit is stuck-positive *authority*, while an epoch is overwritten unconditionally
at the next entry, so a missed restore lands in the refusing direction. S-4 stays **open** pending
Cipher's review of the design: the instruction for option (b) is to stop after the addendum.

The `S-1 / S-5` interaction this note would have flagged is #25 above, already resolved: `S-5`'s
startup refusal is what made `CipherProbeBatchedInsertCheckTest`'s original fixture unstartable, and
the probe is rewritten as a startup-refusal assertion rather than given a new fixture, since S-1's own
property is independently carried by `BatchedWriteVerificationTest`'s seventeen probes.
