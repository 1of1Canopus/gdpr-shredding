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

## #21 A read region left behind by a `StackOverflowError` still reads as "open" (narrowed by S-4's epoch, 2026-09-10; the remainder accepted)

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

**Narrowed, then accepted (Thor, 2026-09-10, S-4 / addendum 2).** The liveness signal turned out not
to need a `StackWalker` and Cipher ruled the `StackWalker` out explicitly: the entry epoch answers
"is a bracketed entry in force on this thread", with one `long` and no Hibernate or Spring state
consulted. A region left on the deque by a returned call now carries an epoch that is not the one in
force, and a region opened outside an entry carries `NO_ENTRY`, so both refuse. What remains is only
the case where an `Error` skipped exactly the frame that restores the epoch, before the next entry -
the same window `popWrite`'s javadoc concedes for write scopes. Accepted, in Cipher's words, in
`SECURITY-NOTES.md` under "Region residue": **a leaked region costs a refusal, never a value.**

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

**Done (Isis, 2026-09-10).** `ShreddingProperties.WriteVerificationProperties.maxOutstanding`
(default 50 000), configured into `WriteVerification` by `ShreddingStartupCheck.afterPropertiesSet`
the same way `ShreddingRuntime` is. `owe` refuses a genuinely new debt once the ledger already holds
`maxOutstanding` distinct rows, naming the property and the remedy; a row already owed and rebound
in the same transaction (an update after an insert) replaces its own entry rather than counting
twice, so only a new row can push the ledger over. `CipherProbeWriteVerificationCapTest`, green.

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

**Done (Isis, 2026-09-10).** `settle` no longer clears its snapshot up front: `groupByTable` now
groups debt *keys*, and `verifyChunk` removes each key from the ledger immediately after the row it
names is found to agree - one at a time within a chunk, in iteration order - not the whole chunk at
once after the SELECT returns. A chunk that throws partway through therefore leaves every debt it
had not yet reached still in the ledger, correctly. New test,
`BatchedWriteVerificationTest.a_settlement_refusal_discharges_only_the_debt_that_actually_passed`:
two rows in one chunk, one deleted out from under its own debt before settlement, `settle` called
directly (package-private, same package) so the still-open transaction can be inspected before it
unwinds - it throws for the vanished row, and the row that verified is discharged regardless of
where in the chunk it fell. Lines not excluded from JaCoCo.

**Correction (S-18, Cipher eighth pass).** The line above used to end "... but no longer unreachable
by construction." That is wrong, and so was the CHANGELOG entry that said the same thing. `settle`
still only ever returns normally after emptying every debt it started with, or throws before
returning at all; a throw from inside `settle` propagates straight out of the `beforeCompletion`
callback, past the branch that checks the ledger afterwards, on every path, including this one. The
"still outstanding at completion" branch in `beforeCompletion` is unreachable by construction today
- the ledger residue this fix produces is real and correctly recorded, it is simply never read back
by that particular branch, because `settle`'s own throw always wins the race to leave `settle`
first. The branch stays: a belt for whatever settlement path replaces this one, deliberately not
excluded from JaCoCo. `WriteVerification.settle`'s javadoc carries the same correction.

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

## S-4 The ownerless-region residual — CLOSED (built, 2026-09-10). History kept below.

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

**Closed (Thor, 2026-09-10).** Cipher approved addendum 2 with six changes and all six are built;
`docs/plans/read-path-design.md` marks each one "applied §2.x" and its "Addendum 2 as built" section
says what each became. The refusal half now holds: a decrypt is served only inside a region opened by
the bracketed entry that is reading, compared by **epoch equality**, so R1 - a decode with no region
of its own, with an ownerless region on the deque - is refused, and the ownerless region cannot even
be *armed* through the public API any more. `CipherProbeRegionResidueTest` is out of
`src/test-pending` with both probes green; `CipherProbeRegionEpochTest` carries the six new ones;
`CipherProbeBracketUnwindTest` is unchanged at 0/200. The residual that remains is #21's, restated in
`SECURITY-NOTES.md` in Cipher's words - an `Error` that skips exactly the epoch-restoring frame,
before the next entry - and **a leaked region costs a refusal, never a value.**

**S-4a, one open question for Cipher (recommended answer: sweep it too).** Change 3 says "sweep only
regions whose epoch is not the epoch in force at entry; never one whose epoch equals it". Applied
literally, a `NO_ENTRY` region left on a thread where nothing is in force compares equal to
`NO_ENTRY` and is *not* swept. It is harmless - a `NO_ENTRY` region is never the current region, so
it can serve nothing, and the enclosing unwind pops it - but it is also exactly the undisciplined
state the WARN exists to make visible. I recommend widening the sweep predicate to "sweep any region
that is not the region the frame in force owns", which is `currentRegion() == null` and still never
touches a caller's live region. Not built: it is Cipher's rule to widen, not mine.

**S-4b, coordination, for the record.** Cipher's change 5 asks that Isis's S-8 fix land first. It had
not been pushed at the agreed hour (Dollar told), so the epoch's close half is built as a separate
method - `refuseIfClosedUnderAnotherEntry`, called as `closeRegion`'s **last** statement, after the
region's own unpaid-debt refusal, so S-8's more specific message wins wherever both apply. Isis's
in-progress S-8 replaces `closeRegion`'s call to `unwindTo` with an inline loop; that loop **must**
call `restoreEpoch(region)` for every region it pops, as `unwindTo`'s javadoc now states. A merge
that drops it leaves the thread's entry epoch naming a frame that has returned and fails
`CipherProbeRegionEpochTest.probe_an_inner_entry_and_its_caller_each_serve_only_their_own_decodes`
and `CipherProbeReadScopeTest.probe_a_repository_call_nested_inside_a_read_bracket_leaves_the_outer_region_alone`
at once.

The `S-1 / S-5` interaction this note would have flagged is #25 above, already resolved: `S-5`'s
startup refusal is what made `CipherProbeBatchedInsertCheckTest`'s original fixture unstartable, and
the probe is rewritten as a startup-refusal assertion rather than given a new fixture, since S-1's own
property is independently carried by `BatchedWriteVerificationTest`'s seventeen probes.

---

## S-7b / S-13 Blind index tenant binding — CLOSED (Thor, 2026-09-10)

**Built, all seven of Cipher's changes.** `docs/plans/read-path-design.md`, "Addendum 3 as built",
marks each one applied §3.1–§3.7 and names its probes; `CHANGELOG.md` carries the user-facing
summary and `SECURITY-NOTES.md` the control and its residual.

**What the answer turned out to be.** Not "derive under the column value" on its own - Cipher's
change 4 is right that (a) alone leaves the ciphertext under a third tenant and closes nothing. The
invariant built is: *for a row to be erasable by one request, the tenant its data key was derived
under, the tenant its index was derived under and the value in its `tenantColumn` are one value*,
enforced per row at the write. With that in force, deriving under `state[tenantColumn]` documents
itself and the two derivations are equal by construction.

**The migration consequence I stopped for is answered by change 6:** clean break, no compatibility
path, the branch is unreleased, no code tries the old keying.

**One consequence worth a decision (not blocking).** Isis removed `@BlindIndex` from the sample's
`Customer` under S-7, because that entity is genuinely multi-tenant per write and its `email` field
needs `tenant = "#{tenantId}"`. Change 4 makes exactly that shape legal again (`tenantId` is what
the row's tenant column holds), so the sample can demonstrate equality-lookup-over-encrypted-data
again with no security cost. **Recommended: restore it** as a small, deliberate sample task. Not
done here: it is product-demo work, not part of this finding, and it touches
`CustomerRepository`/`CustomerService`/`SampleEndToEndTest`/`LogScanTest` assertions
(`blindIndexColumnsCleared()` back to 1).

---

## S-7b (historical) Blind index tenant binding: the general case, where `tenantColumn` differs from the ambient tenant (design stop taken, 2026-09-10 — for Cipher)

**Stop taken, no code.** Cipher's S-7 names the special case S-2 opened (an index derived under a
field's *declared* tenant) and hands the general case to a design stop: an application whose
`tenantColumn` value is simply not the ambient tenant. `docs/plans/read-path-design.md`, "Design
addendum 3: blind index tenant binding", is the page: the property, why the two sides disagree
(`writeBlindIndexes` derives under `scope.tenantFor(of)`; `clearBlindIndexes` matches the row's
stored `tenantColumn` value), five options and their costs, the recommendation, and the probe list.

**Recommendation in one line.** Derive the index under **the row's own `tenantColumn` value, read out
of the state array by the same write**, since that is the only value the erasure's `WHERE` can match;
refuse at startup when `tenantColumn` is not a mapped basic `String` property of the entity, and
refuse the write when its value is null or blank.

**What I did not do, and why.** No code, per the design-stop rule: this changes what a blind index is
keyed under, which is a data-model change with a migration consequence for anyone already running
indexes (an index derived under the old key is not reachable under the new one - the addendum does
not yet say whether that needs a documented re-index or a version marker, and I would rather Cipher
rule on the key before I write a migration for it). Isis's S-7 startup refusal is unaffected and is
not blocked on this.

---

## S-7 (2026-09-10, Isis) — startup refusal closes the declared shape; the general form stays Thor's design stop

**Superseded 2026-09-10 (Thor, addendum 3 change 4): the startup refusal below is relaxed.** A
`@BlindIndex(of = ...)` field may declare its own tenant again; the write is refused, per row, when
that tenant is not the row's `tenantColumn` value. Cipher approved the relaxation explicitly ("agreed,
and change 4 is what makes it safe"). `CipherProbeBlindIndexTenantTest` is rewritten accordingly, and
the fixture changes Isis made to keep the tree green (`fixture.Gadget`, the sample's `Customer`) are
no longer required by this module - see the S-13 entry above for the sample recommendation.

Closed for the shape S-7's fix names: `ShreddedModel.scan` refuses startup (`SHRED-CONFIG-001`) when
a `@BlindIndex(of = ...)` names a `@Shredded` field that itself declares a `tenant` expression -
`CipherProbeBlindIndexTenantTest`, rewritten from a data repro into a startup-refusal assertion
(same shape as #25's `CipherProbeBatchedInsertCheckTest` rewrite), is green.

**Consequential fixture changes, not in scope on their own but required to keep the tree green.**
`fixture.Gadget` (starter integration tests) and `sample.Customer` both had a `@BlindIndex(of=...)`
field that also declared its own `tenant = "#{...}"` expression - exactly the shape S-7 now refuses.
`Gadget.metadata` no longer declares a tenant (it falls back to the row's primary tenant, which
`balance`'s `"#{tenantId}"` already resolves to the same value the row's `tenant_id` column holds);
`ShreddingIntegrationTest.TestApp` gained a fixed `TenantSupplier` bean (`TenantId.of("default")`,
matching every other fixture entity in that file, which already only ever resolves to `"default"`).
`sample.Customer` could not take the same path: it is genuinely multi-tenant per write with no
ambient `TenantSupplier` configured, so both `email` and `phone` need their own `tenant =
"#{tenantId}"` expression, and the field a `@BlindIndex` names `of=` cannot have one any more. I
tried carrying the tenant through a request-scoped `TenantSupplier` (a `ThreadLocal` set by
`CustomerService.create`) instead of the per-entity expression; it broke every OTHER write path
in the sample that touches a `Customer` row without going through `create` - `entityManager.flush()`
after a direct setter call, `entityManager.merge(detached)` - because none of them set the ambient
tenant, and I judged threading tenant context through every one of those test call sites a larger,
riskier change than the finding warrants. **What I did instead: removed `@BlindIndex`/`emailBidx`
from the sample's `Customer` entirely** and adjusted `CustomerRepository`, `CustomerService`,
`SampleEndToEndTest` and `LogScanTest` accordingly (`result.blindIndexColumnsCleared()` now asserts
`0`, not `1`). This drops the sample's demonstration of the equality-lookup-over-encrypted-data
feature. If that demo matters for the product story, the right fix is a small, deliberate sample
config (a real `TenantSupplier` wired to a request-scoped or `ThreadLocal` value, documented as the
pattern a multi-tenant application should use) - a few hours of sample work, not a security
correction, so I did not build it under this finding. Flagging for Dollar/Souhaile: worth a follow-up
task if the free core's blind-index feature should stay demonstrated in the sample.

**The general form is still Thor's design stop, unaffected by this fix.** Per Cipher's seventh-pass
review: "the general form - an application whose `tenantColumn` value simply differs from its
`TenantSupplier`'s ambient tenant - predates S-2, is not reproduced here, and closing it needs a
decision about reading the row's tenant column out of the state array at write time." Not touched.

---

## S-11 (2026-09-10, Isis) — CLOSED (Cipher eighth pass): accepted residual, no design stop. History kept below.

**Ruling (Cipher, eighth pass, 2026-09-10): accepted residual, and here is why.** What the attack
removes is Hibernate's own seeded listener, never ours - ours is registered after the wipe and its
presence is what `refuseIfVerifierNotRegisteredFirst` proves, on all eight types. No control of this
module is disabled: `POST_LOAD`'s default gone still leaves our verifier first and installing;
`FLUSH`'s default gone means Hibernate stops flushing, which is an application that does not work
rather than an erasure that does not erase. And the actor is an integrator on the classpath - code
running in this JVM, which can reflect into `ShreddingContext` and defeat any check the module
writes. A new snapshot mechanism would buy detection of one path against an actor who has ten. Not a
design stop.

**Done (Isis, 2026-09-10).** The accepted-residual wording is in `SECURITY-NOTES.md` ("The startup
listener check proves position, not survival of Hibernate's own defaults") and, condensed, in
`ShreddingStartupCheck.REGISTERED_TYPES`'s own javadoc. `CipherProbeSettlementListenerDisplacedTest`
asserted the wrong outcome (that the application must refuse to start) for a shape the module was
never going to close; rewritten to assert the true, documented one -
`CipherProbeEarlierIntegratorWipesHibernateDefaultsTest`.
`our_listener_is_still_present_and_last_on_flush_after_an_earlier_integrator_wipes_it`: after
`DisplacingIntegrator` wipes Hibernate's own seeded `FLUSH` listener, this module's own listener is
still present and still last on `FLUSH`. `git mv`d into `src/test/java`, green.

### History (superseded by the ruling above)

The original finding, before Cipher's ruling: the described fix (presence + position) does not close
the probe's own scenario.

**What I built.** `ShreddingStartupCheck` now iterates all eight event types `ShreddingIntegrator`
registers (previously five) - `PRE_INSERT`, `PRE_UPDATE`, `POST_LOAD`, `POST_INSERT`, `POST_UPDATE`,
`POST_DELETE`, `FLUSH`, `AUTO_FLUSH` - from one table, and asserts per type both presence and the
position it registered for (first for the three prepended, last for the five appended), exactly as
the finding describes. This is a real improvement: `FLUSH`, `AUTO_FLUSH` and `POST_DELETE` were not
checked at all before, for either presence or position.

**What it does not close: `CipherProbeSettlementListenerDisplacedTest` stays red.** I built the
probe's exact scenario and traced it empirically (a temporary debug print of `FLUSH`'s listener
classes, since removed): `DisplacingIntegrator.integrate()` calls
`registry.setListeners(EventType.FLUSH, ignore)` - which replaces Hibernate's own seeded
`DefaultFlushEventListener`, the listener that actually executes the JDBC batch, not merely
whatever this module had registered - and it runs *before* `ShreddingIntegrator.integrate()`, because
`ShreddingAutoConfiguration.shreddingHibernateCustomizer` composes this module's integrator **last**
in the `IntegratorProvider` list on purpose (so its `POST_LOAD` listener is the last one prepended
and therefore the first one Hibernate calls - S-6's whole point). Because we always run last, our own
`prependListeners`/`appendListeners` call always lands us in the textually "correct" position - first
for a prepended type, last for an appended one - **regardless of what an earlier integrator wiped
first**: on `FLUSH`, the group ends up exactly `[ignore, shreddingEventListener]` - ours genuinely
last, the check genuinely passes - while Hibernate's own default listener is gone. Position-of-our-
own-listener is structurally unable to detect this class of attack, for any type an earlier-running,
composed integrator can call `setListeners` on: whoever runs before us can replace the group's prior
contents and we will still measure as correctly positioned relative to what's left, because we always
register after them. (`PRE_INSERT`/`PRE_UPDATE` are not exploitable this way for a different reason -
Hibernate seeds them with no default listener at all, so there's nothing to wipe; `POST_LOAD` and the
other four appended types do have a real Hibernate default seeded, and are exploitable the same way
`FLUSH` is, though only `FLUSH` has a demonstrating probe today.)

**Why I did not build a fix for this.** The only two closing shapes I found: (a) hardcode Hibernate's
internal default-listener class per event type (`DefaultFlushEventListener`,
`DefaultAutoFlushEventListener`, `PostInsertEventListenerStandardImpl`,
`PostUpdateEventListenerStandardImpl`, `PostDeleteEventListenerStandardImpl`,
`DefaultPostLoadEventListener`) and refuse if none of the *other* listeners in an appended-or-
`POST_LOAD` group is one of them - version-coupled to Hibernate internals with no public "is this
still the platform default" API, and per-type by construction, which cuts against "one table, no
per-type methods"; or (b) a new mechanism that records each listener group's identity/size at the
moment `ShreddingIntegrator` itself registers (inside `integrate()`, before anything later can touch
it) for `ShreddingStartupCheck` to compare against post-boot - genuinely new state, not a correction.
Neither is "the smallest correct change" for a LOW finding; I am flagging it rather than building
either. `CipherProbeSettlementListenerDisplacedTest.java` stays in `src/test-pending/java`, red,
until this is decided.

## S-14 (2026-09-10, Isis) — CLOSED. `unwindTo` scanned the deque before popping.

**Fix (Isis).** `ShreddingContext.unwindTo` scans the deque for `token` first and pops nothing when
it is absent, returning `null` - `closeRegion`'s existing refusal, `discardRegion`'s existing no-op.
`unwindTo(token, ...)` was popping unconditionally until it found `token` or ran out of deque, so a
token from another frame, or one a nested entry's sweep had already taken away, emptied the whole
deque including the live entry region of the call it was invoked from. Package-private
`ShreddingContext.resetForTests()` added for the four `@AfterEach` blocks that used to rely on
`discardRegion(-1L)` emptying the deque unconditionally
(`CipherProbeRegionEpochTest`, `CipherProbeRegionResidueTest`, `CipherProbeSeventhPassTest`,
`CipherProbeEighthPassRegionTest`). Probe:
`CipherProbeEighthPassRegionTest.probe_closing_a_swept_region_does_not_destroy_the_callers_live_region`,
green, moved to `src/test/java`; `CipherProbeRegionEpochTest` and `CipherProbeRegionResidueTest`
still green.

## S-15 (2026-09-10, Isis) — CLOSED. Ruling on QUESTIONS S-4a: widen the sweep predicate.

**Ruling (Cipher, eighth pass, 2026-09-10).** Widen the predicate, as Thor proposed for S-4a.
Addendum 2 change 3's "sweep only regions whose epoch is not the epoch in force at entry" was
written to protect the nested case - a caller's live region must survive its callee's entry.
Applied literally to `NO_ENTRY == NO_ENTRY` it protects nothing, because with no entry in force
there is no live region to protect: everything on that deque is residue by definition.

**Fix (Isis).** Extracted `currentRegion()`'s predicate as `private static boolean isCurrent(Region
region, long inForce)` = `inForce != NO_ENTRY && region.epoch == inForce`, used in both
`currentRegion()` and `sweepForeignRegions`'s loop condition, which is now `while (!stack.isEmpty()
&& !isCurrent(stack.peek(), inForce))`. The nested case is unchanged (the caller's region *is*
current, the loop stops at it); the `NO_ENTRY`-in-force case now clears the deque. WARN content
unchanged. Probe:
`CipherProbeEighthPassRegionTest.probe_raw_regions_do_not_accumulate_on_a_pooled_thread`, green,
moved to `src/test/java`.

## S-16 (2026-09-10, Isis) — CLOSED. `max-outstanding` below 1 now refuses at startup.

**Fix (Isis).** `ShreddingStartupCheck.refuseIfLedgerCapBelowOne`, called in `afterPropertiesSet`
before `WriteVerification.configureMaxOutstanding`, refuses `SHRED-CONFIG-001` when
`shredding.write-verification.max-outstanding` is below 1, naming the property, its value and the
default. `WriteVerification.maxOutstanding`'s javadoc now says it is a `static volatile` shared by
every Spring context in the JVM, the same as `ShreddingRuntime`. Probe:
`CipherProbeLedgerCapConfigTest` (`0` and `-1`), green, moved to `src/test/java`.

## S-17 (2026-09-10, Isis) — CLOSED. The `BigDecimal` placeholder's scale is in the low thousands.

**Fix (Isis).** `Placeholders.randomBigDecimal()` draws the scale from `1_000 + random.nextInt(1_000)`
instead of `1_000_000 + random.nextInt(1_000)`; the seventh pass's own prescription ("a scale of the
order of 10^6") was careless - the unguessability comes from the 64 random unscaled bits, not the
scale, and `toPlainString()` at a scale of 10^6 is over a million characters. `LOCAL_DATE` unchanged.
S-10's javadoc corrected. Probe: `CipherProbePlaceholderRenderingTest`, both methods green, moved to
`src/test/java`.

## S-18 (2026-09-10, Isis) — CLOSED. Corrected #27's own claim rather than fabricate reachability.

Cipher's fix text offered two shapes: a test that reaches `beforeCompletion`'s "still outstanding at
completion" branch, or a correction to the javadoc/CHANGELOG/QUESTIONS claiming it. I looked for a
test and did not find one, and I am confident none exists on this code: `WriteVerification.settle`
still only ever returns normally after emptying every debt it started with (each key is removed the
moment its own row's check passes, one at a time, and nothing else in this module adds a debt to a
session's ledger except `owe`, which only ever runs inside a flush that has already completed by the
time `settle` is called for it) or throws before returning at all. A throw from inside `settle`
propagates straight out of the `beforeCompletion` callback that calls it, past the branch that checks
the ledger afterwards, on every path - there is no route by which `settle` returns normally with a
non-empty ledger on this code. This matches Cipher's own analysis in the eighth-pass writeup.

**Fix (Isis).** Corrected the overclaim in three places rather than build a test for something
unreachable by construction: `WriteVerification.settle`'s own javadoc (new paragraph, explicit that
the branch stays unreachable and why), the QUESTIONS #27 "Done" entry (correction appended, the wrong
sentence identified), and the CHANGELOG #27 entry (rewritten with a correction paragraph). The branch
stays in the code, deliberately not excluded from JaCoCo, as a belt for whatever settlement path
replaces this one. No probe: an unreachable branch is what this finding is about, same as Cipher's
own writeup.

## S-19 (2026-09-10, Isis) — CLOSED. `@apiNote` on the four SPI methods; `README.md` API section.

**Fix (Isis).** `@apiNote` added to the javadoc of `ShreddingContext.enterRegion`, `recordDecoded`,
`drain` and `pendingKeysFor`: this module's internal SPI, called by `Shredded*Converter` and
`ShreddingEventListener`, not API for applications, subject to change without a major version.
`withReadBracket` unchanged and still the one supported entry. `README.md`'s "What it is careful
about" section gains one sentence naming the same split. No probe (Cipher's own finding: nothing
mechanical distinguishes the two until the module says which is which).

## S-21b (2026-09-10, Isis) — CLOSED. `refuseIfSubjectMoved` refuses, not returns, when its read-back finds no row.

Ninth pass, `docs/SECURITY-REVIEW-feat-shredding-core.md`, "Ninth pass (4a95ba5)": S-21's third
consequence ("suspected, not reproduced" there) is that `refuseIfSubjectMoved`'s own read-back,
`readStoredShreddedColumns`, treats "no row found" the same as "every shredded column is null" - the
legitimate CIPHER-14 early return - and skips the subject-immutability comparison in silence.

**Fix (Isis).** `refuseIfSubjectMoved` throws `SHRED-UNVERIFIED-WRITE`, naming the entity, the row id
and the table it looked in, whenever `readStoredShreddedColumns` returns `null` on the update path.
The method runs from `onPreUpdate` only - Hibernate is issuing an `UPDATE` for a row it believes
already exists - so "not found" here is never the legitimate new-row case; that is `onPreInsert`/
`onPostInsert`, which never calls this method.

**Probe.** `CipherProbeSubjectMovedNotFoundTest` (promoted green from `src/test-pending/java`).
Built the deterministic version rather than racing a concurrent delete: Hibernate's own row-count
check would fail on the subsequent real `UPDATE` regardless of this module's own check, masking the
finding. Instead the probe invokes `refuseIfSubjectMoved` directly (reflection, same pattern as
`CipherProbeLedgerKeyTest`/`CipherProbeSecondIntegratorTest`) with an id that addresses no row at
all - the same shape as a wrongly-addressed `SELECT` - and asserts refusal.

Out of scope, left to Thor (S-20, S-21): `BlindIndex`, `subjectColumn` and `tableName`/schema
handling were not touched. `SECURITY-NOTES.md` carries one sentence noting this module's own tables
are unqualified deliberately, per Cipher's instruction.

## S-20 (2026-09-10, Thor) — CLOSED. The subject axis of a blind index is bound to the row, as the tenant axis already was.

Ninth pass, `docs/SECURITY-REVIEW-feat-shredding-core.md`, "Ninth pass (4a95ba5)": `subjectColumn`
was validated as a SQL identifier and interpolated into the erasure's `WHERE` and both of
`verifyCleared`'s queries, and never resolved, never read at write time and never compared with
`Scope.subject()` — S-13 one column over, and fail-open in the same way.

**Fix (Thor), design addendum 3 change 8** (`docs/plans/read-path-design.md`, §3.8a–d): changes 1–4
applied to the subject axis by one resolver shared with the tenant axis (`resolveAxisProperty`), a
second `Optional<String>` on the same `BlindIndexColumn`, `rowSubject` at the write, and a refusal
when the row's subject column is not the subject the data key is derived under.

**Decision made, which Cipher left open.** `subjectColumn` naming the entity's identifier is
**refused**, not supported. The identifier is not in the state array the write path reads; under
`GenerationType.IDENTITY` it does not exist at all when `onPreInsert` derives the index; and a
`SubjectId` is a string while an identifier is as often a `Long`, a `UUID` or a `byte[]`, so the
equality would need a rendering this module would have to invent — the same class of guess as a
guessed row binding. An application that wants its id to be the subject maps that value as an
ordinary basic `String` property and names its column. `IdentifierSubjectNote` is the probe, and the
message says all of this.

**Deviation, recorded.** Cipher's two probe methods are green **as a refusal**, not as a clearing —
the same deviation, for the same reason, as change 4's on `Note` (which Cipher accepted on the ninth
pass). `SplitNote`'s shape is erasable under no keying this module can choose, so the write never
reaches the table and there is no surviving HMAC left to assert about; `AlignedNote`, in the same
file, is that application shape declared correctly and asserts the clearing property in full.

**Probes.** `CipherProbeBlindIndexSubjectColumnTest` (6) and
`CipherProbeBlindIndexSubjectColumnStartupTest` (6), both promoted into `src/test/java`.

## S-21 (2026-09-10, Thor) — CLOSED. Every statement for a user table is addressed at the persister's qualified table.

Ninth pass: `ShreddedModel.tableName(Class)` ignored `@Table(schema)`, so every statement this
module builds for a user table was unqualified and `search_path` decided which table it hit;
`@Table(schema = ...)` and `hibernate.default_schema` were both refused at startup by accident, with
a message naming a `@SecondaryTable` that did not exist.

**Fix (Thor), design addendum 3 change 9** (§3.9a–d). Cipher offered two directions and named
neither as preferred; **the qualified address is the one taken**, because refusing every
schema-qualified deployment would refuse `hibernate.default_schema`, which is how a large share of
enterprise deployments name their schema. New `TableRef` in the core domain, parsed from Hibernate's
own table expression and rendered quoted per part; `ShreddedField.table()` and
`BlindIndexColumn.table()` come from the persister at startup for every `@Shredded` entity, indexed
or not; `tableName(Class)` survives only as the provisional value for a model scanned without an
`EntityManagerFactory`, which builds no SQL.

**Found while fixing it, and fixed with it.** The `@SecondaryTable` refusal compared
`tableName(type)` with itself — one value per entity, so `distinct().count()` was always 1 and the
check could never fire. It now compares each shredded field's own containing table against the
entity's primary table, and it fires for a single `@Shredded` field too.

**Residual, stated in `SECURITY-NOTES.md`.** With no schema in the mapping, Hibernate's own table
expression is unqualified and so is this module's: `search_path` decides, exactly as it does for
Hibernate's own statements. This module's own `shredding_*` tables are unqualified deliberately.

**Probes.** `CipherProbeNinthPassBlindIndexTest` (5, promoted), including the K1 probe Cipher did not
build — a decoy `public.schema_note` ahead of `app2` on `search_path`, which the erasure must leave
untouched — plus `TableRefTest` (7) in the core.

## S-22 (2026-09-10, Thor) — CLOSED. Every column identifier is the one Hibernate's mapping addresses.

Cipher's tenth pass, HIGH, and a design stop: addendum 3 gave the *table* an identifier type and left
the *columns* as bare `String`s, so the erasure's three columns were interpolated unquoted while every
statement the starter built quoted them, and `ShreddedModel.unquote` folded case before it compared.
A reserved-word subject column (`user`) became `WHERE user = ?` — parses, compares the connection's
role name, matches nothing — and the erasure's own read-back, built from the same text, agreed.

Designed in `docs/plans/read-path-design.md` as **addendum 4**, reviewed by Cipher twice
(APPROVED WITH CHANGES ×13, then APPROVED WITH TWO CORRECTIONS), both corrections applied in the
addendum text before any code (`606ef97`).

**Built.** `ColumnRef(text, quoted)` in the core domain, JDK-only, reproducing Hibernate's quoting
rather than imposing one; `ColumnRefs` the single construction site, parsing with the *static*
`Identifier.toIdentifier` and asserting the round trip at startup; every statement on `TableRef` +
`ColumnRef`; every hand quote/unquote helper deleted; annotation text demoted to a case-sensitive
lookup key; refusals for formula, `assignmentExpression`, `@ColumnTransformer`, `@JoinColumn`,
composite id, case-only twins, a `"` in the parsed name and a non-PostgreSQL dialect; and the
independent, unconditional, Hibernate-rendered residual on the erasure's own connection.

**Two things the design assumed that the build found otherwise, both corrected in code, neither
changing the property.**

1. *`getCustomReadExpression()` is never null.* Hibernate populates a templated read
   (`{@}.<column>`) and a write (`?`) for **every** column, so change 4's "refuse when either is
   non-null" would have refused every application. A `@ColumnTransformer` is detected as a read that
   is not the plain template of this column's own expression, or a write that is not a bare
   parameter.
2. *Spring Boot's default physical naming strategy lower-cases `@Column(name = "OWNER_ID")`.* The
   unquoted-upper-case shape change 2 exists for only appears under Hibernate's own
   `PhysicalNamingStrategyStandardImpl`, so `probe_an_unquoted_upper_case_column_is_addressed_folded`
   pins that strategy explicitly. The behaviour under Spring Boot's default is unchanged and covered
   by every other probe.

**Probes.** `CipherProbeColumnIdentityTest` (11) and `CipherProbeReadBackIndependenceTest` (6), all
in the default build, 9 of the 17 RED on `606ef97` before the hook. `CipherProbeTenthPassTest`'s five
promoted out of `src/test-pending`, which is removed. One deviation, recorded rather than hidden:
`probe_a_column_name_containing_a_quote_character_is_refused` pins a unit (`ColumnRefs.parse`) that
did not exist before, so it could not be red against prior behaviour — it was written before the
resolver's callers and is green from its first run.

## S-24 (2026-09-10, Thor) — CLOSED with S-22, by construction.

A `@Shredded` column the mapping quotes (`@Column(name = "\"Email\"")`) used to be read as raw
annotation text by `ShreddedModel.columnName(Field)` and then quoted again by the starter's own
`quote()`, producing an identifier with the quote characters *inside* the name: the application
booted and failed on whichever row was written first.

Closed by change 5, not by a better refusal: `@Shredded`'s column is resolved from Hibernate's
mapping **by property name**, and its annotation text is never read, never compared and never quoted.
The mapping therefore settles at startup, and a quoted column simply works.

**Probe.** `CipherProbeTenthPassTest.probe_a_quoted_shredded_column_is_settled_at_startup_not_at_the_first_write`,
promoted and green by the design's choice — never by a `PSQLException` out of `saveAndFlush`.

## S-23 (2026-09-10, Isis) — CLOSED. `@Shredded` inside an entity inheritance hierarchy is refused by its real reason.

Tenth pass: `ShreddedModel.allFields` walks an entity class and every superclass, so a `@Shredded`
field declared on the root of an `@Inheritance` hierarchy was scanned once per concrete entity that
inherits it, each time against the one converter it declares, under a different `entityName`. No
converter pair can satisfy every scan, so the shape was always refused — but by
`requireMatchingConverter`, naming the converter's entity/field pair as though the developer had
copy-pasted it wrong. They had not: the shape itself is not supported, under any strategy.

**Fix.** `ShreddedModel.refuseIfInheritedFromAnotherEntity`, called before the converter check, for
every `@Shredded` field whose `Field.getDeclaringClass()` is not the entity currently being scanned
and is itself `@Entity`-annotated. Names the ancestor and the inheriting entity, and says
`@MappedSuperclass` is the supported way to share the field. A field declared on a plain
`@MappedSuperclass` is unaffected — it is never scanned as `type` under more than one `entityName`,
so it never had this problem, and this check does not see it as "declared elsewhere" because
`@MappedSuperclass` carries no `@Entity` annotation.

**Documented, not designed around.** `@Shredded` on an inherited entity field is a permanent
limitation, not a residual to close later — every one of this module's per-field checks (subject
expression, `@Immutable`, secondary-table, `onPostLoad`'s field list) is keyed by one entity name,
and making an inherited field work would mean redesigning all four around a field that can belong to
more than one entity. Recorded in `docs/index.md` and `SECURITY-NOTES.md`, beside the existing
`@Embeddable`/`@ElementCollection` limitation (C-29).

**Probe.** `CipherProbeTenthPassTest.probe_a_shredded_field_in_an_inheritance_hierarchy_is_refused_by_its_real_reason`
— RED on `3c424c1` (asserted the message contains "inherit"; got the converter-pair message
instead), GREEN after the fix. That test class is not promoted out of `src/test-pending/java` yet:
two of its other four methods are S-22's and S-24's probes, both Thor's design stop and both still
red by design, and the module's convention is that the whole file moves together only once every
method in it is green.

## S-25 (2026-09-10, Isis) — CLOSED. The starter suite's container-count flake.

Cipher's tenth pass named `CipherProbeCompositeIdTest`'s "Unable to determine Dialect" a flake:
not reproduced in three consecutive full runs, but ruled fix-required because the starter's suite
starts one `PostgreSQLContainer` per test class (32 at the tenth pass) and dialect resolution needs
a live bootstrap connection — under load, one container not yet accepting connections before
Hikari's 30s default `connectionTimeout` reproduces exactly that symptom on whichever context
bootstraps first.

**Fix, both parts Cipher asked for.** Every probe application's properties (all 33 files that start
a `PostgreSQLContainer` under `gdpr-shredding-spring-boot-starter/src/test` and `src/test-pending`)
now pin `spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect`, so
dialect resolution never opens a bootstrap connection at all and cannot race the container. Every
`@Container` declaration also now carries an explicit
`.withStartupTimeout(java.time.Duration.ofMinutes(2))` instead of Testcontainers' default.

**Follow-up deferred, not attempted.** Cipher's suggested follow-up — collapsing the per-test
containers onto one reused singleton with a fresh schema per test class — "if it fits in under two
hours." It does not: all 33 files each build their own `SpringApplicationBuilder` (or
`@SpringBootTest` with `@DynamicPropertySource`) context and each declare their own `@Container`
field: a shared singleton needs every one of those bootstraps touched to pick a schema or database
name per test class for isolation, which is a mechanical but cross-cutting change across the whole
suite, not a two-hour patch on top of this fix. Not a design stop either — no new mechanism, just
more files than the box allows — so recorded here as deferred rather than either built narrowly or
escalated.

**Measured.** `./mvnw -B clean verify` (full reactor, three consecutive runs): BUILD SUCCESS every
time, 289/289 tests, 0 failures; `CipherProbeCompositeIdTest` green (2/2) all three runs, no dialect
failure observed. Container count unchanged (33 static `@Container` declarations before and after —
this fix removes the race, not the container count; the singleton collapse above is what would
reduce it, and is deferred).
