# QUESTIONS — open decisions on the GDPR Shredding free core

Numbered, with the answer I took and why. **Dollar ruled on all ten on 2026-09-08**; each entry
carries the ruling and what it changed in the code. #4 stays open for Cipher to pick between two
options, and #10 stays open until Odin returns the citations.

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

## #12 ENISA pseudonymisation report: section to verify (open)

An ENISA pseudonymisation report is the obvious fourth source, and I have seen it cited for exactly
this technique. **Odin could not verify a section**, so it is deliberately not in `docs/index.md`:
an unverified citation is worse than none. Left here so it is not lost. Someone with the report open
needs to give a title, year and section before it goes into the docs.
