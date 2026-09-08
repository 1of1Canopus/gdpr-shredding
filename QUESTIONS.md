# QUESTIONS — open decisions on the GDPR Shredding free core

Numbered, with the answer I took and why. Anything Dollar or Souhaile disagrees with, say so and I
will change it; I did not wait on any of these, because none of them blocks the rest of the work.

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

---

## #2 A shared chain library (deferred, as instructed)

The erasure log is module B's audit chain copied and adapted: keyed from birth, key id in the hashed
material, length-prefixed canonical form, external anchor row, the same six verifier statuses, the
same trigger set. Three things differ and are not cosmetic: the record's fields, the pseudonymised
subject, and the fact that this chain's key is explicitly never destroyed by an erasure.

**Recommendation.** Extract `housedevinci-chain` after module D, when there are three call sites and
the shape has stopped moving. Extracting it now would freeze an API on a sample of two.

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

**Please confirm.** I read it as within the spirit of controls 6 and 11, but it is an addition to
the data model that Cipher's section does not name.

---

## #4 Subject immutability is enforced from a bounded per-thread map (taken; a known gap)

Control 14 requires that a persisted row's data subject cannot change. Hibernate's `PreUpdateEvent`
carries the *hydrated Java* state, not the stored blob, so the previous subject cannot be read from
the row at that moment. The listener therefore remembers the subject a row loaded (or was inserted)
under, in a per-thread, access-ordered map bounded to 10 000 entries, and refuses an update whose
resolved subject differs.

**The gap.** If the entry has been evicted, or the entity is updated in a thread that never loaded
it (a detached merge from another request), the check cannot fire and the update is allowed.

**Options.** (a) accept it and document it, which is what I have done; (b) require entities with
`@Shredded` fields to carry a `@Version` and stash the subject in a shadow column, which changes the
user's schema; (c) read the stored blob in `PreUpdate` with a second query, which costs a round trip
per shredded update. I would take (a) for the free core and (b) or (c) as a Pro strictness mode.

---

## #5 `LocalDate` and `BigDecimal` have no sentinel (taken)

There is no `LocalDate` or `BigDecimal` value that means "erased". Those two types read as `null`
after an erasure whatever `shredding.erased-value.policy` says. I refused to use `0` or
`LocalDate.EPOCH`: a zero balance is a fact and an erased balance is not.

Documented in the Javadoc and in `docs/index.md`. If Dollar prefers, the alternative is to require
those fields to be boxed and force the `exception` policy for them.

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

---

## #9 The `toString` leak rule is a sample-level ArchUnit test (taken)

Control 12 asks for "the module's ArchUnit rule" flagging a `@Shredded` field reaching a generated
`toString`/`equals`/`hashCode`. The rule lives in the sample, because it has to run against the
*application's* entities, not the library's own classes, and a library cannot run ArchUnit inside
its users' builds.

**Recommendation.** Ship the rule as a documented snippet users paste into their own test sources
(the sample is that snippet), and add the record check to the startup scan so at least the worst
case - an entity that is a record - fails without any test at all. I have not added that startup
check yet; say the word and it is four lines.

---

## #10 Regulatory citations are placeholders until checked (flagged)

`docs/index.md` names EDPB Guidelines 5/2019, the CNIL's encryption guidance and the ICO's right-to-
erasure page. The acceptance check asks for exact section numbers and links. I have not verified the
section numbers, and I will not invent them. Someone with the documents open needs to fill them in
before the article and the launch.
