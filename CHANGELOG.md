# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
[semantic versioning](https://semver.org/).

## [Unreleased]

### Changed
- Internal working documents (the spec, the status log, the open-questions log, the security
  review write-up, design plans) moved out of this repository to a private location; they named an
  internal review process that has no reason to be public. `SECURITY-NOTES.md` and this
  changelog stay, with that narration scrubbed and every finding id and technical detail kept.
  Added `SECURITY.md` (vulnerability reporting, 90-day disclosure) and expanded
  `CONTRIBUTING.md` with the DCO sign-off and inbound-licensing terms, matching the rest of
  the product line.

### Fixed (fourteenth pass at `c1b4157`, three LOW: three loose ends the pre-public docs cleanup left)

**LOW (F-1).** Ten lines across six public files still pointed at documents the previous change
moved out of this repository (the open-questions log, mostly by number - `#4`, `#9`, `#16`, `#19`
- and, once, the portfolio's licensing rationale). A reader of the public repo or the starter's
sources jar could never follow any of those pointers. Each is rewritten with the decision itself
stated in place: `ShreddedModel`'s CIPHER-06 note, `ShreddingEventListener`'s C-27 and
`refuseIfSubjectMoved`/`onPostLoad` notes, `ShreddingReadBracketCustomizer`'s
`BeanPostProcessor`-over-`RepositoryFactoryCustomizer` rationale (and its now-corrected dead
`{@link ShreddingContext#popReadBracket()}`, a method that no longer exists - retargeted to
`enterRegion()`/`closeRegion(long)`, the pair that replaced it), `SECURITY-NOTES.md`'s C-27
paragraph, and three `CHANGELOG.md` entries below, including the FSL licensing entry's pointer to
the portfolio-level licensing rationale document. `ci.yml`'s `build-and-test` job gained a `git
grep` step that fails the build on a reference to any of these moved documents, or to this machine's own
filesystem, outside `internal/` - the same shape of guard as agent-guard's, written here since
agent-guard did not yet have one to copy.

**LOW (F-2).** `CONTRIBUTING.md` stated "`ci.yml` checks that every commit in the pull request
carries one [`Signed-off-by`]" while `ci.yml` had no such job - the DCO trailer CONTRIBUTING calls
"the whole inbound-licensing agreement" was documented as machine-enforced and was not. Added the
`dco` job, copied from `B-agent-guard/.github/workflows/ci.yml` verbatim (the PR commit-range
check, the trivial-back-merge exemption by parent count and tree equality, not by commit subject).
Adding "DCO sign-off" to the branch protection ruleset's required checks is deferred: this repo is
private and has no ruleset yet; the status log records that the ruleset, and this required check,
are created at go-public time.

**LOW (F-3, self-inflicted at `48454b2`, missed by the thirteenth pass).** The release profile did
not build: `./mvnw -B -DskipTests -Prelease -Dgpg.skip=true package` failed on five javadoc errors
- four `unknown tag: apiNote` in `ShreddingContext` (the javadoc plugin's `doclint=all,-missing`
config has no `<tags>` entry registering the JDK-internal `@apiNote` block tag) and one `reference
not found` in `ShreddingReadBracketCustomizer`, the dead link above. The four `@apiNote` blocks are
rewritten as plain `<p><strong>API note</strong>...` description paragraphs (no plugin
configuration change; the tag was never declared to the doclet and the content reads the same way
either form). Nothing else in the release profile changed - CI already runs `clean verify` and
`-Psecurity-scan`; it now also runs `./mvnw -B -DskipTests -Prelease -Dgpg.skip=true package` as a
`release-dryrun` job on every push and pull request, so a break in the sources jar, the javadoc
jar, or the release profile's own plugin wiring fails CI instead of shipping unnoticed to the next
real release attempt.

### Fixed (twelfth pass at `13535d8`, F-1 LOW: a `@BlindIndex` column on a `@SecondaryTable` booted, and every later erasure of that entity failed)

**LOW.** `ShreddedModel.resolveIndexColumns` built the `BlindIndexColumn` from two independent
sources: `primaryTable(persister)` for the table, and the `@BlindIndex` field's own mapping for the
column. It never compared the two. The `@Shredded` column and both index axes (`subjectColumn`,
`tenantColumn`) already refuse at startup when their mapping disagrees with the entity's primary
table; the `@BlindIndex` column itself did not, so a field mapped `@Column(name = "email_idx", table
= "secidx_note_ext")` onto a `@SecondaryTable` booted, wrote indexes correctly, and then every
erasure of that entity failed with `SHRED-KEY-UNAVAILABLE` (`SQLState 42703`, undefined column) — the
erasure's `UPDATE` names the primary table, which has no such column.

- **Changed** `ShreddedModel.indexColumnOf`: takes the entity's primary table and compares it with
  `TableRef.parse(basic.getContainingTableExpression())`, refusing `SHRED-CONFIG-001` at startup
  when they differ, naming the entity, the field, the containing table and the primary table — the
  same message shape `refuseSecondaryTableSplit` and `resolveAxis` already use, and for the same
  reason. Probe: `probe_a_blind_index_column_on_a_secondary_table_is_refused_at_startup`.

### Fixed (eleventh pass at `704f23b`, E-1 MEDIUM: two entities on one table could silently share one independent read-back)

**MEDIUM.** `HibernateBlindIndexResidual` keyed its residual queries on `(table, blind-index column)`
only, never on the subject/tenant axis a mapping matches on. Two entities mapped to the same table
that index the same physical column collided in one `LinkedHashMap`; the second `put` silently
overwrote the first and `Map.copyOf` said nothing. From then on the erasure's independent read-back —
design addendum 4, §4.5, the check that exists precisely because the erasure's own statements cannot
verify themselves — verified one of the two blind indexes with the *other* entity's HQL, which
matches on the wrong subject column. An erasure could record `COMPLETE` with that entity's blind
index still populated.

- **Changed** `HibernateBlindIndexResidual`'s constructor: captures the return of `built.put(key,
  residual)` and, when a second entity resolves to the same `(table, column)` with a different
  residual, refuses at startup (`SHRED-CONFIG-001`) naming both entities, the shared table and the
  shared column. Two entities over one table indexing the same column is a mapping this module has
  not been shown to erase correctly, so it is refused rather than silently checked by half a net.
  Probe: `probe_two_entities_on_one_table_do_not_share_one_independent_read_back`.

### Fixed (eleventh pass at `704f23b`, E-2 LOW: an unquoted reserved-word column mapping booted and refused every later erasure, blaming a trigger)

**LOW.** `@Column(name = "user")`, unquoted, against a physical column PostgreSQL already reserves,
round-trips cleanly through `ColumnRefs.of` — the parse and the render agree, so startup accepted the
mapping. Hibernate's own SQL is alias-qualified and unaffected; this module's `WHERE`/`SET` are not,
so a bare `user` there is read as `CURRENT_USER`, matching nothing. The independent read-back (S-22's
net) caught the miss and refused the transaction every time, correctly — but with a message
(`SHRED-ERASURE-004`) that blames "a trigger, a rule, a rewriting view" and never names the mapping
that actually caused it. Every erasure of that entity was, and stayed, impossible.

- **Added** `PostgreSqlReservedKeywords`, vendored from `pg_get_keywords()` (catcode `R` "reserved"
  and `T` "reserved, can be function or type name") against PostgreSQL 16.14, the version this
  module's tests pin — the two classes that cannot appear as a bare `ColId`, the exact grammar
  position an unqualified column reference occupies. 101 words, checksum-verified at class-init so a
  hand-edited or corrupted list fails loudly. Deliberately **not** `Dialect.getKeywords()`, which
  mixes reserved and non-reserved words and would refuse an ordinary column named `value` or `name`.
- **Changed** `ColumnRefs.of`: after the round trip, refuses an **unquoted** `ColumnRef` whose text
  folds to one of PostgreSQL's reserved key words, naming `Entity.property`, the column, and the fix
  (`@Column(name = "\"user\"")`). Probe:
  `probe_an_unquoted_reserved_word_column_is_refused_at_startup_naming_the_mapping`; the fail-closed
  net for the case that survives past a mapping this module cannot see (a legacy row written by
  another system) stays pinned by
  `CipherProbeEleventhPassTest#probe_an_unquoted_reserved_word_subject_column_never_reports_a_completion_it_did_not_do`.

### Fixed (eleventh pass at `704f23b`, E-3 LOW: S-25's startup timeout and dialect pin were applied to the starter only)

- **Changed** four `PostgreSQLContainer` declarations outside the starter (`gdpr-shredding-core`'s
  `CipherProbeJdbcTest`; `gdpr-shredding-sample`'s `SampleEndToEndTest`, `LogScanTest`,
  `CipherProbeActuatorEndToEndTest`) to carry `.withStartupTimeout(Duration.ofMinutes(2))`.
- **Changed** the same three sample test contexts to pin
  `spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect` via
  `@DynamicPropertySource`, closing the "Unable to determine Dialect" flake under container-count
  load the same way the tenth pass closed it in the starter.

### Fixed (eleventh pass at `704f23b`, E-4 INFO: `@BlindIndex` Javadoc and `TableRef`'s pattern comment still described the pre-addendum-4 behaviour)

- **Changed** `BlindIndex`'s Javadoc and `TableRef`'s `IDENTIFIER` pattern comment: `subjectColumn`/
  `tenantColumn` are lookup keys, matched case-sensitively against Hibernate's own mapping and then
  thrown away — they never become SQL identifiers and there is no pattern they are validated against
  any more, unlike `TableRef`'s own schema/name.

### Fixed (tenth pass, S-22 HIGH and S-24 LOW: every column identifier is now the one Hibernate's mapping addresses)

**HIGH.** Design addendum 3 gave the *table* an identifier type (`TableRef`) and left the *columns*
as bare `String`s: `@Column(name = ...)` text and `@BlindIndex(subjectColumn/tenantColumn)` text,
lower-cased by a hand-written `unquote`, then quoted by a hand-written `quote` in the starter and
**not quoted at all** in `JdbcErasureStore`. A column the mapping quotes was therefore addressed as a
different column, and the erasure's own read-back — built from the same text — agreed with it.
`WHERE user = ?` against a reserved-word subject column parses, compares the connection's role name
and matches nothing: no row cleared, key and ciphertext destroyed, record `COMPLETE`, and the HMAC of
the erased plaintext still in the table. A quoted `"Owner"` beside a plain `owner` cleared a
bystander's index and kept the victim's. S-24 was the same root one column over: a quoted
`@Shredded` column booted and failed on the first row written.

- **Added** `ColumnRef(String text, boolean quoted)` in the core domain, JDK-only (ArchUnit names it
  on its own). It **reproduces** Hibernate's quoting rather than imposing one — bare when the mapping
  is unquoted, `"`-wrapped when it quotes — because `@Column(name = "OWNER_ID")` is an ordinary
  unquoted mapping whose physical column PostgreSQL folded, and blanket-quoting it would address a
  column that does not exist.
- **Added** `ColumnRefs`, the one place a `ColumnRef` is built: from the persister's own
  `getSelectionExpression()`, parsed by the *static* `Identifier.toIdentifier(String)` — never
  `IdentifierHelper.toIdentifier`, whose `normalizeQuoting` adds quoting the mapping never had under
  `globally_quoted_identifiers`, `auto_quote_keyword`, a leading `_` or a `$`. Startup asserts the
  parse round-trips through both `Identifier.render(dialect)` and `ColumnRef.sql()`.
- **Changed** `BlindIndexColumn` to carry three `ColumnRef`s; `ShreddedModel.ShreddedField` to carry
  its resolved `ColumnRef`; `singleIdColumn` to return one. Every statement now takes a `TableRef`
  and `ColumnRef`s: no `String` identifier survives in a signature on any SQL path.
- **Removed** `BlindIndexColumn`'s identifier pattern, `ShreddedModel.columnName(Field)` and
  `.unquote`, and the two starter `quote()` helpers. There is no hand-written quoting left in the
  module outside `TableRef`.
- **Changed** `@BlindIndex(subjectColumn/tenantColumn)` to be a **lookup key**, matched
  case-sensitively against the mapped columns and never used as an identifier. No case-insensitive
  second pass exists or may be added. The refusal lists the mapped columns verbatim with their
  quoting and names the ones differing from the key only by case; a key matching one column exactly
  while another differs only by case is refused as unreadable.
- **Changed** `@Shredded`'s column to resolve by **property name**, its annotation text never
  compared — which closes S-24 by construction rather than by a better refusal.
- **Added** startup refusals, each by its real reason: a `@Formula` on Hibernate's `isFormula()`
  flag (never on the shape of the expression); a `Column.assignmentExpression` by the round trip; a
  `@ColumnTransformer` on the subject, tenant or index column, which mis-addresses *by value*; a
  `@JoinColumn` named as an axis column, reported as an association; a composite identifier; a `"`
  in the parsed name; and any non-PostgreSQL dialect.
- **Added** the independent read-back (`BlindIndexResidual`, implemented by
  `HibernateBlindIndexResidual`): after the `UPDATE`, **unconditionally**, a residual Hibernate
  renders from the entity mapping — subject and tenant as HQL parameters, the index column through
  the persister's own property — run on the erasure's **own** `Connection` through a
  `StatelessSession`, which shares the transaction and snapshot and cannot flush. Above zero refuses
  with `SHRED-ERASURE-004` and rolls the whole transaction back. `JdbcErasureStore` has no default
  residual: an erasure whose only check is the statement it just ran is the shape that shipped.
- **Changed** the refusal predicate: row counts are never one. `cleared < rows` is normal (`AND
  <col> IS NOT NULL` makes it a subset) and stays a diagnostic.
- **Documented** `hibernate.globally_quoted_identifiers` (with and without
  `_skip_column_definitions`) and `hibernate.auto_quote_keyword` as supported for columns, quoted or
  unquoted, reproduced verbatim; tables unchanged.

Probes (all in the default build; `src/test-pending` removed):
`CipherProbeColumnIdentityTest` (11) and `CipherProbeReadBackIndependenceTest` (6), plus the five
`CipherProbeTenthPassTest` methods promoted and green by their own assertions.

### Fixed (tenth pass, S-23: `@Shredded` inside an entity inheritance hierarchy was refused by a reason the developer could not act on)

**LOW.** `ShreddedModel.allFields` walks an entity class and every superclass to collect
`@Shredded` fields, which is what lets a field be shared through a `@MappedSuperclass`. It made no
distinction between a `@MappedSuperclass` ancestor and an `@Entity` ancestor: a `@Shredded` field
declared on the root of an `@Inheritance` hierarchy (`JOINED`, `SINGLE_TABLE` or
`TABLE_PER_CLASS`) was scanned once per concrete entity that inherits it, each time against the
field's one converter, under a different `entityName` — no converter pair could ever satisfy every
scan, so the shape was always refused, but the message named the converter's declared entity/field
pair as though it were a copy-paste mistake the developer could correct. It cannot be: the shape is
not supported under any inheritance strategy.

- **Added** `ShreddedModel.refuseIfInheritedFromAnotherEntity`: refuses at startup, before the
  converter check runs, when a `@Shredded` field's declaring class is not the entity being scanned
  and that declaring class is itself `@Entity`-annotated — naming the ancestor and the inheriting
  entity, and pointing at `@MappedSuperclass` as the supported way to share the field. A field
  inherited from a plain `@MappedSuperclass` is unaffected.
- **Documented** the limitation in `docs/index.md` and `SECURITY-NOTES.md`, beside the existing
  `@Embeddable`/`@ElementCollection` limitation (C-29).

Probe: `CipherProbeTenthPassTest.probe_a_shredded_field_in_an_inheritance_hierarchy_is_refused_by_its_real_reason`.

### Fixed (tenth pass, S-25: the starter's Testcontainers suite could fail bootstrap dialect resolution under container-count load)

**LOW, the flake.** The security review could not reproduce "Unable to determine Dialect" in three consecutive
full `verify` runs, but ruled it fix-required rather than accepted: the starter's suite starts one
`PostgreSQLContainer` per test class, and under load one container not yet accepting connections
before Hikari's default 30s `connectionTimeout` would produce exactly that failure on whichever
context bootstraps first, since dialect resolution needs a live connection.

- **Pinned** `spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect` (or
  the `DynamicPropertySource` equivalent) in every probe application's properties, so dialect
  resolution never needs a bootstrap connection and cannot race the container regardless of how
  slow it is to accept connections.
- **Added** an explicit `.withStartupTimeout(java.time.Duration.ofMinutes(2))` on every
  `@Container static final PostgreSQLContainer`, rather than relying on Testcontainers' default.
- **Deferred** (not a design stop): collapsing the per-test containers
  onto one reused singleton, which does not fit the two-hour follow-up window without restructuring
  every probe's own `SpringApplicationBuilder`/`@DynamicPropertySource` bootstrap for schema
  isolation.

### Fixed (ninth pass at `4a95ba5`, S-20: a blind index whose `subjectColumn` is not the shredded subject survives that subject's erasure)

**HIGH.** Design addendum 3 bound one of the two axes of a blind index to the row it sits in.
`subjectColumn` — the other half of the erasure's `WHERE` — was left exactly as S-13 found
`tenantColumn`: validated as a SQL identifier, interpolated into `clearBlindIndexes` and into both
of `verifyCleared`'s queries, and never resolved to a property, never read at write time, never
compared with the subject the data key, the AAD and the erasure request are all keyed on. An entity
whose `@Shredded(subject = ...)` evaluated to something other than the value in `subjectColumn`
wrote an index no erasure could reach: the key died, the ciphertext died, the chained record said
`COMPLETE`, and `HMAC(secret, tenant | entity | field | plaintext)` stayed in the table as a stable
cross-row correlator for the erased subject and, over a low-entropy field such as an email address,
a confirmation oracle for anyone holding `shredding.blind-index.hmac-secret`. It was fail-*open*:
nothing at startup, nothing at the write and nothing in the erasure said a word, because
`verifyCleared`'s residual query was keyed on the same `subjectColumn` that missed.
`@Shredded(subject = "#{customer.externalId}")` with `subjectColumn = "customer_id"` — the subject
one association away — is the ordinary shape that reached it without trying.

Fixed by design addendum 3 change 8, which applies changes 1–4 to
the subject axis verbatim rather than inventing a mechanism:

- **Added** `ShreddedModel.resolveAxisProperty`: one resolver for both axes, so their rules cannot
  drift apart again (S-20 exists because they were written for one axis and never applied to the
  other). `subjectColumn` must resolve, through the entity's own column mapping, to exactly one
  property that is basic, `String`-typed, on the primary table, not a formula, not itself
  `@Shredded` and not inside a component — every other outcome is `SHRED-CONFIG-001` naming the
  entity, the index field, `subjectColumn` and what was found.
- **Decided** the case the security review left open: `subjectColumn` naming the entity's identifier is
  **refused**, with the reason in the message. The identifier is not in the state array the write
  path reads, under `GenerationType.IDENTITY` it does not exist yet when the index is derived, and a
  `SubjectId` is a string while an identifier is as often a `Long`, a `UUID` or a `byte[]` — so the
  equality this check exists to make would need a rendering this module would have to invent.
- **Added** `BlindIndexColumn.subjectProperty`, beside `tenantProperty` on the same record, resolved
  once, read by the write path (the property) and the erasure path (the column).
  `ShreddingStartupCheck` refuses an unresolved one.
- **Added** `ShreddingEventListener.rowSubject`: the write is refused with
  `SHRED-UNVERIFIED-WRITE` when the subject column's value is null, blank or not a `String`, and —
  the change that closes the finding — when it is not `scope.subject()`, naming both values, the
  field and the column, before any derivation.

Probes: `CipherProbeBlindIndexSubjectColumnTest` (the security review's two, promoted from `src/test-pending/java`
and green **as a refusal**, plus `AlignedNote`, the same application shape declared correctly, which
erases key, ciphertext and index together) and `CipherProbeBlindIndexSubjectColumnStartupTest` (one
per refusal branch, plus the camel-case configuration that must still boot). The refusal is the same
recorded deviation as change 4's on `Note`, for the same reason: `SplitNote`'s shape is erasable
under no keying this module can choose, so the original "the erasure clears the index" assertion is
unbuildable on that fixture and the property is asserted on the correctly declared one.

### Fixed (ninth pass at `4a95ba5`, S-21: every statement for a user table was addressed unqualified, so `search_path` decided which table it hit)

**MEDIUM.** `ShreddedModel.tableName(Class)` read `@Table(name = ...)` and ignored `schema`, and
every statement this module builds for a user table came from it: the blind-index `UPDATE`,
`verifyCleared`'s two queries, the post-hoc header read-back, the `IDENTITY` rebind and the
subject-immutability `SELECT`. Which table they actually hit was decided by the runtime connection's
`search_path` rather than by the mapping Hibernate uses. Consequences: `@Table(schema = ...)` was
refused at startup by accident, with a message about a `@SecondaryTable` that did not exist;
`spring.jpa.properties.hibernate.default_schema` — how a large share of enterprise deployments name
their schema — made every `@BlindIndex` mapping in the application unusable with the same misleading
message; and a same-named table earlier on `search_path` would have taken every one of those
statements.

Fixed by design addendum 3 change 9, taking the first of the security review's two directions (refusing every
schema-qualified deployment would refuse `hibernate.default_schema`, and a library that cannot boot
there is not a library):

- **Added** `TableRef` (core domain): a table as an optional schema and a name, parsed from
  Hibernate's own table expression (dots outside quotes, each part unquoted and validated against
  the identifier pattern) and rendered quoted per part. A catalog-qualified expression and an
  identifier that is not folded lowercase are refused with `SHRED-CONFIG-001` rather than reduced or
  lowercased into another table's name.
- **Changed** `ShreddedField.table()` and `BlindIndexColumn.table()` to `TableRef`s taken from the
  persister at startup (`ShreddedModel.resolveTables`), for every `@Shredded` entity — not only the
  indexed ones. `ShreddedModel.tableName(Class)` survives only as the provisional value for a model
  scanned without an `EntityManagerFactory`, which builds no SQL.
- **Fixed** the `@SecondaryTable` refusal, which compared `tableName(type)` with itself — one value
  per entity, so `distinct().count()` was always 1 and it could never fire. It now compares each
  shredded field's own containing table with the entity's primary table, and it fires for a single
  `@Shredded` field too.
- **Fixed** change 1's primary-table comparison, which compared a persister table expression
  (`public.owned_note`) against an annotation-derived name (`owned_note`); both sides now come from
  the same source.

Probes: `CipherProbeNinthPassBlindIndexTest` promoted from `src/test-pending/java`, all five green —
`@Table(schema = "app2")` boots, writes and erases; `hibernate.default_schema` boots; and the K1
probe the security review did not build,
`probe_a_same_named_table_in_another_schema_earlier_on_the_search_path_is_not_touched`, holds a decoy
`public.schema_note` ahead of `app2` on `search_path` with a live index column that the erasure must
leave untouched while clearing the real one. Plus `TableRefTest` in the core.

**Residual, stated in `SECURITY-NOTES.md`:** with no schema in the mapping, Hibernate's own table
expression is unqualified and so is this module's, and `search_path` decides — exactly as it does
for Hibernate's own statements. This module's own `shredding_*` tables are unqualified deliberately
and are expected on the runtime role's `search_path`.

### Fixed (ninth pass at `4a95ba5`, S-21b: the subject-immutability check failed open on a wrongly-addressed read-back)

**MEDIUM.** `refuseIfSubjectMoved` (control 14) is the write path's per-update check that a
persisted row's data subject has not moved out of its own erasure scope; it re-reads the row's own
stored shredded columns by id, from `onPreUpdate` only. `readStoredShreddedColumns` returns `null`
both when a row genuinely holds no shredded blob at all (the legitimate early return, CIPHER-14) and
when its `SELECT ... WHERE id = ?` simply finds no row - and the caller did `if (stored == null) {
return; }` for both, skipping the comparison in silence. A `SELECT` that cannot find the row
Hibernate believes it is about to `UPDATE` is either racing a concurrent delete (in which case
Hibernate's own row-count check fails a moment later anyway) or addressing the wrong table or row -
never evidence the check passed. Fixed: `refuseIfSubjectMoved` now throws `SHRED-UNVERIFIED-WRITE`,
naming the entity, the row id and the table looked in, whenever the read-back finds no row. The only
legitimate "not found" for a `@Shredded` entity is a brand-new row on insert, which never reaches
this method.

Probe: `CipherProbeSubjectMovedNotFoundTest.probe_the_subject_immutability_check_refuses_when_the_read_back_finds_no_row`,
promoted green from `src/test-pending/java`. It invokes the check directly with an id that addresses
no row at all - the deterministic shape of a wrongly-addressed `SELECT` - rather than racing a
concurrent delete, which Hibernate's own row-count check would mask.

### Fixed (eighth pass at `fa6f477`, S-13 / S-7b: a blind index survives the erasure of the subject it was derived for)

**HIGH.** The index was derived under `Scope.tenantFor(of-field)` - a field's declared tenant, else
the ambient `TenantSupplier` - while `clearBlindIndexes` matched the row's **stored** `tenantColumn`
value. An application whose tenant column holds an owning company while the supplier yields the
acting organisation therefore completed an erasure, destroyed the key, killed the ciphertext,
reported success, and left `HMAC(secret, tenant | entity | field | plaintext)` in the table: a
stable cross-row correlator for the erased subject and, over a low-entropy value such as an email
address, a confirmation oracle for anyone holding the index secret. Fixed per design addendum 3 with
the security review's seven changes ("Addendum 3 as built"):

- `tenantColumn` is a **column** name and is resolved once, at startup, through the entity's own
  column mapping to the single basic `String` property on the primary table that maps to it. None,
  two, non-`String`, a formula, the identifier, an encrypted column, or a match only inside an
  `@Embeddable` are startup refusals (`SHRED-CONFIG-001`) naming entity, index field, column and
  what was found (§3.1).
- The resolution lives on `BlindIndexColumn` beside the column it came from, so the write path and
  the erasure path read one object rather than two independently computed tenants (§3.2).
- A null, blank or non-`String` tenant column value refuses the write with
  `SHRED-UNVERIFIED-WRITE`: an index no `WHERE tenantColumn = ?` can match is an index no erasure
  can destroy (§3.3).
- **The write is refused when the tenant the indexed field's data key is derived under is not the
  row's tenant column value** (§3.4). This is what closes the finding: one erasure request names one
  tenant and one subject, so the key, the ciphertext and the index are reachable together only when
  all three are under one tenant. The index is then derived under that column value.
- The erasure reads the cleared columns back inside its own transaction: still populated refuses the
  erasure with the new **`SHRED-ERASURE-004`** and rolls everything back rather than recording a
  completion that did not happen; the same subject under a different tenant value is a WARN with the
  count, never a refusal (§3.5).
- Clean break, no compatibility path: the branch is unreleased and nothing tries the old keying
  (§3.6). The residual the module cannot see - a bulk `UPDATE t SET tenant_id = ?` outside Hibernate
  - is stated in `SECURITY-NOTES.md` beside the control and surfaces in §3.5's WARN (§3.7).

Probes: `CipherProbeBlindIndexAmbientTenantTest` (6, the security review's repro promoted out of
`src/test-pending/java`), `CipherProbeBlindIndexTenantColumnTest` (5 startup shapes, including the
correct camel-case-property configuration that must still boot),
`CipherProbeBlindIndexResidualTest` (2), `CipherProbeBlindIndexTenantTest` (3, rewritten).

### Changed (S-7's startup refusal relaxed on change 4's terms)

A `@BlindIndex(of = ...)` field may declare its own `@Shredded(tenant = ...)` again. The seventh
pass refused that mapping at boot because the module could not prove, at scan time, that the
declared tenant would ever equal the value in `tenantColumn`; it is now checked per row at the
write, so the shape is allowed exactly when it is erasable. That restores the S-2 shape (one row,
two tenants, one of them indexed) and gives an application with an acting organisation distinct from
an owning one a correct way to declare it.

### Fixed (eighth pass at `fa6f477`, S-14: closing a swept region could destroy a live caller's own region)

**LOW.** `ShreddingContext.unwindTo` popped the region deque unconditionally until it found the
token it was given or ran out of deque, so a token from another frame - or one a nested entry's own
sweep had already taken away - emptied the whole deque, including the live entry region of the call
that invoked it: a well-behaved caller's own, still-open region destroyed as collateral by a close it
had nothing to do with. Now scans for the token first and pops nothing when it is absent, returning
`null`, which `closeRegion` already turns into its own refusal and `discardRegion` already treats as
a no-op. New package-private `ShreddingContext.resetForTests()` for the four `@AfterEach` blocks that
used to rely on the old, unconditional-pop behaviour of `discardRegion(-1L)`.
`CipherProbeEighthPassRegionTest`.

### Fixed (eighth pass at `fa6f477`, S-15: a raw region opened outside any entry never swept)

**LOW.** `sweepForeignRegions` compared a region's epoch against the epoch in force with `!=`, so
with no entry in force (`NO_ENTRY`) a region left behind by the deprecated `openRegion()` also
carried `NO_ENTRY` and compared equal, stopping the sweep - one node and one `HashMap` per leak,
accumulating on a pooled thread for the life of the thread, and `inReadBracket()` staying `true` on
that thread forever. Decision on S-4a: widened the predicate to `isCurrent(region, inForce)`
= `inForce != NO_ENTRY && region.epoch == inForce`, used by both the sweep and `currentRegion()`.
`CipherProbeEighthPassRegionTest`.

### Fixed (eighth pass at `fa6f477`, S-16: a ledger cap of zero or negative refused every write)

**INFO.** `shredding.write-verification.max-outstanding=0` (or negative) booted cleanly and then
refused the application's first write of any `@Shredded` entity, forever. `ShreddingStartupCheck`
now refuses `SHRED-CONFIG-001` at boot when the value is below 1, naming the property, its value and
the default. `CipherProbeLedgerCapConfigTest`.

### Fixed (eighth pass at `fa6f477`, S-17: the `BigDecimal` placeholder rendered as a megabyte)

**INFO.** The seventh pass's own prescription for S-10 - a scale "of the order of 10^6" - was
careless: `toPlainString()` at that scale is over a million characters, and a refused load is
documented to leave the marker in a detached entity that ordinary application code (a DTO round
trip, a log line, a JSON body with `WRITE_BIGDECIMAL_AS_PLAIN`) then copies around. The
unguessability the marker needs comes from the 64 random unscaled bits, not the scale. Now drawn in
the low thousands. `CipherProbePlaceholderRenderingTest`.

### Corrected (eighth pass at `fa6f477`, S-18: #27's "now reachable" claim was wrong)

**INFO.** See the correction above and in `WriteVerification.settle`'s own
javadoc: the "still outstanding at completion" branch in `beforeCompletion` remains unreachable by
construction on this code. No behaviour change; documentation only.

### Changed (eighth pass at `fa6f477`, S-19: the read-region SPI documented as internal, not application API)

**INFO.** `@apiNote` on `ShreddingContext.enterRegion`, `recordDecoded`, `drain` and
`pendingKeysFor`: this module's internal SPI, called by its own converters and listener, not
application API, subject to change without a major version. `withReadBracket` unchanged. `README.md`
gains one sentence naming the split.

### Fixed (seventh pass at `e2c2bdd`, S-11: the startup listener check covered five of eight event types)

**LOW, accepted residual (the eighth pass).** `ShreddingStartupCheck` now checks all eight event
types `ShreddingIntegrator` registers - `FLUSH`, `AUTO_FLUSH` and `POST_DELETE` were entirely
unchecked before - for both presence and the position each was registered for. What this check
cannot prove: that the listeners Hibernate itself seeded are still there when an earlier-composed
integrator replaces a group's prior contents outright before this module ever registers. Ruled an
accepted residual, not a design stop: no control of this module is disabled by it, only Hibernate's
own default behaviour, which then fails loudly. Written up in `SECURITY-NOTES.md` and in
`ShreddingStartupCheck.REGISTERED_TYPES`'s own javadoc.
`CipherProbeEarlierIntegratorWipesHibernateDefaultsTest` (renamed from
`CipherProbeSettlementListenerDisplacedTest`, which asserted the wrong outcome for a shape this
module was never going to close).

### Added (a hard cap on the write-verification ledger)

**The security review's decision on the seventh pass, accepted with a number.** Settlement discharges the ledger at
the end of every flush, so an ordinary `@Transactional` write never holds more than one flush worth
of debt; `StatelessSession` fires no flush event, so a stateless import that stays in one
transaction for its whole run keeps accumulating debts - each one a subject and a tenant - until
`beforeCompletion`, unboundedly. New property `shredding.write-verification.max-outstanding`
(default 50 000): a debt that would exceed it is refused with `SHRED-UNVERIFIED-WRITE`, naming the
property and the remedy (a transaction per chunk), rather than left to grow without bound. It
refuses; it never degrades. `CipherProbeWriteVerificationCapTest`.

### Fixed (a caught settlement refusal used to discharge debts it never checked)

**The security review's decision on the seventh pass: keep the "still outstanding at completion" refusal.**
`WriteVerification.settle` used to clear its whole ledger before it verified any of it, on the
reasoning that a refusal below throws out of the flush and aborts the transaction anyway - which
meant a caught settlement refusal (`SwallowedWriteRefusalTest`'s shape) discharged debts it had
never actually checked. A debt is now removed from the ledger only once the check that discharges it
has actually passed, one at a time within a chunk, so a chunk that throws partway through leaves
every debt it had not yet reached correctly still outstanding in the ledger's own data.
`BatchedWriteVerificationTest.a_settlement_refusal_discharges_only_the_debt_that_actually_passed`.

**Correction (S-18, the eighth pass).** The seventh-pass fix text and this entry both claimed
that change also made `beforeCompletion`'s own "still outstanding when the transaction tries to
commit" refusal reachable. It does not: `settle` still only ever returns normally after emptying
every debt it started with, or throws before returning at all, and a throw from inside `settle`
propagates straight out of the `beforeCompletion` callback, past the branch that checks the ledger
afterwards. That branch is unreachable by construction on this code, on both the
belt-throws-before-`owe` path (`SwallowedWriteRefusalTest`) and this one - three lines JaCoCo
correctly reports as uncovered. Kept as a belt for whatever settlement path replaces this one, and
deliberately not excluded from coverage.

### Changed (seventh pass at `e2c2bdd`, S-12: renamed a probe to what it tests)

**INFO.** `CipherProbeBatchedInsertCheckTest` was rewritten from S-1's batched
fail-open into S-5's startup refusal, and was left with a name for a property it no longer exercises
- the next reader would believe S-1 is covered by it. Renamed to
`CipherProbePropertyAccessSequenceTest` (what it now asserts: a property-access mapping is refused
at startup under a batching configuration); `BatchedWriteVerificationTest`'s class javadoc now names
itself as the file that carries S-1's property in the default build.

### Fixed (seventh pass at `e2c2bdd`, S-8: `closeRegion` discarded an inner region's undrained decode in silence)

**MEDIUM.** `unwindTo` popped every region above the one being closed without ever looking at its
pending map, so a decrypted `@Shredded` value an inner region's own close never drained - the `C-32`
`StackOverflowError` window, or a nested `withReadBracket` body that returned normally without
closing the region it opened - was dropped in silence on the outer call's *normal* return path, and
the outer call returned its result: exactly the accounting `SHRED-READ-UNVERIFIED` exists to make
loud, silently skipped for every region but the one actually being closed. `unwindTo` now takes a
`refuseUndrainedIntermediates` flag: `closeRegion` passes `true` and, once every region down to its
own token has been popped and every epoch restored (so a retry still starts clean), refuses with the
same message shape as its own region's unpaid-debt check if any intermediate region it passed
through still held one; `discardRegion` passes `false` and keeps dropping unchecked, because on that
path the original exception already in flight is the failure worth reporting. Rebuilt on top of
the build's entry-epoch mechanism (`95efeac`/`ff294bc`) rather than the deprecated `openRegion()`.

### Fixed (seventh pass at `e2c2bdd`, S-7: a blind index derived under a declared tenant survives that tenant's erasure)

**A read region left on a pooled thread by a call that never closed it could serve the next call's
decrypts.** `recordDecoded`, `drain`, `pendingKeysFor` and `closeRegion` all asked one question -
"is this thread's region deque non-empty" - so a region a returned call left behind was the same
object at `stack.peek()` as one legitimately open. The sixth pass closed the data-loss half (a stale
value is never installed over a fresh one); this closes the rest. Design addendum 2
weighs three shapes; the security review approved option (b) with six changes,
each marked "applied §2.x" there.

- **A decrypt is served only inside a region opened by the bracketed entry that is reading.** The
  repository proxy and `withReadBracket` - the only two entries - stamp the thread with a fresh
  **entry epoch**; a region records the epoch in force when it is constructed; every region access
  compares the two **for equality**, never for age, so a leftover region carrying a *newer* epoch is
  refused as surely as an older one, and no counter accumulates a permission an unwind can miss.
- **`ShreddingContext.openRegion()` is deprecated and stamps a distinguished "no entry" epoch**, so a
  region opened outside an entry can never serve a decrypt - neither on a thread that never entered
  nor from inside a repository call, which is the case that mattered: a user `@PostLoad` method or an
  `@EntityListeners` bean opening one would otherwise take every remaining decode of that call.
  `ShreddingContext.enterRegion()` is added for a framework integration that owns a call boundary,
  and `closeRegion` refuses a region that no entry opened.
- **Entering sweeps residue, loudly and conditionally.** Regions on top whose epoch is not the one in
  force at entry are discarded with a `WARN` naming the count and the first `entity.field`; a
  region whose epoch matches - the caller's own, in a nested repository call - is never touched.
- **`REGIONS` and the epoch are plain `ThreadLocal`s** and are documented as never inheritable: an
  inherited epoch would match an inherited region and authorise the `@Async` case that is refused
  for free today.

`SECURITY-NOTES.md` states the one remaining residual in the words the security review asked for: a read that
opens no region of its own, on a thread where an `Error` skipped exactly the frame that restores the
epoch, before the next entry - **a leaked region costs a refusal, never a value.** Probes: S-4's two
promoted from `src/test-pending` and green, six in `CipherProbeRegionEpochTest`, two on the real read
path in `CipherProbeReadScopeTest`, and `CipherProbeBracketUnwindTest` unchanged at 0/200.

### Fixed (seventh pass at `e2c2bdd`, S-7: a blind index derived under a declared tenant survives that tenant's erasure)

**HIGH.** `ShreddedModel.scan` refuses startup (`SHRED-CONFIG-001`) when a `@BlindIndex(of = ...)`
names a `@Shredded` field that declares its own `tenant` expression. `writeBlindIndexes` derives the
index under that field's declared tenant, but `JdbcErasureStore.clearBlindIndexes` matches an
erasure against the row's own `tenantColumn` value - not any field's declared tenant expression - so
when the two differ the index survives a completed, successful erasure: an HMAC of the erased
plaintext, a stable correlator and, for a low-entropy value, an offline guessing oracle. The module
cannot know a tenant column's runtime value at scan time, so an index it cannot prove reachable by
the erasure is refused rather than written. `BlindIndex`'s javadoc and `SECURITY-NOTES.md` state the
contract: the value in `tenantColumn` must be the tenant the index was derived under, or the erasure
cannot find it.

### Fixed (seventh pass at `e2c2bdd`, S-10: `Placeholders.LOCAL_DATE` was exactly `LocalDate.MIN`, and is now compared by value)

**LOW.** S-3 widened `Placeholders.isPlaceholder` from reference identity to value equality; `STRING`
and `BYTES` are 128 random bits per JVM, so no application value collides, but `LOCAL_DATE` was
exactly `LocalDate.MIN` - an ordinary application value for an open-ended validity range - so storing
it in a `@Shredded LocalDate` field refused every insert and update of that entity, permanently, with
a message calling the application's own data this module's marker. `LOCAL_DATE` and `BIG_DECIMAL` are
now drawn from `SecureRandom` at class initialisation (a date a few thousand days after
`LocalDate.MIN`, a `BigDecimal` at a scale of the order of 10^6), as unguessable as `STRING` and
`BYTES` already were; the class javadoc no longer claims a reference-identity property the value-
compared code does not have. `Placeholders.describe()` now renders a fixed literal instead of the
real per-JVM `STRING` token, so a message or log line that names "this module's read placeholder"
does not also hand out the real, live marker to whoever can read it.

### Fixed (seventh pass at `e2c2bdd`, S-9: a non-integral numeric id collided in the settlement ledger)

**LOW.** `WriteVerification.normalise` mapped every `Number` through `longValue()`, so a `BigDecimal`,
`Double` or `Float` identifier truncated: `1` and `1.5` normalised to the same ledger key, and the
second row's write debt silently replaced the first's - S-1's property, reopened by an identifier
type. Every numeric id now goes through the same exact `BigDecimal` canonicalisation, never a
truncation, matching regardless of which concrete `Number` subtype the bind side and the JDBC
read-back side each use for the same value.

### Fixed (seventh pass at `e2c2bdd`, S-11: the post-boot self-check verified five of seven registered event types, and one position)

**LOW.** `ShreddingStartupCheck.refuseIfVerifierNotRegisteredFirst` checked presence on `PRE_INSERT`,
`PRE_UPDATE`, `POST_INSERT`, `POST_UPDATE` and first-position on `POST_LOAD` only; `FLUSH`,
`AUTO_FLUSH` and `POST_DELETE` - S-1's settlement machinery - were not checked at all, and presence
was checked instead of the position the integrator actually registered for. The self-check now
iterates the same eight event types `ShreddingIntegrator` registers and asserts, per type, the
position it registered for - first for the three prepended, last for the five appended - from one
table, so a type added to the integrator cannot silently go unchecked here.

### Fixed (sixth pass at `05ca185`, S-1: the write-side verification under a JDBC batch size)

**A standard Hibernate performance property switched the insert-side header check off, and personal
data then committed in the clear.** With `hibernate.jdbc.batch_size` set and an id strategy that
batches, the `INSERT` is still in the JDBC batch when `onPostInsert` fires:
`readStoredShreddedColumns` found no row, returned `null`, and `refuseIfStoredHeadersDisagree`
returned without checking anything - for every row of every batch, with no warning. The security review's probe
committed three rows of plaintext personal data. The update side was weak the same way: the `UPDATE`
was also still in the batch, so the check read the pre-update row and passed vacuously.

The design addendum states the property and weighs four options.
**Option (a), with the fail-open closed**, is what shipped, and the second half is the point:

- **A bind incurs a verification debt, it no longer performs a check.** Each written row records
  `(entity, table, id column, id, expected tenant/subject/rowId)` on the session's ledger.
- **Debts are settled where the batch has demonstrably executed and the transaction has not yet
  committed:** the end of every flush and auto-flush (appended `FLUSH`/`AUTO_FLUSH` listeners, after
  `ActionQueue.executeActions` has run `executeBatch()`), and `beforeCompletion`, which runs after
  Hibernate's own commit-time flush and covers `StatelessSession`, which fires no flush event at all.
  One `SELECT` with an `IN` list per entity per flush, not one statement per row.
- **Settlement is total or the transaction aborts.** A debt whose row cannot be read back, a stored
  header that disagrees, and any debt still outstanding at completion are all the new
  **`SHRED-UNVERIFIED-WRITE`**, thrown before the commit. A write with no transaction has no
  settlement anchor and is refused at bind time. A configuration knob can no longer remove this
  control; it can only make it refuse.
- The per-row post-hoc check stays, as the belt and as early failure.
- A row deleted in the same transaction discharges its own debt (`POST_DELETE`): inside one flush
  Hibernate executes insertions before deletions.

Seventeen probes in `BatchedWriteVerificationTest`, one per path Hibernate offers to write a row,
run RED before the hook: batched `saveAll`, `persist` in a loop, batched `UPDATE`, `merge` of a new
entity, cascade insert, a `@BatchSize` collection, `SEQUENCE`/`IDENTITY`/`UUID`/assigned ids, two
entities in one flush, an explicit flush, `StatelessSession.insertMultiple`, a write with no
transaction, insert-then-delete in one transaction, flush-then-rollback, a row that cannot be read
back, an in-transaction row swap, and a bulk JPQL update. Coverage is measured by recording the SQL
on the application's own `DataSource`, not asserted from the mechanism. Framework matrix rows 24-27.

**Also fixed, found by those probes:** every `StatelessSession` **write** of a `@Shredded` entity
threw `ClassCastException` out of the write path, because the listener cast the session to
`EventSource` and `StatelessSessionImpl` is not one. The read path had `StatelessSession` tests;
nothing wrote through one.

### Fixed (sixth pass corrections at `75af7ea`)

the security review's `## Sixth pass (75af7ea)` review found one HIGH design stop (S-1, closed above by the build) and
five corrections, S-2 to S-6, closed here. Four are fully closed; S-4 is closed for the data-loss half
(a stale decode is never served) with one narrower residual left open: an ownerless region left
behind by an undisciplined direct `openRegion()` call is, on the stack, indistinguishable from one
legitimately open for the call in progress, so the missing-refusal half costs a refusal that should
have fired rather than a leak.

- **S-2 (MEDIUM).** A second `@Shredded` field's declared tenant was silently ignored: `scopeFor` and
  `onPostLoad` took the tenant from the entity's *first* shredded field and applied it to every field,
  so a field whose tenant differed from the others was encrypted into the wrong tenant's erasure
  scope and survived that tenant's own erasure. `ShreddingContext.Scope` now carries a per-field
  tenant map (`Scope.tenantFor(String)`), resolved once per write from each field's own declared
  expression; every write and read-path use of "the tenant" - the converter, blind-index derivation,
  the `IDENTITY` rebind, `refuseIfSubjectMoved`, `refuseIfStoredHeadersDisagree`, `onPostLoad` - goes
  through it instead of the first field's value. This closes as full
  per-field support rather than the review's suggested startup refusal.
- **S-3 (MEDIUM).** A value-equal but reference-distinct copy of the read placeholder - what a DTO
  round trip, `new String(...)`, `trim()` or a defensive `clone()` produces from a refused, detached
  load - defeated both write-back checks and overwrote the live ciphertext with the marker's own
  rendering. `Placeholders.isPlaceholder` now matches by value (`String.equals`, `Arrays.equals` for
  `byte[]`, `equals` for the date and the decimal) as well as by reference identity.
  `FrameworkMatrixTest.a_placeholder_is_never_re_encrypted`'s three assertions are inverted to match.
- **S-4 (LOW).** `ShreddingContext.drain` took `entries.remove(0)` - the *oldest* pending decode under
  a key - so an ownerless region left on the deque by an undisciplined direct call to the public
  `openRegion()` could serve a stale, previously-decrypted value of the same row instead of the one
  the current read just took out of the column. `drain` now takes the most recent entry. The
  `Pending.ownerToken` field and its comparison in `drain` are removed rather than "fixed": they were
  unreachable by construction (a `Pending` is always read back from the very `Region` object it was
  recorded into), and making the check real would need a second piece of call-scoped state - a new
  mechanism, not a correction (S-4).
- **S-5 (LOW).** An `@Access(AccessType.PROPERTY)` `@Shredded` mapping started with no converter on
  the column at all - Hibernate ignores field-level mapping annotations, the `@Convert` among them,
  under property access - caught only on the first write by the post-hoc header check, with a message
  naming neither the entity nor the field. `ShreddedModel.scan` now adds the forward direction of the
  C-19 reverse check: for every field-level `@Shredded`, the metamodel attribute of that name must
  resolve to that field's own declared `ShreddedConverter`, refused at startup by name otherwise.
- **S-6 (LOW).** `ShreddingAutoConfiguration.shreddingHibernateCustomizer` installed the integrator
  with an unconditional `properties.put(JpaSettings.INTEGRATOR_PROVIDER, ...)`, which silently
  discarded any `IntegratorProvider` a library or the application had already installed - its own
  auditing or security integrator included. The customizer now composes with whatever provider is
  already in the map, appending this module's integrator last so its `POST_LOAD` listener remains the
  one Hibernate calls first. `ShreddingStartupCheck` now also verifies, once the `SessionFactory` is
  actually built, that this module's listener is registered on every event it needs and is first on
  `POST_LOAD`, refusing startup and naming the listener that displaced it otherwise.

Probes moved from `src/test-pending/java` to `src/test/java`: `CipherProbeTenantExpressionTest`,
`CipherProbePlaceholderCopyTest`, `CipherProbePropertyAccessTest`, `CipherProbeSecondIntegratorTest`,
and `CipherProbeBatchedInsertCheckTest` (rewritten as a startup-refusal assertion; S-5
makes its original `@Access(PROPERTY)` fixture unstartable, so the batching scenario it demonstrated
is no longer reachable through that fixture at all). `CipherProbeRegionResidueTest` stays pending: one
of its two probe methods is the S-4 residual.

### Changed (read-path redesign, sixth pass at `faaafff`)

The security review's design review (2026-09-09)
returned APPROVED WITH CHANGES: fourteen mandatory items and decisions D1-D6. All fourteen are applied
and indexed in the design file; none is disputed. This closes the fifth-pass design stop - C-33,
C-34, C-35, C-39, C-40, C-41 - as one change rather than six patches.

**The converter no longer returns plaintext.** Five review passes found the same shape of defect in
five different places: the read path treated *the presence of thread-local state* as *permission to
return plaintext*, and every one of them broke the moment that state outlived its owner.
`ShreddedConverter.convertToEntityAttribute` now decrypts, files what it decrypted in the open read
region, and returns a placeholder; `ShreddingEventListener.onPostLoad` - the one hook that knows the
row - verifies and installs. *Ambient state may accuse. It may never authorise.*

#### Breaking

- **Stored format is `SH1` v2** and a v1 header is **refused**, not read (`SHRED-FORMAT-001`). v1
  bound tenant and subject but no row, so two rows of the same subject held interchangeable
  ciphertexts (C-34); a dual-format reader would let anyone holding `UPDATE` strip the row binding by
  writing a v1 blob. No migration path is offered: the branch is unreleased.
- `FieldCipher.encrypt` and `Aad.forValue` take a `RowId`. `Aad.LAYOUT` is `2`, so a v1 AAD and a v2
  AAD differ even when every other component is identical.
- `ShreddingContext.Scope` carries the `RowId`. `ShreddingContext.withRead(...)`,
  `pushReadScope`/`popReadScope`/`currentReadScope` and `clearAll()` are **removed**: a
  caller-supplied read scope vouched for a projection with an ambient identity, which is exactly the
  authority this design removes, and `clearAll()` dropped read regions belonging to still-open
  brackets (C-33). `pushReadBracket`/`popReadBracket` become `openRegion`/`closeRegion`, which take
  and check an owner token; `withReadBracket(...)` keeps its name and its contract.
- A projection now yields `SHRED-READ-UNVERIFIED` when it runs inside a region and
  `SHRED-READ-UNSCOPED` when it does not, in both cases with nothing decrypted returned. There is no
  supported way to read a `@Shredded` column outside a managed entity load.
- New startup refusals (`SHRED-CONFIG-001`): optimistic locking `ALL`/`DIRTY`, select-before-update,
  a `@Shredded` column in the natural id, and a **non-basic identifier** including a single-column
  `@EmbeddedId`. Each is read off the runtime persister, not the annotation.
- New error codes: `SHRED-ROW-MISMATCH`, `SHRED-PLACEHOLDER-001`.
- A `@Shredded` field must never participate in `equals`/`hashCode`.

#### Fixed

- **C-34 (HIGH)** - a ciphertext copied between two rows of the *same* subject decrypted and was
  displayed as the second row's own value, with no error anywhere: the header and the AAD bound
  tenant and subject and no row identity. Fixed: `RowId` - the identifier's canonical, type-tagged
  column encoding, never `Object.toString()`, which cannot tell a `Long 1` from a `String "1"` -
  goes into both. A copy is `SHRED-ROW-MISMATCH`; relabelling the header to claim the other row
  fails GCM authentication instead. Probe `CipherProbeFifthPassTest.probe_a_ciphertext_swapped_
  between_two_rows_of_one_subject_is_detected` now reports `REFUSED SHRED-ROW-MISMATCH` where it
  reported `RETURNED [ROW-A-VALUE, ROW-A-VALUE]`. Under `@GeneratedValue(IDENTITY)` the identifier
  does not exist at bind time, so the insert binds a random 128-bit *unbound intermediate* under a
  tag no real identifier can equal and `onPostInsert` rebinds it in one `UPDATE`, same transaction,
  over raw JDBC; a rebind failure aborts the transaction (finding items 5, 6).
- **C-33 (HIGH)** - any transaction that wrote a shredded entity and committed inside an open read
  bracket erased that bracket's debt, because `registerTransactionBoundaryClear` registered
  `clearAll()`, which dropped the whole read-frame stack. Fixed: the callback is
  `clearWriteScopesOwnedBy(session)` and may not touch a region. P1 reports `REFUSED
  SHRED-READ-UNVERIFIED` where it reported `RETURNED [P1-CLEARALL-SECRET]`.
- **C-39, C-40 (HIGH)** - a read frame or a read scope leaked onto a pooled thread by a
  `StackOverflowError` turned a decrypt that should have been refused into one that returned the
  row. Fixed structurally: the converter returns no plaintext, so a leaked region cannot produce a
  value; and a frame entry carries the token of the region that recorded it, so a drain happens only
  under the region in force and foreign-token residue is discarded with the load refused (finding
  item 4, which also answers D6). The read-scope stack that C-40 attacked no longer exists.
- **C-41 (HIGH)** - `ShreddingContext.require` ignored the entity name, so a residual write scope
  pushed for `A` was handed to a bind of `B`; and `refuseIfSubjectMoved` ran on `onPreUpdate` only,
  never on insert, and on update only when the `Pre` hook pushed a fresh scope - vacuous on every
  path where residue was consumable. Fixed on four fronts (finding items 13, 14): `require` compares
  the entity name; a write scope may not nest, so residue from a bind whose `Post` hook never ran is
  dropped rather than consumed; `refuseIfSubjectMoved` runs on every update; and a post-hoc header
  check after every insert and every update re-reads what was written and refuses a row not bound to
  the `(tenant, subject, rowId)` it was written under, inside the same flush and before the commit.
- **C-35 (LOW)** - `onPostLoad` issued one `SELECT ... WHERE id = ?` per loaded row of every shredded
  entity, an unbounded amplification a caller controlling the page size controlled the multiplier of.
  Fixed: `onPostLoad` issues no SQL at all - which fields owe a decode is decided by reading the
  placeholder off the entity. P3 reports `200 rows, 0 per-row re-reads` where it reported
  `200 rows, 401 statements`.
- **The `null` placeholder data-loss hole** (finding item 2, found in review of this design before any
  code): for `LocalDate`, `BigDecimal` and JSON columns the placeholder would have been `null`, so an
  entity whose install never ran held `null` in the field *and* the loaded state and the next
  ordinary UPDATE wrote `NULL` over a live ciphertext, unseen. Fixed: a non-null per-type constant
  compared by reference identity, carrying 128 bits drawn once per JVM run, ASCII and log-safe;
  writing one back is `SHRED-PLACEHOLDER-001`, checked in the converter and on the state array in the
  `Pre*` listeners before the blind indexes are written.
- **`POST_LOAD` was appended, not prepended** (finding item 8): Hibernate's own
  `PostLoadEventListenerStandardImpl` is what invokes a user's `@PostLoad` methods and
  `@EntityListeners` beans, so every one of those callbacks was handed the placeholder. Fixed:
  prepended. `POST_INSERT`/`POST_UPDATE` stay appended so the post-hoc check sees what reached the
  database. Verified RED against the appended listener before the fix was kept.
- **A refused row could be retried out of the first-level cache** with the value intact. Fixed:
  verification runs before either install (finding item 9), so a refused instance holds placeholders;
  the C-27 eviction stays as the second line.

#### Tests

- `FrameworkMatrixTest` (13) - one test per path Hibernate offers to reach a `@Shredded` column:
  entity load, `@PostLoad` ordering, the placeholder write-back on the types with no sentinel, a
  forged placeholder in the column, `merge`, `refresh`, `StatelessSession`, a `Stream` drained after
  the call, `equals`/`hashCode`, and the `IDENTITY` rebind window including a batched `saveAll` and a
  rollback.
- `LoadedStateHostileMappingsTest` (3), `RowIdTest` (7), `EncryptedValueV2Test` (4),
  `FieldCipherRowBindingTest` (4).
- All six pending fifth-pass probes moved from `src/test-pending/java` into `src/test/java`, green.
  `CipherProbeBracketUnwindTest` is rewritten rather than deleted: its read-scope probe exercised
  `withRead`, which is removed, and its "no frame survives a `StackOverflowError`" assertion is a
  property no arrangement of `finally` can hold (C-32 proved it). It now asserts the two properties
  this design does hold - a decode filed in a region an `Error` unwound past is never drained by a
  later region (0/200), and a leaked region yields no plaintext to anybody - and keeps the original,
  stronger assertion for the write scope, which is real authority and stays at 0/200.

### Fixed (fifth pass at `2f72449`)

The security review's fifth pass (`2f72449`), 2026-09-09. Two of the fix's own two LOW-severity corrections closed; the four HIGH/MEDIUM
findings (C-33/C-34/C-39/C-40/C-41) and the one LOW (C-35) in that pass are one design stop -
`ShreddingContext`'s thread-local ownership and clearing rules - out of scope for this pass and left
for the build's design.

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
  `probe_a_moved_ciphertext_in_a_composite_id_entity_is_never_displayed` - rewritten, per the security review's
  fix text, to build its own context in the shape of `CipherProbeScanDepthTest` rather than share a
  class-level `@SpringBootTest` context that can no longer come up). Reclassified to
  this finding and closed.

### Fixed (fourth pass at `0ba0f6f`)

The security review's fourth pass (`0ba0f6f`), 2026-09-09. Two HIGH, one MEDIUM, three LOW, all closed; one INFO documented.

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
  check. The security review's fix text also asked for the transaction to be marked rollback-only; that half was
  tried and reverted, on evidence. New probe:
  `probe_a_refused_row_is_returned_on_the_retry_from_the_persistence_context`.
- **C-29 (MEDIUM)** - the reverse metamodel scan (`refuseUnmodelledShreddedConverters`) inspected an
  entity persister's own top-level `BasicValuedModelPart` attributes only; a `@Shredded` field
  declared inside an `@Embeddable` or an `@ElementCollection` of embeddables - invisible to the
  forward field scan too - was fully encrypted on write and never checked on read at all. The scan
  now recurses into `EmbeddableValuedModelPart` and a `PluralAttributeMapping`'s element descriptor,
  refusing startup on any nested `ShreddedConverter`, naming its dotted path. New probes:
  `probe_a_shredded_field_inside_an_embeddable` (the security review's own), and the maintainers' mandated companion
  `probe_a_shredded_field_inside_an_element_collection_of_embeddables` (`CipherProbeEmbeddableScanTest`).
- **C-30 (LOW)** - `probe_a_second_row_in_the_same_result_set_is_never_verified` asserted only
  `isNotBlank()` on a two-shredded-field fixture (`Doc`), which let the wrong field's collision
  throw first and never actually exercised the moved field. Rewritten on `Widget` (one shredded
  field) asserting the specific `SHRED-SUBJECT-MISMATCH` code (`CipherProbeReadScopeTest`).
- **C-31 (LOW)** - `probe_an_in_place_mutation_of_an_immutable_byte_array_is_persisted` renamed to
  `..._is_silently_discarded`: the assertion always checked the mutation is lost (correct, per the
  third pass's C-21 decision), the name promised the opposite (`CipherProbeMatrixTest`).
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
  converts to Apache-2.0 two years after each version's release. Decision by the maintainer,
  2026-09-08: the fair-source core plus paid Pro model (the Sentry / GitButler pattern) is what lets
  the core stay genuinely free to use and redistribute while the module still funds its own upkeep -
  FSL is not OSI open source, so every public text says "fair source" or "source available", never
  "open source". `LICENSE` and `NOTICE`
  added at the repo root, `pom.xml` `<licenses>` updated, and `LICENSE`/`NOTICE` are now embedded
  in `gdpr-shredding-core` and `gdpr-shredding-spring-boot-starter`'s jars under `META-INF/`
  (same fix as agent-guard's M7). The reactor's own modules are excluded from the third-party
  licence scan by `groupId` (`excludedGroups`), not by licence name, since
  `com.housedevinci:gdpr-shredding-core` no longer matches the third-party allowlist.

### Fixed (third pass at `8095d2c`)

The security review's third pass (`8095d2c`), 2026-09-09. Four HIGH, three MEDIUM, two LOW, all closed.

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
  than one `EntityManagerFactory` bean is present in the context, as defence in depth; that half
  ships without its own dedicated integration probe (C-20).
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
  mutation persist would mean deep-copying the array again, reopening CIPHER-16).
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

The security review's re-verification (`96713f9`), 2026-09-09. Three HIGH, three MEDIUM, four LOW, all closed.

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
  belt-and-braces for every managed entity load. The `PreLoadEventListener` shape offered as
  the first alternative does not work in this Hibernate version, on bytecode evidence, and a
  `RepositoryFactoryCustomizer` bean - the documented
  Spring Data extension point for this - was replaced with a `BeanPostProcessor` after it did not
  reliably reach every `@EnableJpaRepositories` factory.
- **CIPHER-12 (HIGH)** - `onPostLoad` `return`ed on any `RuntimeException` from resolving the row's
  subject, including on a row carrying an already-decrypted shredded value - exactly the row an
  attacker who nulled the subject-source column wanted through. An unresolvable subject on a row
  that decoded at least one shredded field is now a refusal (`SHRED-SUBJECT-UNRESOLVED`) with a
  WARN naming the entity, never plaintext. A row with no decoded shredded value still loads despite
  an unresolvable subject, matching the decision's own carve-out.
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
- **CIPHER-16 (MEDIUM)** - `ShreddedBytesConverter` refused its own entity's first
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

The security review's first pass, 2026-09-08. Two HIGH, eight
MEDIUM, ten LOW/INFO, all closed.

- **CIPHER-01 (HIGH)** - a ciphertext moved into another subject's or another
  tenant's row decrypted and displayed, and survived the row owner's own erasure, because the read
  path trusted the blob's own header as the row's identity. `ShreddedConverter` now records what
  each field's header actually said; `ShreddingEventListener.onPostLoad` compares it against the
  row's true, resolved subject and tenant once the entity is hydrated and refuses
  `SHRED-SUBJECT-MISMATCH` before the entity is returned to any caller. The write path gets the
  matching half: `onPreUpdate` fetches the row's current header with a second query and refuses
  `SHRED-SUBJECT-IMMUTABLE` before re-encrypting. The bounded per-thread map this replaced is
  deleted. The read-path check cannot fire "before the key store is
  touched" the way the literal fix text asked, and the "skip when not dirty"
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
