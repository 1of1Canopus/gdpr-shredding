# Security review — `feat/shredding-core`

Reviewer: Cipher. Repository `1of1Canopus/gdpr-shredding`, branch `feat/shredding-core`,
HEAD `e9fb823`, draft PR #1 by Thor. Contract: `SPEC.md` § *Cipher spec review (2026-09-08)* —
19 controls, 19 named probes. Rule in force since 2026-09-07: **no allowance** — every HIGH,
MEDIUM, LOW and INFO below is fixed before merge.

---

## 2026-09-08 — first PR review

### Verdict

**NOT MERGEABLE.** Two HIGH findings, both reproduced with a probe that fails on `e9fb823`.

`CIPHER-01` breaks the product's central claim: the read path takes tenant and subject from the
blob header and nothing compares that header with the row the blob is sitting in, so a ciphertext
copied into another subject's — or another tenant's — row decrypts and is displayed, and survives
the row owner's erasure. `CIPHER-03` is a false proof: a first write racing an erasure commits a
live `ACTIVE` data key *after* the tombstone commits, and the erasure record for that subject says
`COMPLETE` with the key still there.

Everything else in the module is of a high standard. The crypto is correct, the chain is module B's
verbatim, the format is strict, the supply chain is pinned, and the nanosecond/`timestamptz` bug was
diagnosed at the right layer with the right guard. The two HIGHs are boundary omissions, not design
failures, and both fixes are small.

### Numbers

| | Value | Source |
|---|---|---|
| `./mvnw -B clean verify` | exit 0, Docker up | `verify` on this machine |
| Tests, core | 70 run, 0 failed, 0 errored, 0 skipped | `gdpr-shredding-core/target/surefire-reports` |
| Tests, starter | 14 run, 0 / 0 / 0 | `.../spring-boot-starter/target/surefire-reports` |
| Tests, sample | 10 run, 0 / 0 / 0 | `.../sample/target/surefire-reports` |
| **Total** | **94, nothing skipped, nothing `@Disabled`** | |
| Coverage LINE (core) | **937 / 1112 = 84.3 %** (gate 80 %) | `gdpr-shredding-core/target/site/jacoco/jacoco.csv` |
| Coverage INSTRUCTION (core) | 4615 / 5632 = 81.9 % | same |
| Coverage BRANCH (core) | 231 / 402 = 57.5 % | same |
| Coverage METHOD (core) | 187 / 223 = 83.9 % | same |
| Coverage COMPLEXITY (core) | 261 / 424 = 61.6 % | same |
| Coverage, starter and sample | **not measured, no gate** | no `jacoco.csv` produced — finding L2 |
| Probes named in the spec | 19 | `SPEC.md` |
| Probes present, exact names, green | **19 / 19** | `diff` of the two sorted name lists is empty |
| Probes that test a weaker property than named | 3 (M8, L8, L9) | below |
| New probes written by this review, all RED on `e9fb823` | **9** | below |

Thor's numbers in `STATUS.md` (923/1107 line, 83.4 %) are one commit stale; they are not wrong,
they were taken before `e9fb823`. Recomputed above from the CSV of this build.

### The 19 probes, judged

All nineteen exist, are named exactly as the spec names them, and are green. Sixteen test the
property I meant. Three do not:

- **`probe_tenant_b_decrypts_tenant_a_value_for_the_same_subject_id` — weaker (M8).** I removed
  `tenant` from `Aad.forValue` and left it in `Aad.forWrap`; the probe **stayed green**. It only
  exercises the wrap AAD (relabelling the blob makes `MasterKey.unwrap` fail), never the value AAD
  that control 2 requires the tenant to be in.
- **`probe_master_key_appears_in_actuator_env` — weaker (L8).** It calls the `SanitizingFunction`
  bean directly. It never asserts that Boot applies that function to `/env` and `/configprops`,
  which is the property the name claims.
- **`probe_second_level_cache_serves_plaintext_after_erasure` — weaker (L9).** It asserts the
  startup refusal, which is the right control, but it never shows a cache serving plaintext, and
  the refusal it tests is blind to `jakarta.persistence.sharedCache.mode=ALL` and to the query
  cache (M7).

Two more are honest but narrower than their name suggests, and I accept both:
`probe_ciphertext_moved_between_rows_still_decrypts` only moves a blob between *fields* (the
between-*subjects* case is CIPHER-01, which it cannot catch because `FieldCipher.decrypt` has no
subject parameter to be wrong), and `probe_concurrent_write_encrypts_under_a_destroying_key` only
covers the race when a key row already exists (the first-mint race is CIPHER-03).

### RED evidence I produced myself

Thor demonstrated RED for six by removing the control. I did the same for eight others, in a scratch
copy of `e9fb823`, one control at a time, reverting between each. Every one of these went red:

| # | Control removed | Probe | Result |
|---|---|---|---|
| R2 | `SimpleEvaluationContext` → `StandardEvaluationContext` | `probe_spel_expression_reaches_a_bean_or_a_static_type` | RED |
| R3 | actuator sanitiser matches nothing | `probe_master_key_appears_in_actuator_env` | RED |
| R4 | a failed hook no longer downgrades the outcome | `probe_a_failed_post_erasure_hook_reports_complete` | RED |
| R5 | verifier reports `INTACT` for unkeyed and for a missing anchor | `probe_an_unkeyed_or_unanchored_erasure_chain_reports_intact` | RED |
| R6 | `refuseSecondLevelCache` removed | `probe_second_level_cache_serves_plaintext_after_erasure` | RED |
| R7 | erasure no longer nulls the blind-index columns | `probe_blind_index_still_matches_the_erased_subject` | RED |
| R8 | key destruction and the record split into two transactions | `probe_crash_between_key_destruction_and_the_erasure_record` | RED |
| R1 | `tenant` removed from `Aad.forValue` | `probe_tenant_b_decrypts_tenant_a_value_for_the_same_subject_id` | **stayed GREEN — finding M8** |

---

## Findings

Nine of the fourteen code findings ship with a probe that fails on `e9fb823`. The probe name is the
one to add to the test sources; where I give no probe I say so and why.

### HIGH

#### CIPHER-01 — a blob moved into another subject's or another tenant's row still decrypts

*Where.* `FieldCipher.decrypt(String entity, String field, byte[] stored, ErasedValuePolicy)` —
`gdpr-shredding-core/.../application/FieldCipher.java:119`. It has **no tenant and no subject
parameter**. Tenant and subject are read out of the blob header (`EncryptedValue.decode`) and then
used both to look up the key and to build the AAD, so the AAD is always self-consistent with the
blob and can never disagree with it. `ShreddedConverter.convertToEntityAttribute` passes only the
column bytes, because a Hibernate `AttributeConverter` read path is handed nothing else.

*Repro.* Encrypt `alice@x.com` for `(tenant-a, s-alice, Customer.email)`. Copy those bytes verbatim
into `s-bob`'s row. `cipher.decrypt("Customer", "email", aliceBlob, SENTINEL)` returns
`alice@x.com`. The same holds across tenants: tenant A's blob sitting in a tenant B row reads back
as tenant A's plaintext.

*Why it is HIGH.* Control 2 states that the AAD "is the only thing that stops a ciphertext being
moved between rows, fields, subjects or tenants". It stops entity and field. It does not stop
subject or tenant, because those travel with the blob. Consequences, in order of seriousness: a row
displays another data subject's personal data; erasing the row's own subject leaves that row
readable, so the erasure claim is false for exactly the row an auditor would check; and tenant
isolation, which control 15 makes mandatory, is a display-level leak away from a botched migration,
a copy-paste in a support tool, or any bug that duplicates an entity's byte array.

*Probes (RED on `e9fb823`).*
`probe_a_blob_moved_into_another_subjects_row_still_decrypts`,
`probe_a_blob_moved_into_another_tenants_row_still_decrypts`.

*Fix.* The read path must be bracketed the way the write path is, and the header must be checked
against the row rather than trusted as the row.
1. `ShreddingEventListener` gains a `PreLoadEventListener` (or resolves the subject in `onPostLoad`
   before the converters' values are handed out — see the note under the ruling) that pushes a
   `ShreddingContext.Scope` for the row being hydrated, popped in `onPostLoad`.
2. `FieldCipher.decrypt` takes `TenantId expectedTenant, SubjectId expectedSubject` and refuses
   with a new `ErrorCodes.SUBJECT_MISMATCH = "SHRED-SUBJECT-MISMATCH"` when the decoded header
   disagrees, *before* it touches the key store.
3. Keep the existing behaviour for a read with no scope: refuse `SHRED-CONTEXT-001` rather than
   fall back to the header.
4. Extend `probe_ciphertext_moved_between_rows_still_decrypts` with the between-subjects and
   between-tenants cases so the weaker version cannot come back.

#### CIPHER-03 — a write racing the first key mint survives the tombstone

*Where.* `JdbcKeyProvider.mint` — `.../adapter/jdbc/JdbcKeyProvider.java:156` —
`SELECT 1 FROM shredding_erased_subject WHERE tenant = ? AND subject = ? FOR SHARE`, and
`JdbcErasureStore.erase` — `.../adapter/jdbc/JdbcErasureStore.java:68`.

*Repro.* Under READ COMMITTED, `FOR SHARE` on a row that does not exist yet locks nothing. Order:

1. Writer W begins, `currentForWrite` takes `FOR UPDATE` on the subject's key rows — there are
   none, so it locks nothing — then `mint` runs the tombstone `SELECT … FOR SHARE`, which finds
   nothing and locks nothing. W has not committed.
2. Erasure E begins, takes `FOR UPDATE` on the same (still empty) key rows, sees no versions and no
   tombstone, deletes 0 key rows, inserts the tombstone, appends the erasure record, commits.
   `ErasureResult.complete()` is `true`.
3. W commits its `INSERT INTO shredding_data_key … 'ACTIVE'`.

The subject now has a live `ACTIVE` v1 key and the erasure log says the erasure is complete.
`keys.forRead(tenant, subject, 1)` is present after a `COMPLETE` erasure. Nothing in the trail
records it, and the next read of that subject's rows returns plaintext.

*Why it is HIGH.* This is the same class of bug the tombstone was introduced to close (QUESTIONS
#3), moved one step earlier: the tombstone only defends a subject that already had a key row when
the erasure started. A subject whose first write is in flight is undefended, and the failure mode is
a *false proof*, which control 6 says must be impossible.

*Probe (RED).* `probe_a_write_racing_the_first_key_mint_survives_the_tombstone`.

*Fix.* Give the (tenant, subject) pair a lock that exists whether or not any row does. Both paths
take it first, in the same transaction:

```
SELECT pg_advisory_xact_lock(hashtextextended(? || '|' || ?, 6072873668427846209))
```

taken at the top of `JdbcKeyProvider.currentForWrite`, `JdbcKeyProvider.rotate` and
`JdbcErasureStore.erase`, with the tenant and the subject as bind parameters. The existing
`FOR UPDATE` and the tombstone check stay; the advisory lock is what makes them ordered. Do **not**
solve this with SERIALIZABLE: it turns every racing write into a retry the application has to
handle, and the module cannot assume the host application retries.

### MEDIUM

#### CIPHER-04 — the runtime role can delete the tombstone

`shredding_erased_subject` (`schema-postgresql.sql:53`) has no append-only trigger, no anchor and no
guard of any kind, while `shredding_erasure` next to it has all three. The application role must be
able to `INSERT` into it, and the same grant lets it `DELETE`. Delete the row and `mint` mints again
for a subject the erasure log says is erased. `probe_the_runtime_role_can_delete_the_tombstone_and_mint_again`
is RED: the `DELETE` succeeds. **Fix:** the same `BEFORE UPDATE OR DELETE` and `BEFORE TRUNCATE`
trigger pair as the erasure log, pointing at the same `shredding_erasure_append_only()` function.
The tombstone is what makes control 11 enforceable; it needs control 8's protection.

#### CIPHER-05 — the append-only triggers are skipped in a second schema (module B's K1, again)

The four trigger guards test `IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '…')` with no
`tgrelid` predicate. `pg_trigger` is database-wide and trigger names are per-*table*, so once one
schema on the database has run the script, every later schema creates the tables and **silently
skips every trigger**. `probe_the_append_only_triggers_are_skipped_in_a_second_schema` is RED: in
schema `other`, `DELETE FROM other.shredding_erasure` succeeds after an insert. This is exactly the
lesson the same file's header comment records for `to_regclass` (findings J1 and K1) and then does
not apply twelve lines further down. **Fix:** add
`AND tgrelid = to_regclass(quote_ident(current_schema()) || '.shredding_erasure')` (and the anchor
equivalent) to all four guards.

#### CIPHER-02 — a repeat erasure upgrades an outstanding `PARTIAL` to `COMPLETE`

`ErasureService.erase`, `.../application/ErasureService.java:92`: on `alreadyErased` it returns
`new ErasureResult(ErasureOutcome.COMPLETE, true, 0, 0, …)` unconditionally, without looking at what
the first erasure recorded. If that first erasure left a `PostErasureHook` failed and is on record
as `PARTIAL`, the second call — the one a DPO makes when producing the proof — reports `COMPLETE`
while the search-index deletion is still outstanding. Control 19 says the proof "refuses to render
complete while one is outstanding". `probe_a_second_erasure_of_a_partial_subject_reports_complete`
is RED. **Fix:** on `alreadyErased`, read the subject's most recent record through `ErasureReader`
and return its outcome; if the trail cannot be read, return `PARTIAL`, never `COMPLETE`.

#### CIPHER-06 — the Lombok half of the generated-rendering check is dead code

`ShreddedModel.refuseGeneratedRendering` looks for `lombok.Data`, `lombok.Value`, `lombok.ToString`
and `lombok.EqualsAndHashCode` via `Class.getAnnotations()`. All four are
`@Retention(RetentionPolicy.SOURCE)`: they are not in the class file, so the loop can never match
and the check can never fire. Only the record half of Dollar's ruling on QUESTIONS #9 works.
`probe_a_lombok_rendered_entity_starts` is RED — with a stand-in `lombok.Data` that has the real
one's retention and target, `ShreddedModel.scan` starts happily. This matters because
`SECURITY-NOTES.md`'s threat table and `QUESTIONS.md` #9 both report it as applied. **Fix:** detect
what Lombok actually leaves behind — `lombok.Generated` is `CLASS`-retained and is put on every
generated method — or drop the claim from the docs and rely on the sample's ArchUnit rule for the
Lombok case. Do not leave a check in the code that reads as a control and is not one.

#### CIPHER-07 — the unkeyed erasure log's subject pseudonyms are computable by anyone

`ShreddingAutoConfiguration.shreddingPseudonymiser` (`:99`) feeds the `Pseudonymiser` the literal
`"sh/unkeyed-pseudonym-pepper/not-a-secret"` when `shredding.erasure-log.unkeyed=true`. Control 9
exists because "the spec's *subject id hash* over an email or a UUID is enumerable in seconds"; with
a pepper printed in the module's own source the HMAC is a public function and the property is
exactly as lost as if the code had used SHA-256. `probe_the_unkeyed_erasure_log_pseudonym_is_computable_without_a_secret`
is RED: I recompute a stored pseudonym from the published constant and the module's own canonical
form. The unkeyed WARN mentions the chain and says nothing about the pseudonyms. **Fix:** unkeyed
mode is about the *chain*, not about the pseudonym. Require `shredding.subject-pseudonym.pepper`
(base64, ≥ 32 bytes, no default) whenever `unkeyed=true`, fail startup without it, and name this
consequence in the unkeyed WARN.

#### CIPHER-08 — a failed write leaves a stale tenant and subject on the thread

`ShreddingEventListener.onPreInsert` pushes the scope and `onPostInsert` pops it. Any write that
never reaches `PostInsert`/`PostUpdate` — the converter refuses (`SHRED-ERASED-001`), a constraint
fires, `writeBlindIndexes` throws two lines after the push, the flush fails — leaves the scope on
the thread. On a pooled request thread the next *unbracketed* write, which control 15 and
`SHRED-CONTEXT-001` exist to refuse (a bulk JPQL update, a criteria parameter, a detached write),
finds a scope and encrypts under the **previous request's subject** instead of failing closed.
`probe_a_failed_insert_leaves_a_stale_shredding_scope` is RED: after a refused create, the sample's
thread still holds `Scope[tenant=acme, subject=cust-leak-…, entityName=Customer]`. **Fix:** wrap the
push in a `try`/`finally` so nothing between it and the return can leak, and clear the whole stack
at the transaction boundary — a `SessionEventListener`/`AfterTransactionCompletionProcess`, not the
`Post` listeners alone, which by construction do not run on the failure path.

#### CIPHER-09 — control 12's cache half misses `sharedCache.mode=ALL` and the query cache

`ShreddedModel.scan(Collection<Class<?>>, boolean)` can only see `@Cacheable` and
`org.hibernate.annotations.@Cache` on the entity class. `jakarta.persistence.sharedCache.mode=ALL`
caches every entity regardless of any annotation, and the **query cache**, which control 12 names
explicitly ("Query cache likewise"), is not looked at anywhere in the module —
`grep -rni 'query_cache|sharedCache|shared-cache'` over the whole repository returns nothing.
No probe: the finding is that the `scan` signature has no way to express the check, which is
visible in the signature itself. **Fix:** pass the resolved JPA/Hibernate cache settings (from the
`EntityManagerFactory` properties, available in `shreddedModel(...)`) into `scan`, and refuse
`sharedCache.mode` of `ALL`/`ENABLE_SELECTIVE`-with-no-opt-out and
`hibernate.cache.use_query_cache=true` under the same `shredding.allow-second-level-cache` escape
hatch and the same WARN. Probe to add: `probe_shared_cache_mode_all_serves_plaintext_after_erasure`.

#### CIPHER-10 — `probe_tenant_b_decrypts_tenant_a_value_for_the_same_subject_id` does not test its property

See R1 above: with `tenant` removed from `Aad.forValue` the probe stays green. **Fix:** add to it an
assertion that the value AAD differs by tenant — the cleanest form is to decrypt a blob whose header
tenant has been rewritten *while the corresponding key for that tenant exists*, so the wrap AAD
cannot be what fails. `CipherProbeAadTest.the_aad_binds_every_component` already asserts the AAD
strings differ; the value-path probe must assert the behaviour, not only the string.

### LOW

- **L1 — the hexagonal rule is a denylist, not "JDK only".**
  `HexagonalArchitectureTest.domain_has_no_framework_imports` forbids `javax..` (minus
  `javax.crypto..`), Spring, `jakarta..`, `java.sql..`, slf4j, Jackson, Hibernate, `..application..`
  and `..adapter..`, and `domain_imports_no_crypto_library` names three crypto packages. The house
  rule and control 18 say the domain is **JDK only**. Today nothing escapes, because
  `gdpr-shredding-core`'s single compile dependency is `slf4j-api` and that is denied — one added
  dependency in `gdpr-shredding-core/pom.xml` is all it takes for Guava, Netty or commons-lang to
  become legal in `domain`. **Fix:** invert to an allowlist —
  `should().onlyDependOnClassesThat().resideInAnyPackage("java..", "javax.crypto..", "com.housedevinci.shredding.domain..")`.
  It passes on the current code, so the hardening is free.
- **L2 — no coverage gate outside `gdpr-shredding-core`.** The JaCoCo plugin is configured only in
  `gdpr-shredding-core/pom.xml`; the starter and the sample produce no `jacoco.csv` and are subject
  to no minimum. That leaves the converters, `ShreddingEventListener`, `SubjectExpression`,
  `ShreddedModel`, `ShreddingStartupCheck` and the actuator sanitiser — controls 5 and 11 to 14 —
  unmeasured. **Fix:** move the JaCoCo `prepare-agent`/`report`/`check` executions to
  `<pluginManagement>`-backed `<plugins>` in the parent so all three modules inherit the 80 % line
  gate.
- **L3 — `JdbcSupport.runtimeRoleOwnsErasureTable` is dead code.** It is public, it is correct, and
  nothing calls it. `SECURITY-NOTES.md` prescribes the very role separation it checks
  ("Run the application with a role that has INSERT and SELECT on `shredding_erasure`, not the
  owner"). **Fix:** call it from `ShreddingStartupCheck` and WARN at every startup when the runtime
  role owns the table, since that role can `ALTER TABLE … DISABLE TRIGGER` and defeat control 8.
- **L4 — the sample ships no log-scan test.** Control 12 asks for "the sample ships a log-scan test
  grepping for the plaintext fixture". `ShreddedFieldsDoNotLeakTest` is an ArchUnit/reflection test
  over the class structure, and `probe_entity_tostring_leaks_the_decrypted_value` inspects
  `toString()`. Neither captures what the application actually logged. **Fix:** attach a
  `ListAppender`/`OutputCaptureExtension` to the end-to-end flow and assert the captured output
  never contains `alice@example.com` or `+33100000000`.
- **L5 — `markDestroying` is theatre under MVCC.** `JdbcErasureStore.erase` runs
  `UPDATE … SET state = 'DESTROYING'` and the `DELETE` in the *same* transaction, so no other
  transaction can ever observe `DESTROYING`: it is invisible until it commits, and when it commits
  the rows are gone. The comment at `:208` claims it is "visible to a concurrent reader that took
  its snapshot after this statement and before the delete commits", which MVCC does not allow.
  The in-process state check in `FieldCipher` is real; the cross-connection one that
  `SECURITY-NOTES.md` lists as the control against post-erasure key use is not. **Fix:** either
  drop the statement and the claim, or commit the `DESTROYING` mark in its own transaction first
  (which is a design change: it makes the two-phase erasure real, and needs its own recovery story
  for a crash between the phases). Do not leave the comment as it stands.
- **L6 — `ErrorCodes.KEY_EXHAUSTED` is declared and never used.** `FieldCipher` rotates instead of
  refusing, which is right; the constant is documented in `docs/index.md` as an error a caller can
  see and cannot occur. Remove it or make it reachable.
- **L7 — the sample teaches a tenant-less read and an unauthenticated erasure.**
  `CustomerEndpoints.read` looks up by `customerId` with no tenant, on a module whose control 15
  makes the tenant mandatory and forbids a default; `POST /customers/erasures` takes
  `requestedBy` from the request body with no authentication. The sample is the copyable reference,
  and `QUESTIONS.md` #9 says so explicitly about its ArchUnit rule. **Fix:** take the tenant on the
  read path and say in the sample's README, in one line, that a real erasure endpoint is
  authenticated and that `requestedBy` comes from the authenticated principal, never from the body.
- **L8 / L9 — two probes weaker than their names.** See "The 19 probes, judged".
- **L10 — `decodeHooks` throws untyped exceptions on a malformed column.**
  `JdbcErasureStore.decodeHooks` guards the canonical form with `ShreddingException` in three places
  and then calls `Integer.parseInt` on an unvalidated substring, so a `hook_outcomes` value of
  `|x:` produces a raw `NumberFormatException`. That column is writable by exactly the attacker the
  chain exists to detect, and the verifier's read path should report `BROKEN`, not die with an
  untyped error. **Fix:** wrap the parse and throw `SHRED-INVALID-001`, and let
  `ErasureChainVerifier` treat an unparseable row as `BROKEN` at that sequence.

### INFO

- **I1 —** `SimpleEvaluationContext.forReadOnlyDataBinding()` blocks bean references, `T()` type
  references, constructors and method invocation (all four verified by
  `probe_spel_expression_reaches_a_bean_or_a_static_type`, and RED when swapped for
  `StandardEvaluationContext`). It still permits property navigation through `getClass()`
  (`#{class.name}`). Not exploitable here — the expression is written by the application author in
  its own source, never supplied by a request. Recorded so that nobody later accepts a subject
  expression from configuration or from a request without revisiting this.
- **I2 —** `MasterKey.REFUSED` matches case-insensitively with `contains`, on strings as short as
  `"example"` and `"insecure"`. A random 32-byte base64 key that contains one of them would be
  refused; the probability is negligible today, but the list must not grow shorter entries.
- **I3 —** `shreddingErasureChainVerifier` puts the active `hmac-key-id` into the keyring first and
  then the `hmac-keys` map, so a map entry repeating the active id with a different secret silently
  replaces it. Refuse the conflict instead.

---

## The ruling I owe: QUESTIONS #4

**Chosen: (c) — read the stored blob in `PreUpdate`. (b), the shadow subject column, is rejected.**

Three reasons, in order of weight.

1. **(c)'s value is authenticated; (b)'s is not.** The subject in the blob header is bound into the
   AAD of every value written under it, so it cannot be changed without invalidating the ciphertext:
   GCM fails and the row stops reading. A shadow column is ordinary, unauthenticated application
   data. Anyone who can rewrite the shadow column — which is anyone who could rewrite the subject in
   the first place — sets it to whatever they like, and the check passes. That is the same shape of
   argument as control 6's rejection of "overwrite then delete": an assurance the mechanism cannot
   deliver is worse than no mechanism, because it gets written into the proof. Thor's own objection
   to (b) — that a shadow column "can drift out of sync with the ciphertext" — is the mild version
   of this; the sharp version is that drift is *attacker-selectable*.
2. **(c) is the same read this branch needs anyway, for CIPHER-01.** The header-versus-row
   comparison is not an extra mechanism invented for #4: it is precisely the check whose absence is
   the HIGH above. Once the read path compares the header's subject and tenant with the row's
   resolved subject and tenant, the `PreUpdate` case is one more caller of the same code, and #4
   stops being a separate design. Picking (b) would leave the module with two unrelated mechanisms
   for one invariant, and would still leave CIPHER-01 open.
3. **(b) changes the user's schema.** Thor is right that this is what stops a team adopting the
   library, and on an unreleased branch we do not get to add a column to every shredded entity for a
   check the blob already supports.

**What (c) has to include, or it is not the stricter design.**

- The comparison runs on the **read path as well as the update path**. On `PreUpdate` it is a second
  fetch of the row's current shredded columns; on the read path it costs nothing extra, because
  `convertToEntityAttribute` already has the bytes and only needs the scope. The read-path half is
  where (c) earns its keep — it is the CIPHER-01 fix.
- Skip the extra round trip entirely when no `@Shredded` field of the entity is dirty. Thor proposed
  this and it is right: the update path only needs the check when it is about to re-encrypt.
- When the stored row has no shredded blob at all — every shredded column null, or a shredded field
  added to an existing entity — there is nothing that could have been moved out of an erasure scope,
  and the update is allowed. That is correct, not a gap; do not paper it over.
- The bounded per-thread map is **removed**, not kept as a fallback. It is a cache whose miss is a
  silent security failure, and once (c) is in place it defends nothing (c) does not. Delete
  `loadedSubjects`, `MAX_REMEMBERED` and `remember(...)` from `ShreddingEventListener`, and delete
  the corresponding residual paragraph from `SECURITY-NOTES.md` ("The data subject of a persisted
  row is only checked when this process loaded it"): after this fix the statement is no longer
  true, and a residual that has been engineered away must not stay in the list.
- New error code `SHRED-SUBJECT-MISMATCH` for the read-path refusal, distinct from
  `SHRED-SUBJECT-IMMUTABLE` for the update-path refusal: they are different events and a DPO reading
  a log needs to tell "someone changed this row's subject" from "this row holds someone else's
  ciphertext".
- Probes: `probe_changing_the_subject_expression_moves_a_row_out_of_erasure_scope` stays, and gains
  a detached-merge variant in a thread that never loaded the row — the case the per-thread map could
  not catch, and the reason the question was open.

---

## What I attacked and found sound

Recorded so the clean results are as reproducible as the findings.

- **HKDF against RFC 5869.** `HkdfTest` carries A.1, A.2 and A.3 with the RFC's own PRK and OKM
  values, plus the null-salt equivalence, the `1..255*HashLen` bound and extract-then-expand
  agreement. Vectors A.4 to A.7 are **HMAC-SHA-1** cases; this is an HKDF-SHA-256-only
  implementation with no SHA-1 code path, so there is no applicable vector missing. Three of seven
  apply and three of three are present.
- **The nonce counter across restarts and nodes.** It is `shredding_data_key.encryption_count`, a
  `bigint` column incremented with `UPDATE … SET encryption_count = encryption_count + ? …
  RETURNING encryption_count`. The 2^31 WARN, the 2^32 hard refusal and the rotation are therefore
  **cluster-wide and restart-safe**, not per JVM — the answer to the question as asked. Two
  properties I checked and accept: `recordEncryptions` commits in its own transaction, so a
  rolled-back business transaction over-counts, which is the safe direction; and
  `InMemoryKeyProvider` is per-JVM, which is what `shredding.dev-mode=true` means and it refuses to
  start without it.
- **Erasure-chain parity with module B.** Keyed from row 1 (`ErasureChain.keyed`, version `sh2h`
  versus `sh1`), key id inside the hashed material (`canonical(...)` writes `keyId` second),
  length-prefixed canonical form with a distinct `|-` encoding for null, external anchor row with an
  immutable `keyed` column and a monotonic `row_count`, `BEFORE UPDATE OR DELETE` and
  `BEFORE TRUNCATE` triggers on both tables, and all six statuses including `INTACT_UNKEYED` and
  `NO_ANCHOR` with the anchor never re-derived by guessing (`SHRED-ERASURE-002`). Verified live:
  `the_erasure_log_refuses_update_delete_and_truncate` and
  `an_unkeyed_instance_is_refused_against_a_keyed_trail`. The one gap is CIPHER-05, which is the
  *creation* of those triggers, not their design.
- **Lossy column types beyond the timestamps.** I swept everything in the hashed material against
  its column: `subject_pseudonym`, `prev_hash` and `hash` are `char(64)` carrying exactly 64 hex
  characters, so `char`'s blank-padding and trailing-space stripping cannot bite; `requested_by` and
  `reason` are `varchar(1000)` against `ErasureRequest`'s 1000-*character* bound; `tenant` is
  `varchar(255)` against `Identifiers`' 255-*byte* bound; `hook_outcomes` is `text`; the five counts
  are `integer`. PostgreSQL errors rather than truncates on overflow in all of them. No `bytea`, no
  `numeric` and no JSON column is inside the hashed material, so numeric scale and JSON key order do
  not arise. **The timestamps were the only lossy case, and it is fixed.** The reflective guard
  `every_instant_that_crosses_the_storage_boundary_is_truncated` walks the record components of
  `ErasureRecord`, `ErasureResult` and `DataKey` and asserts the exact list it checked, so a new
  `Instant` field cannot be added silently. The diagnosis in `STATUS.md` is correct, the fix is at
  the right layer (the value objects, not the assertion), and both regression tests drive an
  explicit nanosecond `Clock` instead of depending on the host clock's resolution. This is the right
  way to close that class of bug.
- **Schema idempotence and B's K1 lesson.** The whole script runs in one transaction under
  `pg_advisory_xact_lock`, every object is `IF NOT EXISTS` / `CREATE OR REPLACE`, and the
  pre-keyed-from-birth guard resolves both oids against
  `to_regclass(quote_ident(current_schema()) || '.…')` rather than letting `to_regclass` follow the
  `search_path` — B's J1 and K1, correctly applied. `CipherProbeJdbcTest`'s `@BeforeEach` drops and
  re-creates the whole set before every test, so "runs from nothing" and "runs again over itself"
  are both exercised on every build. The four `pg_trigger` guards are the one place the lesson was
  not carried through (CIPHER-05).
- **Supply chain.** GitHub Actions pinned by commit SHA with a version comment
  (`actions/checkout@3d3c42e…`, `setup-java@dd06d9c…`, `upload-artifact@043fb46…`),
  `permissions: contents: read` on both workflows, Maven wrapper with `distributionSha256Sum`, the
  PostgreSQL image pinned by digest in both test suites, Dependabot on Maven **and**
  `github-actions`, and a weekly OWASP dependency-check that fails on CVSS ≥ 7. **Zero crypto
  dependencies:** `gdpr-shredding-core`'s only compile-scope dependency is `slf4j-api`; AES-256-GCM,
  HMAC-SHA-256 and the hand-written HKDF all come from the JDK and no provider is installed.
  Control 18 holds.
- **Tombstone for a subject that never had a key.** `erase` on an unknown subject writes the
  tombstone and a record with `keysDestroyed = 0`. I considered this an abuse (a permanent,
  irreversible block on an arbitrary subject id) and decided it is correct behaviour, not a finding:
  an erasure request for a subject with no data is a real request, the record says `0` so the proof
  does not overstate, and refusing it would mean the module has to guess that a subject "does not
  exist" — which under lazy minting it cannot know. The related risk is CIPHER-04: because the
  tombstone is deletable, the block is not as permanent as the record implies.
- **Key cache TTL under erasure on the same node.** `ErasureService.erase` calls
  `cache.evictSubject` after the transaction, and `FieldCipher.decrypt` re-checks the row state on
  every read even on a cache hit (`a_cached_key_does_not_outrank_the_row_state`), so a same-node
  read after an erasure is refused whether or not the eviction ran. The cross-node window is real,
  documented, and QUESTIONS #8 is ruled.
- **`ErasedValue` policy `null`.** `ShreddingStartupCheck` WARNs on `policy=null` at every startup,
  and separately WARNs under `policy=sentinel` naming every field whose type cannot carry one
  (`the_scan_names_the_fields_whose_type_cannot_carry_a_sentinel`). Control 13 and Dollar's ruling
  on QUESTIONS #5 both hold.
- **Startup checks.** Record detection works and is tested; `@Cacheable`/`@Cache` detection works
  and is tested; the sentinel-less WARN works and is tested; the converter/field cross-check works
  and is tested. The Lombok half does not (CIPHER-06) and the cache check is incomplete
  (CIPHER-09).

---

## Fix list for Thor

Merge is blocked until every line below is done. In priority order.

1. **CIPHER-01** — bracket the read path; `FieldCipher.decrypt` takes the expected tenant and
   subject and refuses `SHRED-SUBJECT-MISMATCH` on a header that disagrees. Probes:
   `probe_a_blob_moved_into_another_subjects_row_still_decrypts`,
   `probe_a_blob_moved_into_another_tenants_row_still_decrypts`.
2. **CIPHER-03** — `pg_advisory_xact_lock` on (tenant, subject) at the top of `currentForWrite`,
   `rotate` and `erase`. Probe: `probe_a_write_racing_the_first_key_mint_survives_the_tombstone`.
3. **QUESTIONS #4 ruling** — implement (c) with everything listed under the ruling, delete the
   per-thread map and the corresponding `SECURITY-NOTES.md` residual, add the detached-merge probe.
4. **CIPHER-04** — append-only triggers on `shredding_erased_subject`. Probe:
   `probe_the_runtime_role_can_delete_the_tombstone_and_mint_again`.
5. **CIPHER-05** — add `tgrelid` to all four trigger guards. Probe:
   `probe_the_append_only_triggers_are_skipped_in_a_second_schema`.
6. **CIPHER-02** — `alreadyErased` returns the recorded outcome, never an unconditional `COMPLETE`.
   Probe: `probe_a_second_erasure_of_a_partial_subject_reports_complete`.
7. **CIPHER-06** — make the generated-rendering check real or remove the claim from
   `SECURITY-NOTES.md` and `QUESTIONS.md`. Probe: `probe_a_lombok_rendered_entity_starts`.
8. **CIPHER-07** — `shredding.subject-pseudonym.pepper` required under `unkeyed=true`; name the
   consequence in the WARN. Probe:
   `probe_the_unkeyed_erasure_log_pseudonym_is_computable_without_a_secret`.
9. **CIPHER-08** — `try`/`finally` around the push and a transaction-boundary clear. Probe:
   `probe_a_failed_insert_leaves_a_stale_shredding_scope`.
10. **CIPHER-09** — check `sharedCache.mode` and the query cache. Probe:
    `probe_shared_cache_mode_all_serves_plaintext_after_erasure`.
11. **CIPHER-10 / M8** — strengthen `probe_tenant_b_decrypts_tenant_a_value_for_the_same_subject_id`
    so it goes red when `tenant` leaves `Aad.forValue`.
12. **L1** — ArchUnit allowlist for `domain`.
13. **L2** — JaCoCo gate on the starter and the sample.
14. **L3** — call `runtimeRoleOwnsErasureTable` and WARN.
15. **L4** — a real log-scan test in the sample.
16. **L5** — remove `markDestroying` and its comment, or make it a committed first phase with a
    recovery story.
17. **L6** — remove `KEY_EXHAUSTED` or make it reachable.
18. **L7** — tenant on the sample's read path; one line in the sample README about authenticating
    the erasure endpoint and taking `requestedBy` from the principal.
19. **L8, L9** — strengthen the two weak probes or rename them to what they test.
20. **L10** — typed error from `decodeHooks`; `BROKEN` from the verifier on an unparseable row.
21. **I1, I2, I3** — record I1 in `SECURITY-NOTES.md`; leave `REFUSED` as it is but do not add
    shorter entries; refuse a duplicate key id in the verifier's keyring.

### Not verified

- The actuator behaviour end to end. `probe_master_key_appears_in_actuator_env` exercises the
  `SanitizingFunction` in isolation; I did not stand up an actuator context and read `/env` and
  `/configprops`, so "the master key is absent from the live endpoints" is asserted by construction,
  not observed. L8 asks for the missing test.
- Cross-JVM behaviour of anything. Every concurrency finding was reproduced with two connections or
  two threads against one PostgreSQL instance. A genuine two-node deployment was not stood up.
- `shredding.erasure-log.hmac-keys` rotation across a real key change; the verifier's keyring is
  covered by unit tests only.
- CIPHER-09's exploit path. The finding is a missing check, proven from the `scan` signature and a
  repository-wide grep; I did not build a Spring context with `sharedCache.mode=ALL` and observe a
  cached entity serving plaintext after an erasure.

---

## Re-verification (96713f9)

Reviewer: Cipher. Branch `feat/shredding-core`, HEAD `96713f9`, draft PR #1. Prior review at
`16cc142`; Isis's remediation at `14a7931`, licence switch at `96713f9`. Rule in force: **no
allowance**.

### Verdict

**NOT MERGEABLE.** Three HIGH findings, each reproduced with a probe that fails on `96713f9`.

The remediation is real work and most of it is right: 22 of the 24 prior findings are closed in
code and confirmed by probe, the licence switch is clean, and the two deviations Isis documented
(QUESTIONS #13, #14) are both correct and are accepted below. But **CIPHER-01 is not closed**. It
was closed for one read path — the ordinary entity load — and the fix's design puts the check in a
place that three other paths do not go through. I reached a moved ciphertext's plaintext three
different ways on this HEAD, and in one of them a subject's own Art. 17 erasure leaves their data
readable. That is the product's central claim, so the severity is unchanged from the first pass.

### Numbers

| | Value | Source |
|---|---|---|
| `./mvnw -B clean verify` | **exit 0**, Docker up (29.7.2) | this machine |
| Tests, core | 76 run, 0 failed, 0 errored, 0 skipped | `gdpr-shredding-core/target/surefire-reports` |
| Tests, starter | 25 / 0 / 0 / 0 | `.../spring-boot-starter/target/surefire-reports` |
| Tests, sample | 17 / 0 / 0 / 0 | `.../sample/target/surefire-reports` |
| **Total** | **118, nothing skipped, no `@Disabled`, no `assumeTrue`** | |
| Coverage LINE, core | **965 / 1152 = 83.8 %** (gate 80 %) | `gdpr-shredding-core/target/site/jacoco/jacoco.csv` |
| Coverage LINE, starter | **541 / 655 = 82.6 %** (gate 80 %, new — L2) | `.../spring-boot-starter/.../jacoco.csv` |
| Coverage LINE, sample | **63 / 95 = 66.3 %** (smoke gate 30 %) | `.../sample/.../jacoco.csv` |
| Coverage BRANCH | core 58.1 %, starter 62.9 %, sample 33.3 % | same CSVs, ungated |

Every number Isis reported is exact. The `jacoco.minimum.line` = 0.80 gate is now in the parent's
`<plugins>` and all three modules inherit it; the sample overrides to `jacoco.minimum.sample` = 0.30.

### Probes: none narrowed

19 probes at `16cc142`, 31 at `96713f9`. Thirteen added, one removed:
`probe_second_level_cache_serves_plaintext_after_erasure` is *renamed* to
`the_startup_check_refuses_a_cacheable_shredded_entity` with every assertion kept and a javadoc that
says plainly it never showed a cache serving plaintext. That is the correct disposition of L9 — a
probe whose name overclaims should lose the name, not keep it — and the property it could not test
is now covered by `probe_shared_cache_mode_all_serves_plaintext_after_erasure` and
`the_query_cache_is_refused_under_the_same_escape_hatch`. Nothing was weakened.

The three probes I called weaker now test their named property:

- **L8** — `CipherProbeActuatorEndToEndTest` drives the real `/actuator/env` and
  `/actuator/configprops` through MockMvc and greps the response body for the master key in both
  plaintext and base64. It no longer calls the `SanitizingFunction` in isolation.
- **L9** — see above.
- **CIPHER-10 / M8** — `probe_value_aad_binds_tenant_independently_of_the_wrap_layer` hands
  `FieldCipher` a `KeyProvider` that returns *the same key for every tenant*, so the wrap layer
  cannot be what fails and only the value AAD can. This is exactly the construction the finding
  asked for.

### The 24 prior findings, judged

Closed in code and confirmed: **CIPHER-02** (`ErasureService` re-runs hooks on a repeat erasure of
an outstanding `PARTIAL` and never claims `COMPLETE` the trail does not support; two probes),
**CIPHER-03** (`JdbcSupport.lockSubject` — a transaction-scoped advisory lock on `(tenant, subject)`
taken first by `currentForWrite`, `rotate` and `erase`; see the attack below, it holds),
**CIPHER-04** (`shredding_erased_subject` now carries the same append-only and no-truncate
triggers), **CIPHER-05** (every trigger guard resolves `tgrelid` against
`quote_ident(current_schema())`), **CIPHER-06**, **CIPHER-07** (`unkeyed=true` now *requires*
`shredding.subject-pseudonym.pepper`; `Pseudonymiser` refuses a secret under 32 bytes),
**CIPHER-08** (try/finally around each push *and* an `AfterCompletionCallback` that clears the whole
stack at the transaction boundary — the right two-layer shape, since `Post*` listeners do not run on
the failure path), **CIPHER-09**, **CIPHER-10**, **L1** (the ArchUnit rule is now an allowlist:
`java..`, `javax.crypto..`, `..shredding.domain..`), **L2**, **L3** (`ShreddingStartupCheck` calls
`runtimeRoleOwnsErasureTable` and WARNs), **L4** (a real `OutputCaptureExtension` scan),
**L5** (`markDestroying` and its false claim are gone), **L6** (`KEY_EXHAUSTED` removed),
**L7** (the sample's read takes the tenant; `/customers/erasures` is behind HTTP Basic and
`requestedBy` comes from `Principal`), **L8**, **L9**, **L10** (`decodeHooks` wraps the parse and
`map` names the failing `seq`), **I2**, **I3** (a `hmac-keys` entry repeating the active id with a
different secret is refused).

**I1 — I withdraw it.** I attacked the SpEL surface directly:
`#{class.name}`, `#{class.classLoader}`, `#{class.protectionDomain.codeSource.location}` and
`#{class.module.name}` are all **refused**. `SimpleEvaluationContext.forReadOnlyDataBinding()`'s
`DataBindingPropertyAccessor` filters `Object.getClass` out, so the property-navigation gap I
recorded does not exist. `T(java.lang.Runtime)`, `T(java.lang.System).getenv()`, `@someBean` and
`@systemProperties['user.name']` are all refused too. This closes with no code change, which is the
only way a finding is allowed to close without one.

**CIPHER-01 — not closed. See CIPHER-11, CIPHER-12 and CIPHER-14 below.**

### New findings

#### HIGH

##### CIPHER-11 — a scalar or DTO projection returns another subject's plaintext

CIPHER-01's fix is two-phase by necessity (QUESTIONS #13, which I accept): `ShreddedConverter`
records the header in `ShreddingContext.DECODED_READS`, and `ShreddingEventListener.onPostLoad`
compares it against the hydrated row. **`onPostLoad` fires for entity loads only.** A JPQL or
Criteria query that selects the attribute itself runs the converter — the converter decrypts from
the *header's* tenant and subject, so it needs no ambient scope — and hands the plaintext straight
back with no listener in the path and nothing to compare against.

*Repro.* `Doc` fixture, two shredded `String` fields, `subject = "#{ownerId}"`. Insert Alice with
`title = "ALICE-SECRET-TITLE"`, insert Bob, then `UPDATE doc SET title = <alice's blob> WHERE
id = <bob>` — the identical move `probe_a_blob_moved_into_another_subjects_row_is_refused_on_read`
already refuses on an entity load. Then:

```java
em.createQuery("select d.title from Doc d where d.id = :id").setParameter("id", bob).getSingleResult()
```

returns `ALICE-SECRET-TITLE`. A `Tuple` query, a constructor-expression DTO and a Spring Data
closed projection are the same path. This is verbatim the property CIPHER-01 names.

*Probe (RED).* `probe_a_moved_blob_is_returned_by_a_scalar_projection`.

*Fix.* The comparison cannot stay in a listener that only entity loads reach. Move the refusal into
`ShreddedConverter.convertToEntityAttribute` itself and make the entity path the *relaxation*, not
the mechanism: the converter refuses unless a scope is present that vouches for this header. Two
shapes work and either is acceptable —

1. **Push a read scope.** Add a `PreLoadEventListener` (it fires per row, before hydration
   completes, and it has the entity and its id) that resolves the row's subject/tenant from the
   *identifier and the loaded state array* and pushes a read scope; the converter compares the
   header against that scope and refuses on mismatch. A converter reached with no read scope at all
   — the projection case — is refused with `SHRED-SUBJECT-MISMATCH` rather than decrypted, and the
   application opts a projection in explicitly by wrapping it in `ShreddingContext.with(...)`.
2. **Refuse the unbracketed read outright.** If (1) is too large for this release, make
   `convertToEntityAttribute` fail closed when no read scope is present, and document that shredded
   fields are readable only through a managed entity — the exact rule
   `convertToDatabaseColumn` already enforces for writes via `ShreddingContext.require`. The write
   path already establishes that this module is willing to refuse an unscoped access; the read path
   must not be laxer than the write path about the same value.

Whichever is taken, `onPostLoad` keeps its check as defence in depth.
Probes to add: the one above, plus a `Tuple` variant and a constructor-expression DTO variant, and
one asserting an unscoped projection of a *legitimate* row is refused rather than silently served.

##### CIPHER-12 — nulling the subject column disables the read-path check

`onPostLoad` wraps `resolveSubject` in `try { ... } catch (RuntimeException e) { return; }`
(`ShreddingEventListener:173-179`). The comment says a row whose subject expression cannot be
evaluated "is not a reason to fail the read". It is: it is the reason the check exists. The
attacker who can move a ciphertext between rows is by construction the attacker who can write one
more column, and `UPDATE doc SET owner_id = NULL` makes `SubjectExpression.evaluate` throw
`SHRED-INVALID` — at which point the whole loop, for every shredded field on the row, is skipped and
the moved blob is decrypted and returned through the ordinary entity load that
`probe_a_blob_moved_into_another_subjects_row_is_refused_on_read` covers.

*Repro.* As CIPHER-11, then `UPDATE doc SET owner_id = NULL WHERE id = <bob>`;
`em.find(Doc.class, bob).getTitle()` returns `ALICE-SECRET-TITLE-2`.

*Probe (RED).* `probe_a_moved_blob_is_returned_when_the_subject_source_is_null`.

*Fix.* Fail closed. A row that carries a shredded blob and whose subject cannot be resolved is a row
whose ownership is unknown, and an unknown owner is never a reason to hand out the value. If any
`ShreddingContext.takeDecoded` for the entity is non-empty, an unresolvable subject must throw
`SHRED-SUBJECT-MISMATCH`, not return. Only when every shredded column on the row was null may the
resolution failure be ignored — and by then there is nothing to leak.
Probe: the one above, plus one asserting a row with *no* shredded blob and an unresolvable subject
still loads.

##### CIPHER-14 — the update-path check is skipped when the first shredded column is null, and a row escapes its subject's erasure

`refuseIfSubjectMoved` builds its verification query from `fields.get(0)` alone — one column, the
first `@Shredded` field in declaration order — and returns early when that column is `NULL`
(`ShreddingEventListener:265-267`). On an entity with more than one shredded field, a row whose
first shredded column is null and whose *second* holds a live ciphertext gets no check at all. The
subject is then changed, Hibernate's default (non-`@DynamicUpdate`) UPDATE re-encrypts every
shredded column under the new subject's key, and the row leaves the original subject's erasure
scope permanently.

*Repro.* Persist `Doc(owner = victim, title = null, body = "VICTIM-SECRET-BODY")`. Load it, call
`setOwnerId(hijacker)`, flush — **allowed**, no exception. Then run the victim's own erasure:
`erasures.erase(new ErasureRequest("default", victim, "dpo", "art 17"))`. Reload the row:

```
### AFTER THE VICTIM'S ERASURE, BODY READS = VICTIM-SECRET-BODY
```

The erasure reports success, the chain says so, and the victim's personal data is still readable.
This is the same class as QUESTIONS #4 and it is HIGH for the same reason.

*Probes (RED).* `probe_the_update_check_is_skipped_when_the_first_shredded_column_is_null`
(the update is `ALLOWED`) and
`probe_a_row_escapes_its_subjects_erasure_scope_when_the_first_column_is_null` (the end-to-end
harm).

*Fix.* Read **every** shredded column of the entity in the one verification query
(`SELECT c1, c2, ... FROM t WHERE id = ?`) and compare the header of each non-null one. Return early
only when *all* of them are null, which is the case the ruling actually blessed ("when the stored
row has no shredded blob at all"). While that query is being widened, note that it also assumes all
shredded fields share one table; assert that in `ShreddedModel.scan` and refuse a shredded entity
whose fields span a secondary table, rather than silently checking one of them.

#### MEDIUM

##### CIPHER-13 — a non-entity read leaves a stale header on the thread and breaks the next legitimate load

`DECODED_READS` is written by every `convertToEntityAttribute` and drained only by `onPostLoad`.
Every read that is not an entity load — the projections of CIPHER-11 — leaves its entry behind.
The next entity load of the same type whose shredded column is `NULL` runs no converter, so it puts
nothing in the map, and `takeDecoded` hands it the *previous* query's header: a legitimate row is
refused with `SHRED-SUBJECT-MISMATCH`. Outside a transaction nothing calls `clearAll`, so on a
pooled request thread the map also simply grows.

*Repro.* In one transaction: project Alice's `title`, then `em.find` Carol's row (title null, body
set). The `find` throws `SHRED-SUBJECT-MISMATCH` naming `Doc.title`. Reproduced twice — as its own
probe, and as cross-test contamination when the projection probe ran before an unrelated one in the
same JVM.

*Probe (RED).* `probe_a_projection_leaves_a_stale_decoded_entry_that_breaks_a_later_load`.

*Fix.* Falls out of CIPHER-11: once the converter itself checks against a read scope, the
thread-local hand-off disappears. If CIPHER-11 is fixed by shape (2), `DECODED_READS` must at
minimum be cleared at the same `AfterCompletionCallback` that clears `SCOPES`, and cleared on the
`return` paths of `onPostLoad` — including CIPHER-12's. A cache whose miss is a security failure was
deleted from this class once already (the `loadedSubjects` map, QUESTIONS #4); this is the same
object under a new name and it should not outlive the fix.

##### CIPHER-15 — `latestForSubject` orders an append-only log by the application clock

`JdbcErasureStore.latestForSubject` is `ORDER BY ts DESC, seq DESC`. `ts` is `clock.instant()` from
the application; `seq` is a monotonic `bigserial` in the same row. CIPHER-02's fix — "only report
`COMPLETE` when the trail actually says `COMPLETE`" — reads the newest record through this query, so
a backwards clock step (NTP, a container resume, two nodes disagreeing) between the first `PARTIAL`
and a later append lets the query return an *older* `COMPLETE` and hide an outstanding `PARTIAL`
from the DPO who asked. The log has a monotonic column; use it.

*Fix.* `ORDER BY seq DESC LIMIT 1`. Probe: append a `COMPLETE` then a `PARTIAL` whose `ts` is
earlier, and assert `latestForSubject` returns the `PARTIAL`.

##### CIPHER-16 — `ShreddedBytesConverter` is unusable under `@GeneratedValue(IDENTITY)` (QUESTIONS #15)

Reproduced independently. `new Blob(owner, new byte[]{1,2,3,4})` + `persist` + `flush` fails with
`SHRED-CONTEXT-001` ("no shredding context while writing Blob.payload"), from
`AttributeConverterMutabilityPlan.deepCopyNotNull` outside the `onPreInsert`/`onPostInsert` bracket.
Isis's diagnosis is exactly right. See the ruling on #15 below.

#### LOW

- **L11 — `lockSubject`'s namespace claim is not what the mechanism does.** The javadoc says the
  fixed salt is what stops the subject locks colliding "with the schema step's own single-key lock
  or with `JdbcErasureStore`'s chain append lock". `pg_advisory_xact_lock(bigint)` is a single flat
  64-bit space; a salt changes the *hash*, not the namespace, so `hashtextextended(pair, salt)` can
  in principle land on `0x5348455241` or on `6072873668427846209` like any other value. The
  probability is 2⁻⁶⁴ and the *consequence* of any collision here is benign — two unrelated pairs,
  or a pair and the chain, serialising against each other, never a missed exclusion — so this is not
  an exploitable finding. It is a comment claiming a property the code does not have, which is the
  same defect as L5 in the first pass. **Fix:** either use the two-argument form
  `pg_advisory_xact_lock(int4, int4)`, which *is* a distinct namespace from the one-argument form,
  or delete the namespace sentence and say only that collisions are harmless here and why. Note for
  the record that the delimiter is also ambiguous — tenant `a|b` + subject `c` hashes the same
  string as tenant `a` + subject `b|c` — and is harmless for the same reason; the length-prefixed
  canonical form used everywhere else in this module (`Pseudonymiser.append`, `ErasureChain`) would
  remove the question.
- **L12 — a mistyped subject expression yields an identity hash and an unerasable row.**
  `SubjectExpression.evaluate` ends in `String.valueOf(value)` with no check on the type. I
  confirmed `#{#this}` and `#{#root}` are permitted and return the entity, so the subject becomes
  `com.example.Doc@22875539` — a different value for every instance and every JVM run. The row is
  then encrypted under a key nobody will ever ask for again: an erasure for the real subject never
  touches it, and nothing warns. `#{'a'.bytes}` is likewise permitted and yields `[B@52066604`.
  **Fix:** refuse a resolved value that is not a `CharSequence`, `Number`, `UUID`, `Enum` or
  `java.util.Date`/`Temporal`, with `SHRED-CONFIG` naming the expression; and refuse any resolved
  string matching the default `Object.toString()` shape. Probe:
  `probe_a_subject_expression_resolving_to_an_identity_hash_is_refused`.
- **L13 — a stale licence claim in the build.** `pom.xml:280`, inside the third-party allowlist
  rationale, still reads "Apache-2.0 — the licence of this project". It is not, as of `96713f9`.
  One-word fix; it is in the file a reader checks to learn what the project is licensed under.
- **L14 — `LogScanTest` can pass vacuously.** It asserts `output.getAll()` does not contain the two
  fixtures and never asserts the capture is non-empty, so a logging misconfiguration that captured
  nothing at all would read as a pass. **Fix:** assert the capture contains a known-benign marker
  the flow definitely logs (the customer id, or a WARN this suite provokes) before asserting the
  absence of the plaintext.

### Attacks that found nothing

Recorded so the clean results are as reproducible as the findings.

- **Advisory-lock ordering.** Every path that takes both locks takes them in one order:
  `JdbcErasureStore.erase` takes the `(tenant, subject)` lock, then `LOCK_KEY` inside
  `appendInTransaction`. `append` takes `LOCK_KEY` only; `currentForWrite` and `rotate` take the
  subject lock only; `initializeSchema` takes its own constant only. There is no path from
  `LOCK_KEY` to a subject lock, so there is no cycle and no deadlock. Collisions are benign (L11).
- **`lockSubject` on the read path.** `forRead` takes no lock and mints nothing; no read path mints.
  `recordEncryptions` relies on the row lock of its own `UPDATE … RETURNING`, which is correct.
- **CIPHER-03 under the split transaction.** `JdbcSupport.inTransaction` opens its *own* connection,
  so the key mint commits independently of the caller's JPA transaction. This does not reopen
  CIPHER-03: both `mint` and `erase` take the same advisory lock first, so they serialise, and both
  orderings are safe — mint-then-erase leaves a key row for `erase` to delete, erase-then-mint
  leaves a tombstone for `mint` to refuse. A write that got its key just before an erasure commits
  writes a ciphertext under a key that is then destroyed: unreadable, which is the correct outcome.
- **`onPreUpdate`'s second query is not stale.** It runs through
  `event.getSession().doReturningWork`, i.e. on the session's own JDBC connection inside the
  business transaction, so it sees this transaction's own earlier writes and the last committed
  state of everyone else's. `PreUpdate` fires before this entity's UPDATE binds, so the row it reads
  is the pre-update one. A second update to the same entity in the same transaction reads back the
  first update's value, which is what the check wants. Correct as written — the defect is
  CIPHER-14's single column, not the transaction.
- **The pepper under `unkeyed=true`.** `shredding.subject-pseudonym.pepper` is required, not
  defaulted; `Pseudonymiser` refuses anything under 32 bytes; the WARN names it. CIPHER-07 closed.
- **The context bracket.** Both `Pre*` listeners pop on a `RuntimeException` from
  `writeBlindIndexes`, and `registerTransactionBoundaryClear` clears the whole stack at completion
  whether or not the flush succeeded. A `REQUIRES_NEW` inner transaction's completion clears an
  outer scope too, which makes the outer write fail closed with `SHRED-CONTEXT-001` rather than use
  a wrong scope. That is the right direction to fail.
- **The cache-mode startup check.** `sharedCache.mode=ALL` and `DISABLE_SELECTIVE` are refused on an
  entity carrying no cache annotation at all; `ENABLE_SELECTIVE` without `@Cacheable` is correctly
  allowed; `hibernate.cache.use_query_cache=true` is refused; the escape hatch works in every case.
- **The `PARTIAL` re-erasure.** A repeat erasure of a subject with an outstanding `PARTIAL` re-runs
  the hooks and appends a record reporting what they actually did, with `keysDestroyed = 0`; a
  repeat of a `COMPLETE` subject writes nothing. Subject to CIPHER-15's ordering caveat.
- **The tombstone triggers.** Present on `shredding_erased_subject` and resolved by `tgrelid`
  against `quote_ident(current_schema())`, as are all six other guards.
- **The keyring.** A `hmac-keys` entry repeating the active `hmac-key-id` with a different secret is
  refused with `SHRED-CONFIG`; with the same secret it is allowed. I3 closed.
- **The sample's authentication.** `/customers/erasures` requires HTTP Basic and `requestedBy` comes
  from `Principal`, never the body; `GET /customers/{tenantId}/{customerId}` takes the tenant. The
  unauthenticated `GET /customers/erasures/verify` returns only status, counts, head hash and key
  ids — no pseudonym, no `requestedBy`, no `reason` — so it is not a leak.
- **The sample's log scan.** Real `OutputCaptureExtension` over create, read, blind-index query,
  erase, re-read, verify and a refused write. Subject to L14.

### Ruling: QUESTIONS #13 — **accepted as written**

Isis is right and the evidence is the right kind. My fix text asked for a refusal "before it touches
the key store", and on the read path there is no such hook: she disassembled
`EntityInitializerImpl` in the Hibernate 7.4 this module builds against and showed every converter
has run before the first load listener fires, rather than asserting it. My own text offered
`onPostLoad` as the alternative and she took it. The property CIPHER-01 names — a moved ciphertext
is not *displayed* — is deliverable from `onPostLoad`, and a few instructions of internal,
never-externalised decryption is an acceptable price when the hook that would avoid it does not
exist. Accepted; no change is owed on the reasoning.

What is owed is the *coverage* of that check, which is CIPHER-11 and CIPHER-12: the deviation is
sound, its placement is not, because `onPostLoad` is not on every path that reaches the converter.
Fixing those does not reopen #13.

### Ruling: QUESTIONS #14 — **accepted; the optimisation is withdrawn**

Isis is right and I was wrong. I prescribed "skip the round trip when no `@Shredded` field is
dirty", quoting Thor's proposal; without `@DynamicUpdate` Hibernate's UPDATE rewrites every basic
column, so every converter re-runs and "no shredded field dirty" is true on precisely the update the
check exists to catch — the one that changes only the subject's source property. She found it with
her own probe going green when it should have gone red, which is the only way that class of error
gets caught. The optimisation is withdrawn from the #4 ruling; `refuseIfSubjectMoved` runs on every
update to a shredded entity. If `@DynamicUpdate` is ever supported explicitly, the skip may return
conditioned on `persister.isDynamicUpdate()` and per-property dirtiness, and not before.

### Ruling: QUESTIONS #15 — **a merge blocker; fix it, do not refuse the type**

The question I was asked is whether the `byte[]` converter bug blocks the free core. It does, and
the "refuse it at startup" alternative is the wrong trade here.

`ShreddedBytesConverter` is a documented, exported part of the public API — one of six converter
base classes in `docs/index.md` — and `@GeneratedValue(IDENTITY)` is the ordinary identifier
strategy for the PostgreSQL applications this module targets. "Not supported in this release" for
that combination is not a narrow carve-out; it is most of the type's real use. Shipping it as
"not production-ready" in a doc is worse still: a security library's own documentation telling
users which of its parts not to trust is how a user ends up trusting the wrong one, and the failure
mode when they do is a refused write, not a silent one, which means they will reach for a
workaround — most likely dropping the `@Shredded` annotation. Neither option belongs in a first
release.

It is also small. The cause is that Hibernate treats `byte[]` as mutable and deep-copies the
*converted* value to build the dirty-checking snapshot, calling `convertToDatabaseColumn` a second
time outside the write bracket. The fix is to stop that second call, not to widen the bracket:
declare the converted attribute immutable so `AttributeConverterMutabilityPlan` does not deep-copy
it. In practice that is `@Immutable` on the field or an explicit `MutabilityPlan`/`JavaType`
alongside the converter — `ShreddedConverter` already returns a fresh array from `toBytes` and
`fromBytes`, so nothing shares state and the immutability claim is honest. Widening the bracket to
cover the snapshot would be the wrong fix: `ShreddingContext.require` refusing an unscoped write is
correct behaviour and must not be relaxed to accommodate a caller that should not be there.

**Fix list entry.** Make `ShreddedBytesConverter` work under `@GeneratedValue(IDENTITY)` by
declaring the converted attribute immutable to Hibernate; add `fixture/Blob.java` (a `byte[]`
`@Shredded` field, IDENTITY id) to the starter's `@EntityScan` and a regression test that inserts,
reads back, erases and re-reads it, plus the same round trip under `SEQUENCE` so the fix is not
strategy-specific. Remove the "not production-ready" language from `docs/index.md` and QUESTIONS #15
once it passes. If the immutability route turns out not to hold, come back with the evidence and I
will rule again — but the type does not ship refused and it does not ship warned.

### Licence

Verified, and clean.

| Check | Result |
|---|---|
| `LICENSE` vs upstream `https://fsl.software/FSL-1.1-ALv2.template.md` | **byte-equal except one line**: `Copyright ${year} ${licensor name}` → `Copyright 2026 Housedevinci`. `diff` reports exactly that hunk and nothing else. |
| The two template fields | Both substituted, both on that one line. No other edit. |
| `NOTICE` | Names FSL-1.1-ALv2, points at `LICENSE`, states the two-year Apache-2.0 conversion. Correct. |
| POM `<licenses>` block | `<name>Functional Source License, Version 1.1, ALv2 Future License</name>`, `<url>` the upstream template, `<distribution>repo</distribution>`, comment naming the conversion. Correct. |
| Both files in the core jar | `META-INF/LICENSE` (3744 B), `META-INF/NOTICE` (297 B) — byte-identical to the repo files. |
| Both files in the starter jar | Same two entries, same sizes. |
| Third-party scan excludes our own group | `<excludedGroups>com\.housedevinci</excludedGroups>`, excluding by groupId rather than by licence name, so a third party declaring the same string is still caught. Correct shape. |
| Any "open source" claim for our code | **None.** `grep -rni 'open.source|open-source|OSI|free software'` over the repository returns nothing. `README.md` says "Fair source (FSL-1.1-ALv2): free to use, not as a base for a competing product, becomes Apache-2.0 two years after each release", which is accurate. |

One defect, recorded as L13 above: `pom.xml:280` still calls Apache-2.0 "the licence of this
project".

### Fix list for Isis

1. **CIPHER-11 (HIGH)** — the header-versus-row check must be on the converter, not only on
   `onPostLoad`. Probes: `probe_a_moved_blob_is_returned_by_a_scalar_projection`, plus `Tuple` and
   constructor-expression-DTO variants.
2. **CIPHER-12 (HIGH)** — `onPostLoad` must not `return` on an unresolvable subject when any
   shredded column decoded. Probe: `probe_a_moved_blob_is_returned_when_the_subject_source_is_null`.
3. **CIPHER-14 (HIGH)** — `refuseIfSubjectMoved` reads every shredded column, not `fields.get(0)`;
   refuse a shredded entity spanning a secondary table in `ShreddedModel.scan`. Probes:
   `probe_the_update_check_is_skipped_when_the_first_shredded_column_is_null`,
   `probe_a_row_escapes_its_subjects_erasure_scope_when_the_first_column_is_null`.
4. **CIPHER-13 (MEDIUM)** — `DECODED_READS` must not survive the read that filled it. Probe:
   `probe_a_projection_leaves_a_stale_decoded_entry_that_breaks_a_later_load`.
5. **CIPHER-15 (MEDIUM)** — `latestForSubject`: `ORDER BY seq DESC`. Probe:
   `probe_a_backwards_clock_hides_an_outstanding_partial`.
6. **CIPHER-16 / QUESTIONS #15 (MEDIUM)** — make `ShreddedBytesConverter` work under IDENTITY; add
   the `Blob` fixture and its round-trip regression test under IDENTITY and SEQUENCE; drop the
   "not production-ready" language.
7. **L11** — fix `lockSubject`'s namespace claim (two-argument lock, or correct the comment); use
   the length-prefixed canonical form for the lock string.
8. **L12** — `SubjectExpression.evaluate` refuses a non-scalar resolved value and an identity-hash
   string. Probe: `probe_a_subject_expression_resolving_to_an_identity_hash_is_refused`.
9. **L13** — `pom.xml:280`.
10. **L14** — `LogScanTest` asserts the capture is non-empty first.

### Not verified

- **Multi-node behaviour.** Everything here ran against a single Testcontainers PostgreSQL and one
  JVM. The advisory-lock ordering argument is a reading of the code plus the single-node probes; I
  did not run two application instances against one database.
- **The `SEQUENCE` half of CIPHER-16.** I reproduced the IDENTITY failure only; whether `SEQUENCE`
  is also affected is a question for the fix's own test, which is why it is in the fix text.
- **`@DynamicUpdate`.** No entity in this repository uses it, so QUESTIONS #14's reasoning about it
  is unexercised in both directions.
