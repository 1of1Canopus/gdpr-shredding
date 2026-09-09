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

---

## Third pass (8095d2c)

*2026-09-09. Branch `feat/shredding-core`, HEAD `8095d2c`, draft PR #1. Docker up; every test in this
section ran against a real Testcontainers PostgreSQL. No test was skipped.*

### Verdict

**NOT MERGEABLE.**

CIPHER-11 is closed for the shape it was reported in — a projection run straight off an
`EntityManager` — and open for every other shape of the same attack. The read bracket introduced to
close it is an *unconditional permission granted by the caller's identity* ("you are inside a Spring
Data repository call"), not a *proof that a verifier will run*. Four HIGH findings below are the same
root cause seen from four directions: a decrypt that takes the bracket branch and is never reached by
`onPostLoad` is returned to the caller with nothing having checked it. Three of the four leak a
different subject's plaintext across the module's own boundary, on code an ordinary user writes on
purpose (`@Query` projections, interface projections), not on code an attacker has to contrive.

The ten findings from the re-verification pass are otherwise genuinely closed, the numbers are
honest, and no probe was narrowed. The design is one control away from being right; it is not right
yet.

### Numbers

Full `./mvnw clean verify`, exit 0.

| Module | Tests | Fail | Err | Skip | Line coverage | Branch |
| --- | --- | --- | --- | --- | --- | --- |
| `gdpr-shredding-core` | 77 | 0 | 0 | 0 | **84.54 %** (979/1158) | 58.37 % |
| `gdpr-shredding-spring-boot-starter` | 40 | 0 | 0 | 0 | **85.16 %** (654/768) | 65.87 % |
| `gdpr-shredding-sample` | 17 | 0 | 0 | 0 | **66.32 %** (63/95) | 33.33 % |
| **Total** | **134** | **0** | **0** | **0** | | |

Isis's reported figures (134 tests: 77/40/17; 84.5 % / 85.2 % / 66.3 %) reproduce exactly from the
three `jacoco.csv` files. The sample module is below the 80 % gate by design (the gate is scoped to
the published artefacts), unchanged from the previous pass.

### Probes: none narrowed

`git diff dcae873..HEAD -- '*CipherProbe*'` touches two files, both **pure additions, zero
deletions**: `CipherProbeJdbcTest` (+57, `probe_a_backwards_clock_hides_an_outstanding_partial`) and
`CipherProbeSpelTest` (+29, `probe_a_subject_expression_resolving_to_an_identity_hash_is_refused`).
No probe method was removed, renamed, weakened or had an assertion relaxed. Every probe from the
first two passes runs unchanged and green.

### The ten prior findings, judged

| # | Sev | Ruling |
| --- | --- | --- |
| CIPHER-11 | HIGH | **Partially closed.** The reported repro (`select d.title from Doc d` off the `EntityManager`) is refused, and so are the `Tuple`, constructor-expression and Criteria variants — I re-ran all four. The *same projection declared on a repository* is not (C-17, C-18 below). |
| CIPHER-12 | HIGH | **Closed.** `onPostLoad` throws `SHRED-SUBJECT-UNRESOLVED` instead of returning when any shredded column decoded and the subject cannot be resolved. Verified in code and by the existing probe. |
| CIPHER-13 | MEDIUM | **Partially closed.** `clearAll()` now drops `READ_BRACKET_DEPTH`, `READ_SCOPES` and `DECODED_READS` at the transaction boundary, and `onPostLoad` drains every shredded field of the row up front. But the bracket created a new producer of undrained entries, and the original symptom is reproducible again inside one transaction (C-22 below). |
| CIPHER-14 | HIGH | **Closed.** `refuseIfSubjectMoved` reads every shredded column in one query and only early-returns when all are null; `ShreddedModel.scan` refuses a shredded entity spanning a secondary table. Verified in code. |
| CIPHER-15 | MEDIUM | **Closed.** `latestForSubject` is `ORDER BY seq DESC LIMIT 1`; the backwards-clock probe is green. |
| CIPHER-16 | MEDIUM | **Closed as reported, with a new trap it creates.** `byte[]` round-trips under both IDENTITY (`Blob`) and SEQUENCE (`BlobSeq`), and `@Immutable` is enforced at startup naming the field. See C-20 and C-21 for what that enforcement costs and what it does not cover. |
| L11 | LOW | Closed. |
| L12 | LOW | Closed; new probe green. |
| L13 | LOW | Closed. |
| L14 | LOW | Closed; `LogScanTest` asserts a non-empty capture first. |

### New findings

#### HIGH

##### C-17 — a repository `@Query` projection returns another subject's plaintext

The exact attack CIPHER-11 named, moved from an `EntityManager` to a repository method. The
`BeanPostProcessor` opens the read bracket for *any* method on *any* `Repository` bean, including one
whose `@Query` is a scalar projection. `convertToEntityAttribute` therefore takes branch 2 ("defer to
`onPostLoad`") — and `onPostLoad` never fires, because no entity was loaded. Nothing verifies, and
the value is returned.

*Repro.* Fixture `DocProjectionRepository extends Repository<Doc, Long>` with
`@Query("select d.title from Doc d where d.ownerId = :id") List<String> titlesOf(String id)`. Save a
`Doc` for alice with title `ALICE-SECRET-TITLE` and one for bob; `UPDATE doc SET title = <alice's
ciphertext> WHERE owner_id = <bob>`; call `projections.titlesOf(bob)`.

```
Expecting ["ALICE-SECRET-TITLE"] not to contain ["ALICE-SECRET-TITLE"] but found ["ALICE-SECRET-TITLE"]
```

Probe: `probe_a_repository_query_projection_returns_a_moved_ciphertext`.

##### C-18 — a Spring Data interface projection returns another subject's plaintext

Same mechanism, on the return type Spring Data's own documentation recommends for projections, and
with no `@Query` at all — a derived finder is enough.

*Repro.* `interface TitleView { String getTitle(); }` and
`List<TitleView> findByOwnerId(String id)` on the same repository, same moved row:

```
Expecting ["ALICE-IFACE-SECRET"] not to contain ["ALICE-IFACE-SECRET"] but found ["ALICE-IFACE-SECRET"]
```

Probe: `probe_a_repository_interface_projection_returns_a_moved_ciphertext`.

C-17 and C-18 generalise: *any* code that reaches a shredded converter while a repository call is on
the stack is unverified. A repository fragment implementation running a projection, a
`JdbcTemplate`/`JdbcClient` read that calls a converter by hand from inside a service that a
repository call is nested in, and an `EntityManager` projection issued inside a custom repository
method all inherit the same permission. Outside a repository call every one of those is refused
(`SHRED-READ-UNSCOPED`) — I confirmed the raw-`EntityManager` and Criteria cases. The bracket is the
only difference, and it proves nothing.

##### C-19 — a converter-mapped column with no field-level `@Shredded` is encrypted but never verified

`ShreddedModel.scan` finds shredded fields by walking `getDeclaredFields()` looking for `@Shredded`.
There is no reverse check: nothing asks the metamodel which attributes are actually mapped by a
`ShreddedConverter`. A column mapped through a class-level `@Convert(attributeName = "secret", …)`
(equally: an `orm.xml` `<convert>`) is therefore invisible to the model — while the write path still
encrypts it correctly, because the entity is in the model via a *different*, properly annotated
field, so `onPreInsert` pushes the scope for the whole state array.

The result is a column that is fully shredded, fully encrypted, and completely unprotected:
`onPostLoad` never drains or checks it (it is not in `fields`), the `@Immutable` check never sees it,
and neither does the second-level-cache or secondary-table refusal.

*Repro.* Fixture `Ledger` with `@Shredded note` (declared normally) and
`@Converts({@Convert(attributeName = "secret", converter = LedgerSecretConverter.class)})` on the
class for a `secret` column carrying no `@Shredded`. Application starts clean. Move alice's `secret`
ciphertext into bob's row, then `ledgers.findByOwnerId(bob)`:

```
Expecting ["ALICE-LEDGER-SECRET"] not to contain ["ALICE-LEDGER-SECRET"] but found ["ALICE-LEDGER-SECRET"]
```

Probe: `probe_a_class_level_convert_column_is_shredded_but_never_verified`.

This is also the answer to the second half of the `@Immutable` question: **yes, the startup
enforcement is bypassable.** Not by annotating a getter — a property-access entity with `@Shredded`
on the field is refused at startup for having no field-level `@Convert`, and one without `@Shredded`
is simply not a shredded field as far as the module is concerned — but by moving the `@Convert` to
the class or to XML, which takes the attribute out of the model entirely rather than only out of the
`byte[]` check.

##### C-20 — a second `EntityManagerFactory` has no listener, no startup scan, and still gets the bracket

`ShreddingIntegrator` is installed through a `HibernatePropertiesCustomizer` bean, which Spring Boot
applies only to the auto-configured `EntityManagerFactory`. A second, hand-built
`LocalContainerEntityManagerFactoryBean` — the ordinary multi-datasource shape — gets no
`PreInsert`/`PreUpdate`/`PostLoad` listener and its entities are never scanned. The converters still
run (they are mapping-level), and `ShreddingReadBracketCustomizer` still wraps its repositories,
because it keys on `instanceof Repository` and knows nothing about which factory a repository belongs
to. Every decrypt through that factory takes the bracket branch and is verified by nobody.

*Repro.* Build a second EMF over the same `DataSource` and the same `Doc` entity, then read the moved
row inside `ShreddingContext.withReadBracket(...)` — exactly what a repository bound to that factory
would do for the caller:

```
MATRIX2 second EMF read -> ALICE-EMF2-SECRET
```

Probe: `probe_a_second_entity_manager_factory_decrypts_a_moved_ciphertext`.

#### MEDIUM

##### C-21 — `@Immutable` on `byte[]` silently discards an in-place mutation

The module now *requires* `@org.hibernate.annotations.Immutable` on every shredded `byte[]` field and
refuses to start without it. That annotation is what stops `AttributeConverterMutabilityPlan` from
deep-copying the converted value — which is the whole point of the fix — but the same deep copy is
how Hibernate builds the dirty-checking snapshot. With the copy gone, the snapshot holds *the same
array reference* the entity holds, `PrimitiveByteArrayJavaType.areEqual` compares the array against
itself, and an in-place mutation is never dirty.

For an entity with no setter — which `Blob`, the module's own fixture, is, and which the module's
"immutable value objects" style encourages — in-place mutation is the *only* way to change the value,
and it is silently lost. No exception, no log line, no UPDATE.

*Repro.* Save a `Blob` with payload `{1,2,3,4}`; in a transaction, load it and set
`b.getPayload()[0] = 99`; commit; reload:

```
MATRIX @Immutable in-place mutation -> stored[0]=1
```

Probe: `probe_an_in_place_mutation_of_an_immutable_byte_array_is_persisted`.

Aggravating: the startup message that mandates the annotation tells the user *"`ShreddedBytesConverter`
already returns a fresh array from `toBytes`/`fromBytes`, so nothing shares state and the claim is
honest."* That is the opposite of what happens. The converter returning a fresh array is exactly what
makes the shared snapshot possible; state *is* shared, deliberately, and the user is told it is not.
The claim must be corrected wherever it appears.

##### C-22 — CIPHER-13's stale-decode bug is reproducible again, through the bracket

`convertToEntityAttribute` calls `recordDecoded` on every path, including the bracket path taken by a
repository projection — a path no `onPostLoad` will ever drain. The entry survives until the next
`clearAll()` at the transaction boundary. Inside that transaction, the next entity load of the same
`entity.field` whose column happens to be `NULL` drains the stale header and compares it against its
own row.

The visible symptom in this direction is a false refusal of legitimate data; the mirror direction is
worse in principle — a stale entry naming the right subject would let a genuinely moved value pass.

*Repro.* Alice's `Doc` has a title, bob's `Doc` has `title = NULL`. In one transaction, call
`projections.titlesOf(alice)` (records `Doc.title` for alice, nothing drains it), then
`docs.findByOwnerId(bob)`:

```
MATRIX stale-decode contamination -> SHRED-SUBJECT-MISMATCH
```

Bob's row is refused although nothing was ever done to it. Probe:
`probe_a_projection_decode_contaminates_a_later_rows_check`.

##### C-23 — supported repository return types and idiomatic DAOs are refused, with a message that misnames the cause

The bracket's lifetime is the repository method call, so anything lazy outlives it.

- A `Stream<Doc>`-returning repository method — a first-class Spring Data return type — fails on
  consumption with `SHRED-READ-UNSCOPED`, correctly refusing but with a message that tells the user
  they wrote "a scalar, `Tuple` or constructor-expression projection", which they did not.
  Probe: `probe_a_streaming_repository_method_still_decrypts`.
- A hand-written `@Repository` DAO holding an `@PersistenceContext EntityManager` — not a Spring Data
  `Repository`, so never proxied — is refused for an ordinary entity query.
- `EntityManager.find` and `getReference` are refused unless the caller wraps them in
  `withReadBracket`. This is the intended contract, and it is fail-closed, but **`withReadBracket`
  appears nowhere in `README.md` or `docs/`** — only in `SECURITY-NOTES.md`'s control table, and only
  as the error code. A mandatory API contract that the user meets an exception before they meet the
  documentation is not documented.

`Page`, `Slice`, `Streamable`, `Specification`, derived finders and `findById` all work (materialised
inside the call). A `nativeQuery` returning the raw column returns ciphertext, correctly.

#### LOW

- **C-24** — `ShreddingContext`'s javadoc, on the security-critical class, still names
  `ShreddingReadBracketRepositoryFactoryCustomizer`. That class does not exist; the mechanism was
  replaced by `ShreddingReadBracketCustomizer`. The same paragraph is the primary written explanation
  of the read design.
- **C-25** — `ShreddingReadBracketCustomizer` opens a bracket for `toString`, `equals` and `hashCode`
  on every repository bean, and implements no `Ordered`, leaving its position relative to any other
  post-processor that wraps `Repository` beans unspecified. It also replaces every repository bean
  with a JDK `Proxy` (`jdk.proxy2.$Proxy166` here), so `AopUtils`/`Advised` unwrapping in application
  code now sees an extra, non-Spring layer.

### Ruling: QUESTIONS #16

**The evidence is accepted; the mechanism is not. Prescribed instead.**

Two of the three claims in #16 stand and I am not asking for them again:

1. Shape (1) is genuinely unavailable. The `javap -c` reading of
   `EntityInitializerImpl.resolveEntityState` is correct and matches what I established for
   `onPostLoad` in the previous pass. No Hibernate hook fires before a row's own converters run. I
   withdraw the `PreLoadEventListener` half of the CIPHER-11 fix text.
2. Preferring a `BeanPostProcessor` over a `RepositoryFactoryCustomizer` that measurably does not
   fire is the right instinct, honestly recorded. Noting a deviation beats shipping a comment that
   claims a mechanism which does not run.

What I do not accept is what the bracket *is*. #16 describes it as marking "this decrypt is happening
inside something that will get `onPostLoad`'s verification afterwards; if it does not, refuse." The
code does the first half and not the second: there is no "if it does not". `pushReadBracket()` is a
depth counter, `inReadBracket()` returns true, the converter takes branch 2, and if `onPostLoad`
never comes, nothing notices. C-17 through C-20 are four ways to be inside the bracket and never
reach a verifier, and three of them return another subject's plaintext.

The fix is to make the bracket owe a debt rather than grant a permission, and to close the model's
one-directional scan:

1. **`ShreddingContext`: make the deferral accountable.** `pushReadBracket()` opens a frame.
   `recordDecoded` records into *that frame*, not into a flat map. `onPostLoad` drains the entries
   for the row it verifies. `popReadBracket()` must find the frame **empty**; any entry still in it
   is a decrypt that no verifier ever reached, and it throws `SHRED-READ-UNVERIFIED` from the pop —
   after the value was computed, but before the repository method returns it to the caller, which is
   the same "decrypt now, refuse before return" relaxation already accepted under QUESTIONS #13. This
   closes C-17, C-18, C-20 and C-22 with one change, and it makes the class's own javadoc true.
   Probes: the C-17, C-18, C-20 and C-22 probes above must all end in a refusal.
2. **`ShreddedModel.scan`: add the reverse check.** After the field scan, walk the
   `EntityManagerFactory`'s metamodel for every attribute whose JPA converter is a
   `ShreddedConverter`, and refuse to start on any that has no matching `@Shredded` entry, naming the
   entity and attribute and saying that `@Convert` must sit on the field beside `@Shredded`. Closes
   C-19 and the `@Immutable` bypass in one place. Probe:
   `probe_a_class_level_convert_column_is_shredded_but_never_verified` must fail at startup.
3. **`ShreddingReadBracketCustomizer`: bind the bracket to the factory it belongs to,** or refuse at
   startup when more than one `EntityManagerFactory` is present and the shredded entities are not all
   on the instrumented one. A bracket that cannot tell which Hibernate session it is vouching for
   cannot vouch for anything. Second half of C-20.
4. Keep `withRead` exactly as it is. It is the one branch that actually verifies, atomically, at
   decrypt time, and it is the model the rest should be measured against.

### Fix list for Isis

| # | Sev | What |
| --- | --- | --- |
| C-17 | HIGH | Bracket must account for undrained decodes; `popReadBracket` throws `SHRED-READ-UNVERIFIED`. Probe: `probe_a_repository_query_projection_returns_a_moved_ciphertext`. |
| C-18 | HIGH | Same fix. Probe: `probe_a_repository_interface_projection_returns_a_moved_ciphertext`. |
| C-19 | HIGH | `ShreddedModel.scan` reverse check against the metamodel's converters. Probe: `probe_a_class_level_convert_column_is_shredded_but_never_verified` (must fail at startup). |
| C-20 | HIGH | Bracket bound to the instrumented `EntityManagerFactory`, or a startup refusal. Probe: `probe_a_second_entity_manager_factory_decrypts_a_moved_ciphertext`. |
| C-21 | MEDIUM | Document the in-place-mutation trap on `@Shredded byte[]`, and correct the "nothing shares state and the claim is honest" sentence in `ShreddedModel` and anywhere it is repeated. Probe: `probe_an_in_place_mutation_of_an_immutable_byte_array_is_persisted`. |
| C-22 | MEDIUM | Falls out of C-17's frame accounting. Probe: `probe_a_projection_decode_contaminates_a_later_rows_check`. |
| C-23 | MEDIUM | `SHRED-READ-UNSCOPED`'s message must name the real cause; document `withReadBracket` in `README.md` and `docs/index.md` as the contract for `EntityManager` entity reads, `Stream` returns and hand-written DAOs. |
| C-24 | LOW | `ShreddingContext` javadoc: `ShreddingReadBracketRepositoryFactoryCustomizer` → `ShreddingReadBracketCustomizer`. |
| C-25 | LOW | Skip `Object` methods in the bracket proxy; give the `BeanPostProcessor` an explicit order. |

Probe sources for all of the above are in the third-pass working set and are handed to Isis with this
review; the fixtures they need are `DocProjectionRepository`, `DocMatrixRepository`, `Ledger`,
`LedgerRepository` and `Dao` in `…autoconfigure.fixture`.

### Attacks that found nothing

- Multi-row result sets. `PostLoadEvent` fires per row in this Hibernate, so two `Doc`s in one query
  with one carrying a moved ciphertext is refused in either ordering. `DECODED_READS`' single
  entry per `entity.field` is not overwritten across rows.
- `Page`, `Slice`, `Streamable`, `Specification`, derived finders, `findById`, `Optional` returns.
- `nativeQuery` returning the shredded column: the converter is not invoked; ciphertext is returned.
- Criteria API, entity and scalar-projection forms, off a bare `EntityManager`: both refused.
- `@Async` at the service layer around a repository call: the whole call runs on the async thread, so
  the thread-local bracket is correct there.
- Reading an entity after the transaction and bracket have closed: the row was fully hydrated and
  verified inside the bracket, so nothing decrypts late.
- Reactive repositories: absent from the module, correctly — a thread-local bracket could not survive
  a reactive pipeline, and nothing pretends otherwise.

### Not verified

- **`@Async` declared on a repository interface method itself.** Reasoned to be fail-closed (the
  bracket would be pushed and popped on the caller thread while the work runs on the pool thread),
  not reproduced. It is not a leak in either outcome.
- **Spring Data JDBC.** Not on the classpath; there is no shredded read path through it to attack.
- **Multi-node behaviour**, unchanged from the previous pass.

## Fourth pass (0ba0f6f)

*2026-09-09. Branch `feat/shredding-core`, HEAD `0ba0f6f`, draft PR #1. Docker up; every test in this
section ran against a real Testcontainers PostgreSQL. No test was skipped.*

### Verdict

**NOT MERGEABLE.**

C-17 through C-25 are closed *as they were reported*. Every third-pass probe is green, no probe was
narrowed, and the reverse metamodel scan, the `Object`-method skip, the explicit order and the
documentation are all real. The read bracket now genuinely owes a debt.

But the debt is filed under the wrong name. `ShreddingContext.recordDecoded` keys a frame entry by
`entityName + "." + fieldName` and nothing else — no row. Hibernate hydrates every row of a result
set before it fires the first `PostLoad` for that set, so in any query returning more than one row of
the same entity, each row's decode overwrites the previous row's under that one key, and the entry
that survives is verified against whichever row happens to drain first. Every other row in the set is
verified by nobody, and the frame is empty at `popReadBracket()`, so nothing notices.

That is C-17's own defect one level down: not "inside a bracket, therefore permitted", but "some row
was verified, therefore all of them were". It is not a contrived shape. It fires on
`repository.findAll()`.

### Numbers

Full `./mvnw clean verify`, exit 0.

| Module | Tests | Fail | Err | Skip | Line coverage | Branch |
| --- | --- | --- | --- | --- | --- | --- |
| `gdpr-shredding-core` | 77 | 0 | 0 | 0 | **84.54 %** (979/1158) | 58.37 % |
| `gdpr-shredding-spring-boot-starter` | 50 | 0 | 0 | 0 | **85.42 %** (715/837) | 66.67 % |
| `gdpr-shredding-sample` | 17 | 0 | 0 | 0 | 66.32 % (63/95) | 33.33 % |
| **Total** | **144** | **0** | **0** | **0** | | |

Isis's reported figures (144 tests: 77/50/17; 84.5 % / 85.4 %) reproduce exactly from the three
`jacoco.csv` files. The sample module is below the 80 % gate by design; the gate is scoped to the
published artefacts.

### Probes: none narrowed

`git diff 114dc4f..HEAD -- '*CipherProbe*'` touches four files — `CipherProbeMatrixTest`,
`CipherProbeMatrix2Test`, `CipherProbeReadScopeTest`, `CipherProbeReverseScanTest` — **854 insertions,
zero deletions**. All four are new; no probe from the first three passes was removed, renamed,
weakened or had an assertion relaxed. Seven new `probe_` methods, all green. Two of them are weak,
not narrowed: see C-30 and C-31.

### The nine prior findings, judged

| # | Sev | Ruling |
| --- | --- | --- |
| C-17 | HIGH | **Closed as reported.** The repository `@Query` projection is refused with `SHRED-READ-UNVERIFIED`, from `popReadBracket()`, before the list reaches the caller. Re-ran the probe. |
| C-18 | HIGH | **Closed as reported.** Same mechanism, same refusal, on the interface projection. |
| C-19 | HIGH | **Closed for the shape it was reported in, incomplete.** `refuseUnmodelledShreddedConverters` walks the mapping metamodel and refuses `Ledger.secret` at startup, naming the attribute. It walks top-level `BasicValuedModelPart` attributes only; an `@Embeddable` or `@ElementCollection` is not one. See C-29. |
| C-20 | HIGH | **Closed, on the frame accounting, as QUESTIONS #17 says.** The second-EMF probe is green. Its closure is inherited from the frame, so it inherits C-26 with it. |
| C-21 | MEDIUM | **Closed.** The `ShreddedModel` startup message no longer claims "nothing shares state"; it names the in-place-mutation trap and the assign-a-new-array rule. `README.md`, `docs/index.md` and `SECURITY-NOTES.md` repeat it. See the ruling on QUESTIONS #18. |
| C-22 | MEDIUM | **Closed across repository calls, reopened inside one result set.** Each call gets its own frame, so alice's refused projection no longer contaminates bob's separate call — the probe proves it. Within a single frame the flat `entity.field` key is unchanged, and that is C-26. |
| C-23 | MEDIUM | **Closed.** `SHRED-READ-UNSCOPED`'s message now names the four real causes including the `Stream` case; `withReadBracket` appears in `README.md` and `docs/index.md`, twice each. |
| C-24 | LOW | **Closed.** The phantom class name survives only in `CHANGELOG.md` and in this document's own history, where it belongs. |
| C-25 | LOW | **Closed.** `Object` methods bypass the bracket entirely; `getOrder()` returns `LOWEST_PRECEDENCE` with the reasoning written down. |

### New findings

#### HIGH

##### C-26 — the frame is keyed by `entity.field`, so one row's verification stands in for every row's

`ShreddingContext.recordDecoded(entity + "." + field, …)` writes into a `HashMap` whose key carries no
row identity. `ShreddingEventListener.onPostLoad` drains by the same key. In Hibernate ORM 7.4 the
`PostLoad` callbacks for a query are deferred until the whole `JdbcValues` result set has been
processed, so the ordering in a two-row query is: hydrate row 1 (converter records), hydrate row 2
(converter **overwrites**), `onPostLoad(row 1)`, `onPostLoad(row 2)`. One entry exists for two rows.
The first row to drain takes it; the second finds nothing, and `onPostLoad`'s
`if (decodedByField.isEmpty()) return;` treats "nothing recorded" as "nothing was decrypted" — which,
after the overwrite, is false.

This is the same value that made `Doc` look safe in the third pass: `Doc` has two shredded fields, so
the *other* field's collision throws first and the row looks refused. An entity with one shredded
field has nothing to catch it.

*Repro, the leak.* `Widget` (one `@Shredded` field). Save alice with `ALICE-FRAME-SECRET` and bob with
`bob name`; `UPDATE widget SET name = <alice's ciphertext> WHERE owner_id = <bob>`; then an ordinary
`widgets.findAll(Sort.by("ownerId"))`. Alice sorts first, drains the surviving entry, and it is her own
header, so she passes. Bob drains nothing and is never checked:

```
FRAME F1 multi-row single-shredded-field -> RETURNED [ALICE-FRAME-SECRET, ALICE-FRAME-SECRET]
```

No exception. The moved plaintext is returned to the caller, twice.

Probe: `probe_a_moved_ciphertext_in_a_second_row_of_one_result_set`.

*Repro, the mirror.* The same defect with honest data refuses honest data. Two `Widget` rows, two
subjects, nothing moved, one `findAll(Sort.by("ownerId"))`:

```
FRAME F6 legitimate two-subject read -> REFUSED SHRED-SUBJECT-MISMATCH
```

Alice's row drains bob's header and is refused for a mismatch that is an artefact of the map. **Any
list query spanning more than one data subject throws.** That is every admin screen, every export,
every report in a multi-tenant application. No existing test covers it, which is why CI is green.

Probe: `probe_two_rows_of_two_subjects_read_in_one_query`.

*Fix.* A decode must be correlated to the row it came from; `entity.field` is not a row identity and a
count is not either (two rows of one result set swapping their ciphertexts would balance). The
converter genuinely cannot know its row — that part of QUESTIONS #16 stands. So stop trying to carry
the answer across from the converter, and have the verifier fetch it: in `onPostLoad`, for the entity
being loaded, re-read that row's own shredded columns by `event.getId()` and decode the headers, the
way `refuseIfSubjectMoved` already does on the write path (public header only, no key material, one
`SELECT` per loaded row of a shredded entity). Compare those headers against the row's resolved
subject and tenant. Keep the frame, but reduce it to what it can honestly do — *count* decodes and
require the count to reach zero — so a decrypt no `onPostLoad` ever ran for is still refused by
`popReadBracket()`, which is what closes C-17, C-18 and C-20. If you would rather not pay a `SELECT`
per row, propose the alternative with a probe; I will review it, but I will not accept a thread-local
correlation that cannot name a row.

Probes that must end green: the two above, plus every C-17/C-18/C-20/C-22 probe unchanged.

##### C-27 — a row refused by `onPostLoad` stays in the persistence context and is returned on the next read

`onPostLoad` throws *after* Hibernate has registered the fully hydrated entity — decrypted shredded
fields and all — in the session's first-level cache. The exception aborts the load in progress. It
does not remove the instance. The next read of that row in the same transaction is a cache hit: no
SQL, no converter, no `PostLoad`, an empty frame, and the entity is handed over intact.

The bracket proxy's `discardReadBracket()` on the exceptional path is correct as far as the frame
goes, and it is also what makes this silent: the aborted call leaves no debt behind.

*Repro.* Alice's `Widget` ciphertext moved into bob's row. In one transaction, call
`widgets.findByOwnerId(bob)` — refused — catch it, then call `widgets.findById(bobId)`:

```
FRAME F2 first-level-cache retry -> first=[REFUSED SHRED-SUBJECT-MISMATCH] second=[RETURNED ALICE-L1-SECRET]
```

A `try`/`catch` around a repository call is not an exotic thing to write. Neither is a service that
falls back to `findById` when a finder refuses.

Probe: `probe_a_refused_row_is_returned_on_the_retry_from_the_persistence_context`.

*Fix.* Before `onPostLoad` throws, evict the offending instance from the session's persistence context
(`event.getSession().getPersistenceContextInternal().removeEntityHolder(...)` / `evict`) so no
first-level-cache hit can serve it, and mark the transaction rollback-only so the poisoned session
cannot be reused for anything else. A refusal that only holds until the caller asks a second time is
not a refusal. Probe: the one above, with `second=` refused or empty.

#### MEDIUM

##### C-29 — the reverse metamodel scan does not walk `@Embeddable` or `@ElementCollection` attributes

`refuseUnmodelledShreddedConverters` iterates `persister.getAttributeMappings()` and returns early on
anything that is not a `BasicValuedModelPart`. An `@Embedded` component is an
`EmbeddableValuedModelPart` and an `@ElementCollection` is a `PluralAttributeMapping`; the shredded
converters mapped inside either are never inspected. The forward scan cannot see them either —
`allFields` walks the entity class and its superclasses, not its components — so a `@Shredded` field
declared inside an `@Embeddable` is invisible to the module in both directions. (`@MappedSuperclass` is
fine: `allFields` walks superclasses. A `@Converter(autoApply = true)` `ShreddedConverter` is fine in
the other direction: it attaches to top-level basic attributes, which the reverse scan does see, and
is refused at startup.)

*Repro.* `Vault` with a properly declared `@Shredded label` and an `@Embedded Secrets` holding a
`@Shredded @Convert token`:

```
EMBED -> STARTED / WROTE / READ-REFUSED SHRED-READ-UNVERIFIED
```

The application starts. The token column is encrypted correctly. It can never be read back, and the
error the developer meets says a verifier was never reached — true, but it names the bracket rather
than the mapping they actually got wrong.

Fail-closed, and only by accident: the sole reason this is a refusal and not a C-19-shaped leak is
that the frame is non-empty at `popReadBracket()`. **The C-26 fix must not lose that.** If the frame
is reduced to a counter, the counter must still be non-zero here.

Probe: `probe_a_shredded_field_inside_an_embeddable` (must fail at startup, naming
`Vault.secrets.token`).

*Fix.* Recurse into `EmbeddableValuedModelPart` and `PluralAttributeMapping` in
`refuseUnmodelledShreddedConverters`, and refuse at startup with the C-19 message extended: a
`@Shredded` field inside a component or an element collection is not supported, because the subject
expression, the `@Immutable` check, the secondary-table check and `onPostLoad`'s field list are all
built from the entity's own declared fields.

#### LOW

- **C-30** — `probe_a_second_row_in_the_same_result_set_is_never_verified` asserts only
  `assertThat(shreddingCode(t)).isNotBlank()`. It is the probe for the exact bug C-26 describes, it
  runs on `Doc` (two shredded fields), and it passes on `Doc.body`'s collision throwing
  `SHRED-SUBJECT-MISMATCH` while `Doc.title` — the field the probe moved — was never checked at all.
  A probe that green-lights the bug it is named for is worse than no probe. Assert the specific error
  code, and make the fixture single-shredded-field so nothing else can throw first.
- **C-31** — `probe_an_in_place_mutation_of_an_immutable_byte_array_is_persisted` asserts
  `isEqualTo((byte) 1)`, i.e. that the mutation is **lost**. The assertion is right (see the ruling on
  QUESTIONS #18); the name is the opposite of it. Rename it
  `probe_an_in_place_mutation_of_an_immutable_byte_array_is_silently_discarded`. Isis was right not to
  rename a probe Cipher named; this is the instruction.
- **C-32** — `ShreddingContext.withReadBracket` catches `RuntimeException` only. An `Error` thrown by
  the body — `StackOverflowError` from a deep object graph, an `AssertionError` from application
  code — unwinds past both `discardReadBracket()` and `popReadBracket()` and leaves the frame on the
  thread for whatever the pool hands it next. The proxy's own `Bracket.invoke` gets this right
  (`catch (Throwable t)`); the public API does not. Use `try`/`finally` with an explicit
  "threw?" flag, or catch `Throwable`.

#### Not verified

- **A lazy basic attribute.** `@Basic(fetch = LAZY)` on a shredded column is inert without Hibernate's
  bytecode enhancement, and no enhancement plugin is configured in any of the three POMs, so there is
  no path here to attack. In an application that does enable enhancement, the column would be fetched
  on first getter access, which for an entity returned out of a repository call is after the bracket
  closed: reasoned to be `SHRED-READ-UNSCOPED`, i.e. fail-closed, but not reproduced. It belongs in the
  documented residuals either way — the module should say that shredded fields must not be mapped
  lazily.
- **Multi-node behaviour**, unchanged from every previous pass.

### Attacks that found nothing

- Nested brackets. An outer frame's undrained decode survives an inner repository call opening and
  cleanly closing its own frame, and the outer `popReadBracket()` still refuses
  (`probe_a_nested_repository_call_does_not_absolve_the_outer_frames_debt`). A decode is filed to the
  frame on top of the stack at the moment it happens, which is the right frame in both directions:
  the wrong-frame cases fail closed with `SHRED-READ-UNVERIFIED`, never open.
- Two entity types sharing a field name, or two entities sharing an id value. The frame key carries the
  entity name, so `Doc.title` and `Widget.title` cannot collide. Only same-entity rows collide, which
  is C-26.
- Empty results. `findByOwnerId` with no match, `findById` on a missing id, an empty `Optional`: no
  decode, a trivially clean frame, no refusal (`probe_empty_results_are_not_refused`).
- `@Transactional(readOnly = true)` with `FlushMode.MANUAL`. A moved ciphertext is still refused
  (`SHRED-SUBJECT-MISMATCH`); nothing about the read path depends on the flush mode.
- `@MappedSuperclass` and `@Converter(autoApply = true)`, both covered above.
- The `Object`-method skip. `toString`, `equals` and `hashCode` on a repository bean no longer open a
  frame, and no shredded converter is reachable from any of them.

### Ruling: QUESTIONS #17 — accepted

The evidence is correct and I verified it independently rather than taking it on trust:
`javap -v` on `org.springframework.boot.jpa.autoconfigure.JpaBaseConfiguration` shows
`entityManagerFactory(...)` annotated `@Bean`, `@Primary`, and
`@ConditionalOnMissingBean(value = [LocalContainerEntityManagerFactoryBean.class,
EntityManagerFactory.class])`. Declaring a second factory bean the ordinary way does suppress the
auto-configured, instrumented one instead of coexisting with it, so the shape
`CipherProbeSecondEmfStartupTest` was written to construct cannot be constructed through ordinary
auto-configuration. Deleting the test rather than committing it failing or `@Disabled` is the right
call, and recording why in QUESTIONS.md is exactly what that file is for.

The check stays as a safety rail; it is reachable in the one wiring that matters (a context that
excludes `HibernateJpaAutoConfiguration` and hand-rolls two factories) and it costs nothing. C-20 is
closed on the frame accounting, as claimed — and therefore reopens with C-26, which is a comment on my
own prescription, not on this deviation.

### Ruling: QUESTIONS #18 — the rewrite is legitimate, not a narrowing

My own third-pass fix list for C-21 was documentation only, and the third-pass text says in as many
words that making the mutation persist would reintroduce CIPHER-16. A probe asserting
`reloaded[0] == 99` therefore asserts a behaviour I had already ruled must not exist. It could never
have gone green, and Isis is right that fixing the documentation and passing that probe as written are
mutually exclusive.

A narrowing is an assertion weakened to stop protecting a property that was being protected. This
assertion protects nothing — it characterises an accepted, documented residual, and the direction it
now asserts is the direction the corrected documentation promises. The security-relevant half of C-21
is the text, and the text is verifiably corrected in `ShreddedModel`, `README.md`, `docs/index.md` and
`SECURITY-NOTES.md`.

The name is a separate problem and it is mine: I named the probe. C-31 above is the instruction to
rename it.

### Fix list for Isis

| # | Sev | What |
| --- | --- | --- |
| C-26 | HIGH | The frame's key carries no row identity. Verify each row's headers per row — re-read the row's shredded columns by id in `onPostLoad`, the way `refuseIfSubjectMoved` does — and reduce the frame to a drain count that must reach zero. Probes: `probe_a_moved_ciphertext_in_a_second_row_of_one_result_set`, `probe_two_rows_of_two_subjects_read_in_one_query`, and every C-17/C-18/C-20/C-22 probe still green. |
| C-27 | HIGH | Evict the refused instance from the persistence context and mark the transaction rollback-only before `onPostLoad` throws. Probe: `probe_a_refused_row_is_returned_on_the_retry_from_the_persistence_context`. |
| C-29 | MEDIUM | Recurse into `EmbeddableValuedModelPart` and `PluralAttributeMapping` in `refuseUnmodelledShreddedConverters`; refuse `@Shredded` inside a component or element collection at startup. Probe: `probe_a_shredded_field_inside_an_embeddable`. |
| C-30 | LOW | `probe_a_second_row_in_the_same_result_set_is_never_verified`: assert the specific error code, on a single-shredded-field fixture. |
| C-31 | LOW | Rename `probe_an_in_place_mutation_of_an_immutable_byte_array_is_persisted` to `..._is_silently_discarded`. |
| C-32 | LOW | `ShreddingContext.withReadBracket` must unwind the frame on `Throwable`, not only `RuntimeException`. |
| — | INFO | Document that a `@Shredded` field must not be mapped `@Basic(fetch = LAZY)`, and that bytecode enhancement is untested against this module. |

Probe sources for C-26, C-27 and C-29 are `CipherProbeFrameTest`, `CipherProbeEmbeddableScanTest` and
the `…autoconfigure.embed` fixture package, handed to Isis with this review.

---

## Fifth pass (2f72449): NOT MERGEABLE

Cipher, 2026-09-09. Branch `feat/shredding-core`, HEAD `2f72449`, draft PR #1.
Two HIGH findings are open, so the no-allowance rule gives exactly one verdict.

### Build

`./mvnw clean verify`, exit 0, Docker up, Testcontainers Postgres pinned by digest. No skipped tests.

| Module | Tests | Failures | Skipped | JaCoCo LINE (from `jacoco.csv`) | Gate |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gdpr-shredding-core` | 77 | 0 | 0 | 84.54 % (979 / 1158) | 80 % |
| `gdpr-shredding-spring-boot-starter` | 58 | 0 | 0 | 85.45 % (752 / 880) | 80 % |
| `gdpr-shredding-sample` | 17 | 0 | 0 | 66.32 % (63 / 95) | 30 % |
| **Total** | **152** | **0** | **0** | | |

Every existing `CipherProbe*` test ran unchanged and green: 39 in the starter, the core's
`CipherProbeAadTest`, `CipherProbeBlindIndexTest`, `CipherProbeFormatTest`, `CipherProbeErasureTest`,
`CipherProbeFieldCipherTest`, `CipherProbeJdbcTest`, and the sample's `CipherProbeActuatorEndToEndTest`.

**Probe diff against `c065cc8`.** No probe method was removed and none was narrowed. Two were changed:
`probe_an_in_place_mutation_of_an_immutable_byte_array_is_persisted` was renamed to
`..._is_silently_discarded` (C-31, body unchanged), and
`probe_a_second_row_in_the_same_result_set_is_never_verified` was moved from `Doc` to `Widget` and its
assertion tightened from `isNotBlank()` to `isEqualTo(ErrorCodes.SUBJECT_MISMATCH)` (C-30). Both are
strengthenings. Eight probe methods were added.

### The nine from the fourth pass

| # | Verified | How |
| --- | --- | --- |
| C-26 | closed | `probe_a_moved_ciphertext_in_a_second_row_of_one_result_set` and `probe_two_rows_of_two_subjects_read_in_one_query` green; the multiset re-key and the per-row re-read are in `ShreddingContext.FrameKey` / `ShreddingEventListener.onPostLoad`. Attacked further below. |
| C-26 mirror | closed | The legitimate two-subject read no longer refuses (F6, asserting each row's own value, not merely "no exception"). |
| C-27 | closed, with the deviation accepted | `refuseLoad` evicts. I attacked the eviction from the one angle the dropped rollback-only mark leaves open — an instance already referenced elsewhere in the session — and it held (C-36 below, not reproduced). |
| C-29 | closed, and deeper than asked | `probe_a_shredded_field_inside_an_embeddable` and `..._element_collection_of_embeddables` green. I added two levels of nesting and an `@ElementCollection` of *basic* values: both refused at startup (`SHRED-CONFIG-001`, naming `DeepVault.outer.inner.token` and `TagBag.tags[]`). One recursion path is still not walked — C-37. |
| C-30 | closed | Rewritten on `Widget`, asserts `SHRED-SUBJECT-MISMATCH`. |
| C-31 | closed | Renamed. |
| C-32 | **not closed** | The `try`/`finally` on `Throwable` does not survive the one `Error` the fix's own javadoc names. C-39/C-40/C-41. |

### New findings

| # | Sev | Owner | What |
| --- | --- | --- | --- |
| C-33 | HIGH | **DESIGN STOP (Thor)** | A transaction that writes a shredded entity and completes inside an open read bracket erases that bracket's debt, and an unverified decrypt is returned. |
| C-39 | HIGH | **DESIGN STOP (Thor)** | A `StackOverflowError` inside nested read brackets leaves frames on the thread; the next call on that pooled thread decrypts unverified. |
| C-40 | HIGH | **DESIGN STOP (Thor)** | The same for the read-scope stack: a caller's vouched-for `(tenant, subject)` survives onto the next call. |
| C-41 | MEDIUM | **DESIGN STOP (Thor)** | The same for the write-scope stack: the next write encrypts under the previous subject. |
| C-34 | MEDIUM | **DESIGN STOP (Thor)** | A ciphertext swapped between two rows of the *same* subject is undetected and displayed. `SECURITY-NOTES.md` claims "moved between rows" is stopped. |
| C-35 | LOW | **DESIGN STOP (Thor)** | The per-row re-read is one extra `SELECT` per loaded row: 200 rows cost 200 extra by-id queries, caller-controlled. |
| C-37 | LOW | correction (Isis) | The reverse scan never walks `PluralAttributeMapping.getIndexDescriptor()`: a `ShreddedConverter` on a map key starts up unrefused. |
| C-38 | LOW | correction (Isis) | A composite-id `@Shredded` entity starts up and is then unreadable. It must be refused at boot. |

C-33, C-39, C-40 and C-41 are one design stop, not four: they are the same question — who owns
`ShreddingContext`'s thread-local state and what is allowed to clear it — and prescribing four
separate patches for it is what produced rounds two to four on this module.

---

#### C-33 — HIGH — a transaction completing inside a read bracket erases its debt

**Repro.** `CipherProbeFifthPassTest.probe_a_transaction_committing_inside_a_read_bracket_does_not_erase_its_debt`
(`src/test-pending`). Output:

```
P1 clearAll vs open bracket -> RETURNED [P1-CLEARALL-SECRET]
```

`ShreddingEventListener.registerTransactionBoundaryClear` registers `ShreddingContext.clearAll()` as
an after-completion callback on every insert and update of a shredded entity, and `clearAll()` does
`READ_FRAMES.remove()` — it drops the *whole* frame stack for the thread, including frames belonging
to brackets that are still open and whose owner will still call `popReadBracket()`. `popFrame()` then
returns `null` and `popReadBracket()` passes silently.

`ShreddingReadBracketCustomizer` is a `BeanPostProcessor` at `LOWEST_PRECEDENCE`, so it runs last and
its proxy wraps the transactional proxy: for every repository call that is not already inside a
caller's transaction, the transaction begins and commits *inside* the bracket. The bracket is the
outer layer, not the inner one its own javadoc claims.

This is `CipherProbeFrameTest` F3's shape — an unverified projection decode inside `withReadBracket`
that nothing drains, which F3 asserts must be refused with `SHRED-READ-UNVERIFIED` — with one
addition: a write in the same transaction. F3 stays green; the probe above returns the plaintext.

This is the control from C-17, C-18 and C-20, and it is switchable off by any write. It also removes
the only thing standing between the read path and a read-committed TOCTOU: `onPostLoad`'s re-read is
a *second* statement, so under PostgreSQL's default `READ COMMITTED` it can see bytes that are not
the bytes the converter decrypted. Today that is fail-closed — the drain key is built from the
re-read's header and the record key from the decrypted bytes' header, so they miss each other and the
frame stays dirty — but that safety is exactly the accounting C-33 wipes out.

**Property that must hold.** A read bracket that is still open survives every transaction completion
on its thread; a bracket abandoned by a thread that will never pop it does not survive the request.

**Paths it must cover.** `ShreddingReadBracketCustomizer.Bracket#invoke`; `withReadBracket`; `withRead`;
the `AfterCompletionCallback` registered from `onPreInsert`/`onPreUpdate`; nested brackets; and thread
reuse — servlet pool, virtual threads, `@Async`, and a `Stream`-returning repository method.

---

#### C-39 / C-40 / C-41 — HIGH, HIGH, MEDIUM — thread-local state survives a `StackOverflowError`

**Repro.** `CipherProbeBracketUnwindTest`, three probes, 200 attempts each on a fresh 256 KB-stack
thread. Stable across runs:

```
UNWIND read bracket -> leaked on  10/200 unwinds
UNWIND read scope   -> leaked on  35/200 unwinds
UNWIND write scope  -> leaked on  13/200 unwinds
```

(In isolation, with the JIT differently warmed: 26/40, 33–36/40, 39/40.)

C-32's fix is `try`/`finally` with a `threw` flag. A `finally` block does not survive a
`StackOverflowError`: it has to *call* `discardReadBracket()` / `pop()`, and at the depths where the
stack is already exhausted that call throws a second `StackOverflowError` which replaces the first and
skips the cleanup. `ShreddingReadBracketCustomizer.Bracket#invoke`'s `catch (Throwable)` has the same
weakness for the same reason. The shape that produces it is nested brackets — a recursive repository
traversal, one bracket per level, all still open when the stack runs out — which is ordinary code, and
it is the "deep object graph" case C-32's javadoc names.

What each leak costs on a pooled thread:

- **C-39, a leaked frame.** `ShreddedConverter` sees `inReadBracket()` true, treats the decrypt as
  "inside a managed entity load", defers verification to an `onPostLoad` that will never run for a
  projection, and returns the plaintext where it should have thrown `SHRED-READ-UNSCOPED`.
- **C-40, a leaked read scope.** Worse: `withRead` takes a caller-supplied `(tenant, subject)` on
  trust — it is a vouch, not an authentication. A leaked one turns the next call's projection over
  that subject's rows from a refusal into a decrypt-and-return.
- **C-41, a leaked write scope.** `ShreddingContext.require` hands a converter the stale scope
  instead of throwing `SHRED-CONTEXT-001`, so the next write encrypts under the previous subject's
  key and the row lands in the wrong subject's erasure scope. The transaction-completion `clearAll()`
  backstop covers the listener path when a transaction exists and completes on this thread; it does
  not cover `ShreddingContext.with(...)`, which is public API and is what the erasure endpoint uses.

**Property that must hold.** No `ShreddingContext` thread-local entry outlives the call that created
it, on any completion path, including an `Error` raised at a depth where no further method call can be
made.

**Paths it must cover.** The same list as C-33, plus `ShreddingContext.with` and `ShreddingContext.push`
/`pop` as called from `onPreInsert` / `onPreUpdate`.

---

#### C-34 — MEDIUM — a ciphertext swapped between two rows of one subject is displayed

**Repro.** `CipherProbeFifthPassTest.probe_a_ciphertext_swapped_between_two_rows_of_one_subject_is_detected`.
Two `Widget` rows of one owner, row A's `name` column copied over row B's:

```
P2 same-subject row swap -> RETURNED [ROW-A-VALUE, ROW-A-VALUE]
```

The AAD and the stored header bind `(tenant, subject, entity, field)` and no row identity, and
`onPostLoad`'s per-row re-read compares the row's stored header against the row's *resolved subject
and tenant* only. Two rows of the same subject therefore have interchangeable ciphertexts: both
headers match, and the multiset drains a count of two cleanly. Row B displays row A's value as its
own, with no error anywhere and nothing in any log.

Erasure scope is unaffected — it is the same subject's key — so this is an integrity failure, not a
confidentiality one. But `SECURITY-NOTES.md`'s threat table says *"A ciphertext moved between rows,
subjects or tenants displayed on read … the row's stored header is checked against the row"*, and
`docs/index.md` says the same of `SHRED-SUBJECT-MISMATCH`. Between subjects and between tenants: true.
Between rows: not true. Under the no-allowance rule the gap between the claim and the code closes one
way or the other, and which way is a design decision, not a patch.

**Property that must hold.** Either a stored value verifies against the row it was read from, or the
documentation states plainly that intra-subject row integrity is out of scope and the threat table
stops claiming "between rows".

**Paths it must cover.** If the answer is to bind row identity: the AAD, the header format, `onPostLoad`,
`refuseIfSubjectMoved`, `withRead`, and the erasure path — and note that the branch is unreleased, so
no compatibility with the current format is owed.

---

#### C-35 — LOW — one extra query per loaded row

**Repro.** `CipherProbeFifthPassTest.probe_a_multi_row_read_does_not_issue_one_extra_query_per_row`,
counting `Connection.prepareStatement` on the application's own `DataSource` (not timings, not
PostgreSQL's asynchronous statistics collector):

```
P3 per-row re-read cost -> 200 rows, 401 statements prepared,
                           200 of them a per-row shredded-column re-read
```

`onPostLoad` calls `readStoredShreddedColumns` once per loaded row of every shredded entity. A page of
N rows costs N+1 round trips instead of 1, and the multiplier is whatever page size the caller asks
for. It is on the read path of every shredded entity, unconditionally.

**Property that must hold.** Verifying a result set costs a number of round trips bounded independently
of the number of rows in it.

**Paths it must cover.** `onPostLoad` for a list, a page, a lazy collection load and a nested eager
association; `refuseIfSubjectMoved` on a batched flush.

---

#### C-37 — LOW — correction (Isis) — the reverse scan does not walk a collection's index

**Repro.** `CipherProbeScanDepthTest.probe_a_shredded_map_key_in_an_element_collection_is_refused_at_startup`,
fixture `…autoconfigure.mapkey.KeyedNotes` (`@ElementCollection Map<String,String>` with
`@Convert(attributeName = "key", converter = NoteKeyConverter.class)`):

```
SCAN-DEPTH mapkey -> STARTED (nothing refused it)
```

`ShreddedModel.scanAttribute` handles a `PluralAttributeMapping` by walking `getElementDescriptor()`
only. `getIndexDescriptor()` — the map key, and the list index of an `@OrderColumn` — is never walked,
so a `ShreddedConverter` reached that way is neither modelled by the forward field scan nor refused by
the reverse one. It is not a leak: the first write fails closed with `SHRED-CONTEXT-001`
(`no shredding context while writing KeyedNotes.notesKey`), and a read would leave the frame dirty. It
is the startup contract not holding — the application finds out in production instead of at boot.

**Fix.** In `ShreddedModel.scanAttribute`, in the `PluralAttributeMapping` branch, also
`scanAttribute(entityName, path + "[key]", plural.getIndexDescriptor(), known)` when the index
descriptor is non-null. Probe named above; move it from `src/test-pending` to `src/test` when green.

---

#### C-38 — LOW — correction (Isis) — a composite-id shredded entity starts and is then unreadable

**Repro.** `CipherProbeCompositeIdTest`, fixture `…autoconfigure.composite.Ticket` (`@IdClass`):

```
COMPOSITE untampered read -> REFUSED SHRED-READ-UNVERIFIED
COMPOSITE read            -> REFUSED SHRED-READ-UNVERIFIED
```

The first line is a row this application wrote itself, with nothing tampered. Both `onPostLoad` and
`refuseIfSubjectMoved` return early when `getIdentifierColumnNames().length != 1`, so `onPostLoad`
never drains, the frame stays dirty, and every read of a composite-id shredded row that carries a
stored value is refused. Writes go the same way, because `save`'s merge has to read first. The mapping
is fail-closed and unusable.

That is the right outcome and the wrong time. The startup scan already refuses a `@Shredded` entity
whose fields span a `@SecondaryTable`, for exactly this reason ("cannot be checked that way and is
refused rather than silently skipped"). A composite identifier is the same class of unsupported
mapping and belongs in the same check.

**Fix.** In `ShreddedModel.from`, for every entity with at least one `@Shredded` field, refuse at
startup when the entity's identifier maps to more than one column, with a message naming the entity and
saying that the update-time subject-immutability check and the load-time per-row re-read both bind a
single-column id. Probe: `probe_a_composite_id_shredded_entity_is_refused_at_startup`, which asserts
the read succeeds — it will never run once the context correctly refuses to start, which is the point;
rewrite it as a startup-refusal probe in the shape of `CipherProbeScanDepthTest` when fixing.

---

### What I attacked and did not reproduce

- **C-36, eviction versus an instance referenced elsewhere in the session.** `refuseLoad` evicts the
  refused entity, but eviction removes the session's own entry, not a Java reference another managed
  instance already holds. I built `…autoconfigure.assoc.Holder`, a non-shredded entity with an eager
  `@ManyToOne Widget`, loaded it so the tampered `Widget` hydrated inside the same query, caught the
  refusal, and went back for the `Holder` three ways in the same session. All three refused:
  `first=[REFUSED SHRED-SUBJECT-MISMATCH] second=[REFUSED SHRED-READ-UNSCOPED]
  third=[REFUSED SHRED-SUBJECT-MISMATCH] commit=[UnexpectedRollbackException]`. Hibernate does not
  leave the `Holder` in the persistence context when a load aborts, so there is no surviving reference
  to reach. Closed with no code change. `CipherProbeEvictionTest` is green and is worth keeping as a
  positive control.
- **The `READ COMMITTED` TOCTOU on the per-row re-read.** The re-read runs through
  `session.doReturningWork`, on the session's own connection, inside the same transaction — but as a
  second statement, so under PostgreSQL's default isolation it can see bytes the converter did not
  decrypt. It is fail-closed by construction: the record key comes from the decrypted bytes' header and
  the drain key from the re-read's header, so a substitution between the two leaves the frame dirty and
  `popReadBracket()` refuses. That argument depends entirely on the frame accounting, which is what
  C-33 disables. Not a separate finding; a reason C-33 is HIGH.
- **A row whose id the entity does not expose.** `onPostLoad` takes the id from `PostLoadEvent.getId()`,
  never from a getter, so there is no entity-shape bypass. The only id shape that escapes is the
  composite one, which is C-38.
- **Embeddable recursion depth.** Two levels of `@Embeddable`, and an `@ElementCollection` of basic
  values with the converter on the element itself: both refused at startup with the right message and
  the right path (`DeepVault.outer.inner.token`, `TagBag.tags[]`). C-29's recursion is sound; only the
  index descriptor is missing (C-37).
- **The multiset drain with two rows sharing `(entity, field, tenant, subject)` where one is tampered.**
  Correct: the tampered row's own re-read names a different subject from the row's resolved subject and
  refuses, whichever order `PostLoad` fires in, and the clean row drains its own count. The only case
  the per-row re-read cannot separate is when the two rows genuinely share a subject — C-34.

### Rulings

**QUESTIONS #19 — C-27's dropped rollback-only mark: accepted as taken, no code change.**
Isis's evidence is correct and I reproduced it independently without meaning to: my own C-36 probe,
which contains no `markRollbackOnly` call and touches no production code, ends with
`commit=[UnexpectedRollbackException]` purely because Spring's read-only advice on a repository method
marked the participating transaction rollback-only when the refusal escaped it. Marking rollback-only
and "catch the refusal and continue in this transaction" are genuinely mutually exclusive, and my fix
text asked for both. Eviction alone closes the leak C-27 demonstrates; I attacked the gap the deviation
leaves — an instance already referenced elsewhere in the session — and it held (C-36). The deviation
stands.

**QUESTIONS #20 — the composite-identifier residual: rejected as a residual, reclassified as C-38.**
It is not "undemonstrated rather than proven safe". It is demonstrated: a composite-id `@Shredded`
entity cannot be read at all, including rows it wrote itself and nobody touched. That is fail-closed,
which is why it is LOW and not HIGH, but a mapping this module cannot support must be refused at
startup like the `@SecondaryTable` split already is, not discovered on the first read in production.
Correction for Isis, above. Once it is in, #20's write-path half stops being a residual too: the entity
cannot exist.

### Verdict

**NOT MERGEABLE.** C-33, C-39 and C-40 are HIGH. C-33 turns off the module's central read-path control
whenever a shredded write commits inside a bracket, which is the ordinary shape of an untransacted
repository call. C-39/C-40/C-41 leave the same control's thread-local state on a pooled thread after an
`Error`, which is the case C-32 was opened for and did not close.

Six of the eight findings are one design stop each for Thor, and the first four of those are one
design stop together: **who owns `ShreddingContext`'s thread-local state, and what is allowed to clear
it.** Do not patch C-33, C-39, C-40 and C-41 separately — a `finally` cannot be fixed with another
`finally`, and a backstop that clears the whole thread cannot be made safe by clearing slightly less.
Thor writes one page; I review it before any code.

Two are corrections for Isis and can land in parallel: C-37 and C-38.

Probe sources are committed under `gdpr-shredding-spring-boot-starter/src/test-pending/java`, with the
fixtures they need in `…autoconfigure.assoc`, `…autoconfigure.composite`, `…autoconfigure.elemcoll`,
`…autoconfigure.mapkey` and `…autoconfigure.nested`. Run them with `./mvnw -Pprobes-pending test`;
they do not affect the default build, which is still 152 tests, 0 failures, 84.54 % / 85.45 % / 66.32 %.
