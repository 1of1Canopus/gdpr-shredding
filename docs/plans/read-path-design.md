# Read-path design — ownership, row binding, cost

Thor, 2026-09-09. **Revision 2**: Cipher's design review of 2026-09-09 (reproduced verbatim at the
end) returned APPROVED WITH CHANGES with fourteen mandatory items and rulings D1–D6. All fourteen
are applied below; the index at `## Application of Cipher's review` maps each item to the section
that carries it. Nothing is disputed. One item (2) carries an interpretation note, recorded there
rather than argued.

Revision 1 answered the fifth-pass design stop: C-33, C-39, C-40, C-41, C-34, C-35 — all six
reproduced at `7efe689` with `./mvnw -Pprobes-pending test` (7 failures: P1 `RETURNED
[P1-CLEARALL-SECRET]`, P2 `RETURNED [ROW-A-VALUE, ROW-A-VALUE]`, P3 `200 rows, 401 statements`,
unwind 21/200 bracket, 18/200 read scope, 0/200 write scope).

**Invariant.** No decrypted value is ever handed to application code without a verification recorded
against it, on any path, including error paths.

**Second invariant, revision 2 (item 1).** Absence of state is never silence. A decrypt with no open
read region is refused (`SHRED-READ-UNSCOPED`), not answered with a placeholder.

## 1. Ownership of per-thread state

The converter is blind — no session, no entity, no row, and no Hibernate 7.4 hook fires before it
(QUESTIONS #13/#16, twice accepted) — so state it consults must be thread-local. C-17/18/20/26/33/39/40
are one shape: the converter treats *presence of state* as *permission to return plaintext*.
Remove that authority rather than try again to perfect the ownership.

> **Ambient state may accuse. It may never authorise.**

`convertToEntityAttribute` no longer returns plaintext:

1. `null` column ⇒ `null`. Nothing happened.
2. Decode the header. A v1 header is refused, `SHRED-FORMAT-001` (item 12, §3).
3. **No open read region ⇒ throw `SHRED-READ-UNSCOPED`** (item 1). This is the first thing checked
   after the decode and before any key material is touched. Revision 1 proposed deleting this code;
   Cipher refused, and the refusal is right: a placeholder handed to a caller with nothing that will
   ever close a region is a value crossing the boundary with no signal at all.
4. Decrypt. The crypto is untouched except that the AAD now also binds `rowId` (§3).
5. File `(FrameKey, plaintext, ownerToken)` into the current region's frame, where
   `FrameKey = (entity, field, tenant, subject, rowId)` — all five read out of the header the
   converter just decoded — and `ownerToken` is the token of the region currently on top.
6. Return the **placeholder** for the attribute type (§1.1).

Plaintext is installed by `onPostLoad` alone — the one hook that knows the row (`event.getId()`,
the persister, the session) — into the entity *and* the persistence context's `EntityEntry` loaded
state, so dirty checking still compares plaintext to plaintext. Verification happens **before**
either install (item 9): a refusal therefore leaves the instance holding the placeholder, so an L1
retry that dodges the eviction yields a placeholder and not the value.

Therefore **no state ⇒ a refusal**, by construction, not by accounting; **stale state ⇒ at worst a
refusal**, never another subject's value and (item 4) never a stale value of the same row either.
C-39 and C-40 stop being confidentiality findings.

### 1.1 The placeholder (items 2, 3)

`null` is never a placeholder. For `LocalDate`, `BigDecimal` and a JSON column it is silent
destruction: an entity whose install never ran would hold `null` in the field *and* in the loaded
state, and the next ordinary (non-`@DynamicUpdate`) UPDATE would write `NULL` over a live
ciphertext, unseen by any check. Every type gets a **non-null constant, compared by reference
identity**, in a new `com.housedevinci.shredding.jpa.Placeholders`:

| Type | Placeholder | Never persistable because |
|---|---|---|
| `String`, JSON | `"[SHRED-PLACEHOLDER-<32 hex>]"` | identity check in `convertToDatabaseColumn` |
| `byte[]` | a 16-byte array allocated once per JVM run | identity check |
| `LocalDate` | `LocalDate.of(-999999999, 1, 1)`, our own instance | identity check |
| `BigDecimal` | `new BigDecimal("-0.00000000000000000000000000001")`, our own instance | identity check |

The `<32 hex>` is 128 bits from `SecureRandom`, drawn once per JVM run (item 3), ASCII only, no
control characters, no `%`, no `{`/`}` — so it is log-safe in a format string and an attacker
holding `UPDATE` cannot store a value that reads back as the placeholder. Even if they could, the
comparison is reference identity, so an equal-but-distinct instance is not a placeholder.

Writing a placeholder back is refused: `SHRED-PLACEHOLDER-001`, a typed error naming the field and
never the value. It is checked in two places, both before anything is encrypted:

- in `convertToDatabaseColumn`, the last line of defence;
- in `onPreInsert`/`onPreUpdate`, **on the state array, before `writeBlindIndexes`** (item 14), which
  is where it is caught early enough to name the entity and to keep a placeholder out of a blind
  index.

**Interpretation note on item 2.** Cipher's item 2, and Dollar's restatement of it, say the loaded
state "must hold the ciphertext, not null". Hibernate's `EntityEntry` loaded state holds *converted*
(domain-typed) values, not column bytes, so it cannot literally hold the ciphertext; what it holds
before the install is the placeholder. The property item 2 exists for — *an entity whose install
never ran can never write NULL over a live ciphertext* — is delivered exactly, and more loudly: the
UPDATE is refused with `SHRED-PLACEHOLDER-001` instead of silently writing the ciphertext back.

### 1.2 Regions, tokens and write scopes

| State | Created by | Destroyed by | Never cleared by |
|---|---|---|---|
| write scope | `onPreInsert`/`onPreUpdate`, tagged with the session and a per-push token | the matching `Post*` by token, else that **session's own** after-completion callback | another session; any read path |
| read region (frame + owner token) | the repository proxy, or `withReadBracket` | the same call, by owner token | a transaction completion (C-33); another region |

- One `ThreadLocal<ShreddingState>`, two stacks, every entry carrying an owner token (write scopes
  also the session); `closeRegion(token)` unwinds to that token and refuses if it is absent.
  `clearAll()` is deleted; the transaction callback becomes `clearWriteScopesOwnedBy(session)`,
  which may not touch read regions — that alone closes C-33.
- **Drain only under the current region's owner token (item 4).** `onPostLoad` may drain a frame
  entry only if the entry's `ownerToken` equals the token of the region currently on top. A
  foreign-token entry — residue from a region that a `StackOverflowError` unwound past, or from a
  region closed after an erasure — is discarded and the load is refused with
  `SHRED-READ-UNVERIFIED`. D6's stale-but-identical value and post-erasure residue (a false proof)
  both die here, for the price of one field on the frame entry.
- **Session- or transaction-scoped storage: considered, rejected.** Ownership is session/call-scoped
  and now tagged as such; storage cannot be, because the converter cannot reach the session, so a
  session-keyed map still needs a thread-local to find it — the same object, one more indirection.
- **`StackOverflowError`/`Throwable` mid-unwind:** stop depending on unwind cleanup. A `finally` must
  *call* the pop, and at exhaustion that call throws again; no arrangement of `finally` fixes it
  (C-32 proved it). Entry points still restore stack sizes and the transaction callback still clears
  its own, but the argument rests on the placeholder rule plus item 4: residue on a pooled thread is
  bounded, carries a foreign token, and can only produce `SHRED-READ-UNSCOPED` or
  `SHRED-READ-UNVERIFIED`.
- The public entry point keeps the name `ShreddingContext.withReadBracket(...)` — the concept is
  renamed "region" throughout the prose and the internals, but the published method name does not
  churn through README, `docs/index.md` and eleven tests for a rename.

### 1.3 C-41 and item 13: a write scope is consumable only by the bind it was pushed for

Revision 1's C-41 answer was false and item 14 says so: `refuseIfSubjectMoved` ran on `onPreUpdate`
only, never on insert, and on update only when the Pre hook pushed a fresh scope — vacuous on every
path where residue is consumable. Four changes, together, make the property true:

1. **`ShreddingContext.require(entity, field)` compares `scope.entityName()` to the converter's
   entity** (item 13). It ignored it, which *is* C-41: a residual scope pushed for `A` was handed to
   a bind of `B`. A mismatch is `SHRED-CONTEXT-001`, never a silent substitution. `require` also
   refuses a scope whose session is not the session currently flushing where that is knowable, and
   a scope whose push token has already been popped.
2. **A write scope may not nest.** Hibernate executes the action queue serially and a converter
   never triggers another entity's bind, so a scope already live when `onPreInsert`/`onPreUpdate`
   pushes is by construction residue from a bind whose `Post` hook never ran. It is dropped, with a
   WARN, before the new push, so it is never consumable.
3. **`refuseIfSubjectMoved` runs on insert and on every update** (Dollar's (c), item 14) — not only
   when a fresh scope was pushed.
4. **A post-hoc header check runs in `onPostInsert` and `onPostUpdate`** (item 14): the row's stored
   shredded columns are re-read by id and every header is compared against `(tenant, subject,
   rowId)` of the scope the row was written under. A row written under a stale scope is refused
   inside the same flush, before commit, so it is never left in the wrong erasure scope. This is one
   `SELECT` per written row on both insert and update; the cost is stated in §4 and accepted.

## 2. Framework integration matrix — one test per path, written before the hook

Item 1 changes rows 6 and 7: what used to be "placeholder only, loudness may be absent" is now a
refusal, because those paths have no open region.

| # | Path | Outcome | Test |
|---|---|---|---|
| 1 | `find`, derived finder, JPQL/Criteria entity query, `Page`/`Slice` | verified by `onPostLoad`'s row-keyed install | `an_entity_load_installs_and_verifies_each_row` |
| 2 | `getReference`, lazy proxy init, eager association | verified on initialisation | `a_lazy_proxy_initialisation_is_verified` |
| 3 | ciphertext moved between subjects / tenants | refused `SHRED-SUBJECT-MISMATCH` | CIPHER-01 probes |
| 4 | ciphertext moved between two rows of one subject | refused `SHRED-ROW-MISMATCH` | `probe_a_ciphertext_swapped_between_two_rows_of_one_subject_is_detected` (C-34) |
| 5 | multi-row set: one row moved; two subjects | refused; both rows correct | `probe_a_moved_ciphertext_in_a_second_row_of_one_result_set`, `probe_two_rows_of_two_subjects_read_in_one_query` |
| 6 | scalar JPQL, `Tuple`, constructor DTO, interface projection, repository `@Query` | inside a region: `SHRED-READ-UNVERIFIED` at close; outside one: `SHRED-READ-UNSCOPED` at the decrypt | C-17 / C-18 probes, kept; `a_projection_with_no_region_is_refused` |
| 7 | `Stream` consumed after the call returns, `@Async`, hand-written DAO, bare `EntityManager` | refused `SHRED-READ-UNSCOPED` (item 1: D2's silent set is now empty) | `a_streaming_repository_method_consumed_after_the_call_is_refused` |
| 8 | second `EntityManagerFactory` | >1 EMF refused at startup; a repository on an uninstrumented factory has no region | `probe_a_second_entity_manager_factory_decrypts_a_moved_ciphertext` |
| 9 | native query | ciphertext; converter not invoked | existing |
| 10 | first-level-cache retry after a refusal | refused; instance evicted, and holds the placeholder either way (item 9) | `probe_a_refused_row_is_returned_on_the_retry_from_the_persistence_context` |
| 11 | second-level cache, `sharedCache.mode=ALL`, query cache | refused at startup | existing |
| 12 | embeddable, element collection, map key, `@OrderColumn` index | refused at startup `SHRED-CONFIG-001` | existing + C-37's probe |
| 13 | composite id, non-basic id (single-column `@EmbeddedId`), `@SecondaryTable`, `@Basic(fetch=LAZY)` | refused at startup (item 7) | C-38's probe as a startup refusal; `a_single_column_embedded_id_is_refused_at_startup`; `a_lazy_shredded_field_is_refused_at_startup` |
| 14 | `@OptimisticLocking(ALL)` / `(DIRTY)`, `@SelectBeforeUpdate`, `@NaturalId` on a shredded column | refused at startup `SHRED-CONFIG-001` (item 10) | `an_all_column_optimistic_lock_is_refused_at_startup` and two siblings |
| 15 | bulk JPQL update, detached write, criteria parameter | refused `SHRED-CONTEXT-001` | existing |
| 16 | a placeholder written back | refused `SHRED-PLACEHOLDER-001`, from the converter and from the Pre-hook state-array check | `a_placeholder_is_never_re_encrypted`, `a_load_then_flush_never_rewrites_a_shredded_column` |
| 17 | user `@PostLoad` / `@EntityListeners` on a shredded entity | sees plaintext, never the placeholder (item 8) | `a_user_post_load_callback_never_sees_a_placeholder` |
| 18 | `merge`, `refresh` | verified like any other load; `merge`'s internal re-load is inside the region | `a_merge_is_verified`, `a_refresh_is_verified` |
| 19 | `StatelessSession` | no `PostLoad`, so no region: refused `SHRED-READ-UNSCOPED`; a write binds and rebinds or aborts | `a_stateless_session_read_is_refused` |
| 20 | `Set`/`Map` keyed on a shredded field | documented hazard, probed (item 11) | `an_entity_in_a_set_before_install_is_documented_as_unreachable` |
| 21 | forged placeholder stored in the column | refused `SHRED-FORMAT-001` (it is not `SH1` bytes) | `a_forged_placeholder_in_the_column_is_refused` |
| 22 | `IDENTITY` insert: CDC / trigger / replica sees the intermediate | intermediate is bound to a random rowId and verifies against no row (item 5) | `an_identity_insert_intermediate_is_bound_to_no_row` |
| 23 | `IDENTITY` insert inside a batched `saveAll`; rollback | rebind runs per row; failure aborts the transaction (item 6) | `a_batched_save_all_rebinds_every_row`, `a_rebind_failure_aborts_the_transaction` |
| 24 | batched insert (`saveAll`, `persist` loop, cascade, `merge` of a new entity, `SEQUENCE`/`UUID`/assigned id) and batched `UPDATE` | one settlement `SELECT` per entity per flush; every row's stored header compared before commit (S-1) | `a_batched_save_all_is_settled_before_the_commit` and 8 siblings in `BatchedWriteVerificationTest` |
| 25 | `StatelessSession.insert`/`insertMultiple` | no flush event, so settled at `beforeCompletion`; a write with no transaction is refused `SHRED-UNVERIFIED-WRITE` at bind time | `a_stateless_session_insert_multiple_is_settled_before_the_commit`, `a_stateless_write_with_no_transaction_is_refused` |
| 26 | a written row that cannot be read back; a stored header naming another row | `SHRED-UNVERIFIED-WRITE` / `SHRED-SUBJECT-IMMUTABLE`, thrown before the commit | `a_written_row_that_cannot_be_read_back_refuses_the_commit`, `a_row_whose_stored_header_names_another_row_refuses_the_commit` |
| 27 | insert then delete in one transaction; flush then rollback; `@BatchSize` collection | not refused: a deleted row discharges its own debt, a rollback commits nothing | `an_insert_and_a_delete_of_one_row_in_one_transaction_is_not_refused`, `a_flush_then_a_rollback_commits_nothing_and_refuses_nothing`, `a_cascade_insert_of_shredded_children_is_settled_before_the_commit` |

Each row is a RED test committed before the mechanism it names.

## 3. Row binding (C-34), format `SH1` v2

The primary key is the only row identity an attacker holding `UPDATE` cannot forge; any extra
binding column travels with the ciphertext they copy. So **`rowId` goes into the header and the
value AAD**, format `SH1` **v2**. No compatibility is owed on an unreleased branch, and **a v1
header is refused, not ignored** (item 12): `SHRED-FORMAT-001`, the same code an unknown magic gets.

```
offset  len  field
0       3    magic "SH1"
3       1    format version 0x02          v1 (0x01) is refused
4       1    algorithm id
5       4    key version
9       1    tenant id length
10      t    tenant id (UTF-8)
        1    subject id length
        s    subject id (UTF-8)
        1    rowId length, 1..255         NEW
        r    rowId bytes                  NEW
        12   nonce
        4    ciphertext length
        n    ciphertext || tag
```

`Aad.forValue` gains the rowId as one more length-prefixed component and `Aad.LAYOUT` becomes `"2"`,
so a v1 AAD and a v2 AAD are different authenticated strings even for identical field values.

**rowId bytes come from the identifier's column value (item 7)**, never `toString()`. A domain value
object `RowId` encodes the identifier canonically with a one-byte type tag:

| Tag | Identifier type | Bytes |
|---|---|---|
| `0x01` | `Long`, `Integer`, `Short`, `Byte` | int64, big-endian |
| `0x02` | `UUID` | 16 bytes, msb then lsb |
| `0x03` | `String` | UTF-8 |
| `0x04` | `byte[]` | as stored |
| `0x7f` | **unbound intermediate** | 16 bytes from `SecureRandom` |

Any other identifier type, and **any non-basic identifier — a single-column `@EmbeddedId` passes the
existing composite-id column count check but is not basic — is refused at startup** (item 7), so the
encoding is never guessed. **No unbound header exists** (item 5): `RowId` refuses an empty value and
refuses an all-zero value, and a `0x7f` intermediate matches no row's real identifier, so nothing
with an absent, zero or intermediate rowId ever verifies on a read.

**Identifier reuse after a delete** — an application that re-inserts the same primary key value for
a different subject — is named here as an accepted residual (item 7): the subject in the header
still differs, so the row is refused; only a same-subject, same-id re-insert is indistinguishable,
and that is the same row by every definition the module has.

### 3.1 `IDENTITY` (D3, items 5, 6)

The write path knows the row for assigned and `SEQUENCE` ids: `PreInsertEvent.getId()`. Under
`@GeneratedValue(IDENTITY)` the id does not exist at bind time. **Assumption proved by a test before
the hook** (`the_insert_event_has_no_id_under_identity`); if the id turns out to be populated the
whole rebind is dropped.

`IDENTITY` is not refused (D3). Instead:

1. `onPreInsert` pushes a scope carrying a fresh **random 128-bit `0x7f` rowId** (item 5). The row is
   inserted bound to that, so an intermediate captured by CDC, a trigger or a physical replica is
   bound to no row and verifies nowhere.
2. `onPostInsert` — where `event.getId()` exists — re-encrypts that row's shredded columns from the
   plaintext still in `event.getState()`, bound to the real rowId, and writes them in **one
   `UPDATE`, in the same transaction, over raw JDBC via `session.doWork`** (item 6) — never the
   session query API and never `flush()`, neither of which is supported inside the action queue.
3. **Rebind failure aborts the transaction** (item 6). The exception escapes `onPostInsert`, which
   fails the flush; nothing catches it. Probed under a batched `saveAll`, under an explicit
   rollback, and under `StatelessSession`.
4. The post-hoc header check of §1.3 then runs against the rebound bytes, so a rebind that wrote the
   wrong thing is caught in the same flush.

Cost: two `encrypt` calls per shredded column on an `IDENTITY` insert, so two ticks of the per-key
encryption counter. Stated in `SECURITY-NOTES.md` beside control 3.

## 4. Cost (C-35)

`onPostLoad` no longer re-reads the row, and `readStoredShreddedColumns` is deleted from the read
path entirely. The converter already decrypted its bytes and filed them under `(entity, field,
tenant, subject, rowId)` from the header; `onPostLoad` builds the same key from `event.getId()` and
the subject and tenant resolved from the hydrated entity, drains it under the current region's token
(item 4), and a miss is an immediate refusal — `SHRED-ROW-MISMATCH` or `SHRED-SUBJECT-MISMATCH` when
an entry for that `(entity, field)` exists under a different triple, `SHRED-READ-UNVERIFIED`
otherwise.

**Which fields must have an entry** is decided by the placeholder, not by a query: a field holding
the placeholder (by identity) had a converter run on it and therefore owes an entry; a field holding
anything else had a `null` column and owes nothing. No `SELECT`.

**200-row list: 1 statement against the entity's table, 2 with a `Page` count** — down from 201
(200 per-row re-reads plus the list query). Measured, not asserted: Cipher's P3 counts
`prepareStatement` on the real `DataSource` and reports 0 per-row re-reads.

What P3 also shows, and revision 1 got wrong by claiming "1 statement" flat: the total is 201, and
the other 200 are `FieldCipher.decrypt`'s per-decrypt key-state check against
`shredding_data_key`. That is control 7 — the data-key cache holds key *material*, never
*authority*, so every decrypt re-reads the row that says whether the key may still be used at all —
and it predates this design; the fifth pass measured 401 because the 200 per-row entity re-reads
sat on top of it. Memoising the key state per transaction would remove it, but caching authority is
a security decision, not a performance one, and it is recorded in `QUESTIONS.md` for Cipher rather
than taken here.

The write path pays more, not less: one `SELECT` before an update (`refuseIfSubjectMoved`, now on
every update) and one `SELECT` after every insert and every update (the post-hoc header check of
§1.3), plus one `UPDATE` per `IDENTITY` insert of a shredded entity. That is the price of item 14
and it is charged on the write path, which is not the caller-influenceable amplification C-35
objected to. Batching the post-hoc check per flush is a later optimisation, recorded in QUESTIONS.

## 5. Deleted, kept, probes

**Deleted:** `clearAll()`; the read-scope stack (`READ_SCOPES`, `withRead`, `pushReadScope`/
`popReadScope`, `currentReadScope`) — with no plaintext leaving the converter there is nothing for a
caller to vouch for; the converter's `inReadBracket()` *authority* branch; `onPostLoad`'s
`readStoredShreddedColumns` call.

**Kept:** `SHRED-READ-UNSCOPED` (item 1 — revision 1 proposed deleting it; it stays and gets
*wider*, since a projection now meets it on every path); the region `BeanPostProcessor`; the frame
as a row-keyed, token-tagged multiset; `refuseIfSubjectMoved` (now on insert and every update);
`refuseLoad`'s eviction; every startup refusal; the reverse metamodel scan; all crypto and erasure
code except the AAD and header changes of §3.

**New codes:** `SHRED-ROW-MISMATCH`, `SHRED-PLACEHOLDER-001`.

**Listener registration (item 8):** `ShreddingIntegrator` **prepends** `POST_LOAD` as well as
`PRE_INSERT` and `PRE_UPDATE`. It appended, so `PostLoadEventListenerStandardImpl` ran first and
every user `@PostLoad` method and every `@EntityListeners` bean saw the placeholder. `POST_INSERT`
and `POST_UPDATE` stay appended: the post-hoc check must see what actually reached the database.

**Startup refusals added:** `@OptimisticLocking(ALL)` and `(DIRTY)` (the UPDATE's `WHERE` would
carry the plaintext against a ciphertext column), `@SelectBeforeUpdate` and `@NaturalId` on a
shredded column (`getDatabaseSnapshot` re-reads through the converter with no `PostLoad`, so it
compares placeholders) — item 10; and a non-basic identifier — item 7.

**Documented (item 11):** a shredded field holds the placeholder between the converter and the
install, so an instance put into a `HashSet` or used as a `HashMap` key *before* the install is
unreachable afterwards. README and `docs/index.md` carry the rule — **a shredded field never
participates in `equals`/`hashCode`** — and a probe demonstrates it. Dirty checking is unaffected:
the install writes the entity field and the loaded state together.

**Probes:** the six pending ones move from `src/test-pending/java` to `src/test/java` as they turn
green — P1 refused, P2 `SHRED-ROW-MISMATCH`, P3 ≤ 2 statements for 200 rows, the three unwind probes
green. Cipher's "probes once built" list is the acceptance list for §2: listener order against a
user `@PostLoad`; the null-placeholder UPDATE erasing a `BigDecimal` ciphertext; a projection with
no region; a forged placeholder in the column; a foreign-token drain after a forced
`StackOverflowError`; a read after erasure with residue; the INSERT/UPDATE window under CDC and
under rollback; single-column `@EmbeddedId`; `StatelessSession`; `merge`, `refresh`,
`@SelectBeforeUpdate`, `OptimisticLockType.ALL`; a `Set` keyed on a shredded field; the 200-row
count; every `CipherProbe*` unchanged. C-37 and C-38 stay Isis's and are unaffected.

## 6. Rulings D1–D6 (Cipher, 2026-09-09)

1. **D1 accepted.** §1 is the design.
2. **D2 accepted with item 1** — applied §1 step 3 and §2 rows 6–7. The silent set is empty.
3. **D3 accepted subject to items 5–7** — applied §3.1.
4. **D4 accepted subject to items 8–11** — applied §5 (prepend, startup refusals, documentation)
   and §1 step 6 (verify before install).
5. **D5 accepted with item 12** — applied §3: v2, and v1 refused rather than ignored.
6. **D6 rejected as stated** — applied §1.2 item 4: the stale value becomes
   `SHRED-READ-UNVERIFIED`.

## Application of Cipher's review

| Item | Applied |
|---|---|
| 1 no region ⇒ throw | §1 step 3, §2 rows 6–7, §5 "kept" |
| 2 `null` is never a placeholder | §1.1 (+ interpretation note) |
| 3 unforgeable, log-safe token | §1.1 |
| 4 drain only under the current owner token | §1.2 |
| 5 no unbound header exists | §3, §3.1 step 1 |
| 6 rebind failure aborts; raw JDBC `doWork` | §3.1 steps 2–3 |
| 7 rowId from the column value; refuse a non-basic id | §3, §2 row 13 |
| 8 prepend `POST_LOAD` | §5, §2 row 17 |
| 9 verify first, install second | §1 step 6, §2 row 10 |
| 10 startup refusals for `@OptimisticLocking(ALL/DIRTY)`, `@SelectBeforeUpdate`, `@NaturalId` | §5, §2 row 14 |
| 11 document and probe `equals`/`hashCode` | §5, §2 row 20 |
| 12 a v1 header is refused | §3 |
| 13 `require` must compare `scope.entityName()` | §1.3 change 1 |
| 14 a write scope is consumable only by the bind it was pushed for | §1.3 changes 1–4, §1.1 |

## Cipher design review (2026-09-09)

**Verdict: APPROVED WITH CHANGES.** "Ambient state may accuse, never authorise" is the first proposal in five passes
that removes the authority instead of re-accounting for it, and rowId-in-AAD closes C-34 and C-26's whole class at
once. Fourteen changes are mandatory before code; 8, 13 and 14 break the design as written.

**Rulings.** D1 **accepted** — §1 is the design. D2 **accepted with change 1**: silence is not acceptable
where a signal exists. D3 **accepted subject to 5-7**; I do not require refusing `IDENTITY`. D4 **accepted
subject to 8-11**. D5 **accepted with 12**. D6 **rejected as stated**: change 4 turns the stale value into
a refusal for the price of one field. The changes, all mandatory before any code:

1. **No region ⇒ throw, never a placeholder.** A placeholder outside an open region discards today's
   `SHRED-READ-UNSCOPED` (C-17/18/20) and is a narrowing. D2's silent set then empties: `Stream` after the call,
   `@Async`, hand-written DAO, raw `EntityManager` have no region and stay loud. §2 rows 6-7 change.
   — **applied §1 step 3, §2 rows 6–7**
2. **`null` is never a placeholder.** For `LocalDate`/`BigDecimal`/JSON it is silent destruction: an entity whose
   install never ran holds `null` in field *and* loaded state, and the next non-`@DynamicUpdate` UPDATE writes `NULL`
   over the ciphertext, unseen by `SHRED-PLACEHOLDER-001`. Non-null constants, compared by **reference identity**.
   — **applied §1.1**
3. **The token is unforgeable and log-safe**: per JVM run, `[SHRED-PLACEHOLDER-<hex>]`, ASCII, no control characters
   or `%`/`{}`, so an attacker with `UPDATE` cannot store a value that reads back as one. — **applied §1.1**
4. **Drain only under the current region's owner token**; a foreign-token entry is discarded and the load refuses.
   D6 becomes `SHRED-READ-UNVERIFIED`, and post-erasure residue — a false proof — dies with it. — **applied §1.2**
5. **No unbound header exists.** A v2 header with rowId absent or zero that still verifies reopens C-34 for anyone
   with `UPDATE`. The IDENTITY insert binds a random 128-bit rowId and `onPostInsert` rebinds, so an intermediate
   captured by CDC, a trigger or a replica is bound to no row. — **applied §3, §3.1**
6. **Rebind failure aborts the transaction**, on raw JDBC via `session.doWork` — never the session query API or
   `flush()`, unsupported inside the action queue. Probe batched `saveAll`, rollback, `StatelessSession`.
   — **applied §3.1**
7. **rowId bytes come from the identifier's column value**, length-prefixed into the AAD, not `toString()`. A
   single-column `@EmbeddedId` passes C-38's check but is not basic: refuse a non-basic id at startup. Name id
   reuse after a delete as an accepted residual. — **applied §3**
8. **`POST_LOAD` must be prepended.** `ShreddingIntegrator` appends, so `PostLoadEventListenerStandardImpl`
   runs first and every `@PostLoad` callback and `@EntityListeners` bean sees the placeholder. — **applied §5**
9. **Verify first, install second** (entity and `EntityEntry` loaded state), so an L1 retry yields a placeholder.
   — **applied §1 step 6**
10. **Refuse at startup where loaded-state mutation cannot hold:** `@OptimisticLocking(ALL|DIRTY)` (the UPDATE's
    WHERE would carry plaintext against a ciphertext column), `@SelectBeforeUpdate`, `@NaturalId` on a shredded
    column — `getDatabaseSnapshot` re-reads through the converter with no `PostLoad` and compares placeholders.
    — **applied §5, §2 row 14**
11. **Document and probe `equals`/`hashCode`.** Before install the field holds the placeholder, so an instance added
    to a `Set` first is unreachable after; dirty checking is safe (the install writes both sides). README rule:
    shredded fields never participate in `equals`/`hashCode`. — **applied §5, §2 row 20**
12. **A v1 header is refused, not ignored** (`SHRED-FORMAT`). — **applied §3**
13. **`ShreddingContext.require` must compare `scope.entityName()` to the converter's entity** — it ignores it
    today, which is C-41 itself: a residual scope pushed for A is handed to a bind of B. — **applied §1.3**
14. **§1's C-41 answer is false.** `refuseIfSubjectMoved` runs on `onPreUpdate` only, never on insert, and on update
    only when the Pre hook pushed a fresh scope: vacuous on every path where residue is consumable. Property: *a write
    scope is consumable only by the bind it was pushed for* — tag it with session and flush generation, refuse a
    foreign or dead-generation scope in `require`, add the post-hoc header check to `onPostInsert`, and run the
    placeholder write-back check on the state array in the Pre hooks, before `writeBlindIndexes`. — **applied §1.3**

**Sound as argued.** The pooled-thread claim holds once the frame key carries tenant and rowId: same
entity+field+tenant+subject+rowId is the same row, so residue cannot cross subjects. `StackOverflowError`,
`OutOfMemoryError`, a throw from `onPostLoad` and a session closed without commit all reduce to residue, which change
4 reduces to a refusal. Session-scoped storage and the per-row re-read: rejections accepted. Jackson: with change 1 a
placeholder is serialisable only from inside a region whose close refuses first.

**Probes once built.** Listener order against a user `@PostLoad`; the null-placeholder UPDATE erasing a `BigDecimal`
ciphertext; a projection with no region; a forged placeholder in the column; a foreign-token drain after a forced
`StackOverflowError`; a read after erasure with residue; the INSERT/UPDATE window under CDC and under rollback;
single-column `@EmbeddedId`; `StatelessSession`; `merge`, `refresh`, `@SelectBeforeUpdate`, `OptimisticLockType.ALL`;
a `Set` keyed on a shredded field; the 200-row count; every `CipherProbe*` unchanged.

## Design addendum: insert-side binding under batching (2026-09-10)

**Property.** *No row of a `@Shredded` entity commits whose stored header is not bound to that row's
own id, subject and tenant — at any `hibernate.jdbc.batch_size`, on insert and on update.* With the
corollary the built code lacks: **a check that could not run is a refusal, never a pass.** S-1 is not
"the `SELECT` is in the wrong place"; it is `readStoredShreddedColumns` returning `null` and
`refuseIfStoredHeadersDisagree` reading "I saw nothing" as "nothing is wrong".

**Options.** (a) settle at flush completion from the ids the `Post*` events carry — one `SELECT` per
entity per flush instead of one per row, which is §4's deferred optimisation, and needs "after the
batch executed" proved rather than assumed. (b) `doWork` after `flush()` inside the same batch
boundary — the module may not call `flush()` from inside the action queue (§3.1) and it would settle
only the flush a caller happens to make: rejected. (c) refuse `batch_size > 0` at startup — complete
and not a mechanism, but it deletes a real feature from every application holding one `@Shredded`
entity, and it is per-`SessionFactory` while `session.setJdbcBatchSize` and `StatelessSession` are
per-session, so it needs a runtime refusal too and is therefore not the two-line change it looks
like. (d) bind the id before the `INSERT` and refuse `IDENTITY` under batching — removes the *rebind*
read-back of §3.1, not the *verification* read-back of item 14, whose whole point is to catch a write
this module's own bookkeeping got wrong (S-5's unconverted column, a residual scope). Not sufficient
alone.

**Recommendation: (a), with the fail-open closed — this is what makes it a property and not a
mechanism.** Three parts. 1. Every bind records a **verification debt** on the session:
`(entity, table, id column, id, expected tenant/subject/rowId)`. 2. Debts are settled in one
`SELECT … WHERE id IN (…)` per entity at each settlement point: the end of every flush, after the
action queue and the JDBC batch have run, **and** unconditionally at `beforeCompletion`. 3.
**Settlement is total or the transaction aborts**: a debt whose row is absent at `beforeCompletion`,
and any debt still outstanding when that synchronisation runs, is `SHRED-UNVERIFIED-WRITE`; a bind
with no settlement anchor (no transaction to register on) is refused at bind time. A configuration
knob can then no longer remove the control — it can only make it refuse. The existing per-row
post-hoc check stays as belt and as early failure. (d)'s useful half is taken as a probed assumption,
not a design: `IDENTITY` is asserted unbatchable by test, and refused at runtime if it ever is not.

**Paths, one RED probe each before the hook:** batched `saveAll` (S-1's probe), `persist` in a loop,
batched `UPDATE`, `StatelessSession.insert` with `setJdbcBatchSize`, `merge` of a new entity, cascade
insert through a collection, `@BatchSize` collection then flush, `IDENTITY` under batching (rebind
and settlement), assigned id, sequence id, two entities in one flush, `saveAndFlush` then a second
flush, flush-then-rollback (nothing commits, nothing refused), a bind with no transaction, and bulk
JPQL update, which fires no event and stays matrix row 15's `SHRED-CONTEXT-001`. Matrix rows 24-27.

## Design addendum 2: region residue (2026-09-10)

**Property.** A decrypt is served only inside a region opened by the same call that is reading, on
the same thread; residue from an earlier call, however it ended, never serves. `recordDecoded` today
asks only "is this deque non-empty", and a region a returned call left behind is the same object at
`stack.peek()` as one legitimately open (QUESTIONS S-4).

**A counter is refused; an epoch is not one.** Isis stopped at a second `ThreadLocal` depth counter,
rightly: a counter is *accumulated* state, so one exit missed under a `StackOverflowError` (C-32) is
permanently wrong in the *permissive* direction — stuck positive, still authorising. An epoch is
*replaced* state: entry assigns `TOKENS.incrementAndGet()` unconditionally, nothing accumulates, and
a missed restore is overwritten by the next entry in the refusing direction, since an older-stamped
region is thereby residue. `pushBind`'s own argument: correctness on entry, never on exit.

| | (a) session/tx binding | (b) epoch at proxy entry | (c) sweep on entry |
|---|---|---|---|
| SOE mid-unwind | residue outlives its session only if the session ends too; inside one session it keeps authorising | residue's epoch ≠ the next entry's → refused; residual is the window before that next entry | residue destroyed by the next proxied call; until then it keeps authorising |
| nested repo calls | one session throughout → no discrimination at all | save/restore the outer epoch; a failed restore refuses the outer region, fail-closed | needs the explicit nesting token, a second mechanism, and a lazy load through a converter cannot pass one |
| async / session closed uncommitted | async already refused (no region on that thread); a closed session is (a)'s one real win | both refused on the epoch alone, no session state consulted | both refused at the next entry, not before |
| cost | a `TransactionSynchronizationManager` or `Session` lookup per decode; couples the read path to Spring tx state | one `long` compare per decode, one `ThreadLocal<Long>` | one deque drain per proxied call |
| **closes S-4 R1?** | **no** | **yes** | **no** |

**(a) and (c) do not close R1, which decides it.** R1 builds its ownerless region from a direct
`openRegion()` with no session and no transaction, then reads it from a caller holding no region:
under (a) both sides see "no current session" and the binding matches, while refusing "no session"
would refuse every non-transactional `withReadBracket`, C-32's probes included. Under (c) nothing
sweeps — the undisciplined reader never enters the proxy; (c) guards the next proxied call only.

**Recommendation: (b), with (c)'s sweep as a free complement** — `Bracket.invoke` discards any region
already on the deque before opening its own, bounding (b)'s residual to "no proxied call since the
failed restore". `Bracket.invoke` and `withReadBracket` stamp a fresh epoch; public `openRegion()`
stamps the thread's *current* epoch, so a region opened outside either is residue by construction.
No leak here carries authority: a surviving epoch can only make regions refuse. **Residual, stated
not hidden:** a read opening no region of its own, after an SOE skipped exactly the restoring frame
and before any proxied call, sees a stale matching epoch — the C-32 window `popWrite` concedes.

**Probes, RED first.** R1 promoted from `src/test-pending`; a region left by a returned call does not
serve a later non-proxied decode; nested repository calls still serve their own decodes; a failed
inner restore refuses the outer region; `CipherProbeBracketUnwindTest` unchanged, leaks still 0/200.

### Cipher review of addendum 2 (2026-09-10)

**APPROVED WITH CHANGES.** The choice of (b) is right and the argument for it is right. A counter is
accumulated state and one missed exit is stuck-positive authority; an epoch is replaced state and a
missed restore lands in the refusing direction. The rejections of (a) and (c) are made on evidence -
R1's region has no session and R1's reader enters no proxy - and I accept both. What follows are six
changes, five of them because the mechanism as written does not yet have the property the addendum
claims for it, and one because the accounting the epoch is meant to protect is already broken on
`e2c2bdd` and should be fixed first.

**1. Compare epochs for equality, never for age.** The addendum's predicate is "regions with an older
epoch are residue". A region can carry an epoch *newer* than the thread's: an inner entry stamps
`n+1`, an `Error` inside it leaves its region on the deque, the outer frame's `finally` restores `n`
and the outer call carries on. Under "older is residue" that leftover region is not older, so it is
not residue, so it authorises - and it is the region on top, so it is the one every subsequent decode
of the outer call is filed into. Equality refuses both directions and is the only predicate the
property needs — **applied §2.1**. It also takes wraparound off the table: at `TOKENS.incrementAndGet()` 2^63 is not
reachable by any workload, but an ordering test is the one shape where a single overflow inverts
every comparison at once, and equality cannot be inverted.

**2. There must be a distinguished "no entry in force" epoch, and public `openRegion()` must not stamp
the live one.** The addendum states that "public `openRegion()` stamps the thread's *current* epoch,
so a region opened outside either is residue by construction". That is false in two places I can
name.

  - *A thread that has never entered.* The epoch `ThreadLocal` has to start somewhere. A raw
    `openRegion()` on a fresh or pooled-but-never-bracketed thread stamps that initial value, and
    `recordDecoded` compares against the same initial value: equal, authorised. R1 would then be red
    or green according to whether the JUnit thread happened to enter a repository proxy earlier in
    the class, which is not a property, it is an ordering artefact.
  - *A raw `openRegion()` from inside a proxied call.* A user `@PostLoad` method, an
    `@EntityListeners` bean, a hand-written DAO reached from a repository default method - all run
    with the live epoch in force. A region they open is stamped live, sits on top of the deque, and
    every decode for the remainder of that call is filed into it and drained from it rather than
    from the proxy's own region. Indistinguishable from the legitimate one, which is exactly S-4.

  So: the epoch `ThreadLocal`'s initial value, and the value restored at the outermost exit, is a
  `NONE` that no entry ever assigns; `Bracket.invoke` and `withReadBracket` are the only two writers
  of a real epoch; a `Region` captures the epoch in force at the moment it is constructed and never
  re-reads it; and every region access refuses when the thread's epoch is `NONE`. Public
  `openRegion()` either stamps `NONE` explicitly or stops being public and becomes reachable only
  through the two entries — **applied §2.2**. Only then is "a region opened outside either is residue by construction"
  true as written - and only then does the residual shrink to the one case the addendum wants to
  concede, because a region-less read after an ordinary return now refuses instead of matching.

**3. (c)'s sweep must be conditional on the epoch, and must not be silent.** "`Bracket.invoke`
discards any region already on the deque before opening its own" is written unconditionally. A
nested repository call would then destroy the *outer* call's still-live region: its pending decodes
vanish, and the outer `closeRegion(outerToken)` finds its token no longer on the stack and raises
`SHRED-READ-UNVERIFIED` - on every nested repository call in the application, which is the shape the
addendum's own probe list says must keep working. Sweep only regions whose epoch is not the epoch in
force at entry; never one whose epoch equals it. And log what is swept at WARN with the count and
the first `entity.field`, the way `pushBind` already does for a stale write scope: the sweep is the
only moment an operator ever learns an undisciplined region existed at all. — **applied §2.3**

**4. The check belongs at every region access, not only at `recordDecoded`.** `drain`,
`pendingKeysFor` and `closeRegion` each read `stack.peek()` with no test of any kind. A decode
recorded while the epoch matched and drained after it changed is the same fail-open one method
later, and a `closeRegion` that unwinds a region it does not own is what makes residue reachable in
the first place. One predicate in one private `currentRegion()`, four callers. — **applied §2.4**

**5. Fix `unwindTo`'s silent discard before building the epoch, not after.** Reproduced on `e2c2bdd`:
`CipherProbeSeventhPassTest.probe_an_inner_regions_undrained_decode_is_discarded_in_silence_by_the_outer_close`
(`src/test-pending/java`). `closeRegion(outer)` pops every region above `outer` and never looks at
their pending maps, so an inner region whose own close was skipped - precisely the C-32 state this
addendum exists to handle - is dropped with its unverified decode inside it, and the outer call
returns its result. `discardRegion` may drop unchecked; the original exception is the failure worth
reporting. `closeRegion` may not: an intermediate region still holding a decode is
`SHRED-READ-UNVERIFIED`, named the same way its own region's would be. The epoch is worth little on
top of accounting that already loses a debt on the normal return path. — **applied §2.5** (Isis's
S-8 fix is the one this waits on; §2.5 says what was built instead and how the two merge)

**6. Two probes to add to the list.** A raw `openRegion()` *inside* a proxied call is refused (change
2's second case), and a raw `openRegion()` on a thread that has never entered an entry is refused
(change 2's first case). The four already listed are right, and `CipherProbeBracketUnwindTest` stays
unchanged at 0/200. — **applied §2.6**

**The named residual: accepted - and no, the converter must not be made to refuse "when no proxied
call is active".** The phrasing is the problem, not the position. `withReadBracket` is deliberately
not a proxied call; it is the documented path for a raw `EntityManager` entity operation, and a
"proxied call in flight" test would refuse exactly the relaxation (a) was rejected for refusing. The
property to enforce is *no bracketed entry is in force on this thread*, which change 2 makes testable
with one `long` and without consulting Spring or Hibernate state at all. With change 2 in place the
residual is no longer "a region-less read on a thread that has not entered the proxy" - that case
refuses - but only "a region-less read on a thread where an `Error` skipped exactly the frame that
restores the epoch, and before the next entry". That is the same window `popWrite`'s javadoc concedes
for write scopes and `CipherProbeBracketUnwindTest` already measures, and its cost is bounded by
S-4's closed half: an ownerless region can serve nothing but this row's own current value, verified
by `onPostLoad` against this row's tenant, subject and identifier, with the per-decrypt key-state
check still in force. **A leaked region costs a refusal, never a value.** Accept it, state it in
`SECURITY-NOTES.md` in those words beside QUESTIONS #21, and do not buy a `StackWalker` on every
decode for it.

**Async, for the record.** Both `REGIONS` and the new epoch must be plain `ThreadLocal`s, never
`InheritableThreadLocal` and never anything a task decorator can copy: an inherited epoch would match
an inherited region and authorise the one case the design gets for free today. Worth a line of
javadoc, since the failure mode of getting this wrong is silent. — **applied §2.2** (the javadoc on
`EPOCH` says exactly this)

### Addendum 2 as built (2026-09-10)

**§2.1 Equality, never age.** `currentRegion()` is `top.epoch == EPOCH.get() && EPOCH.get() !=
NO_ENTRY`. There is no `<`, no `>` and no arithmetic on an epoch anywhere in the class, so neither a
newer leftover nor a wraparound has a direction to exploit.

**§2.2 `NO_ENTRY`, and the two writers.** `NO_ENTRY` is `0L`; `TOKENS.incrementAndGet()` never
returns it, so no entry can ever assign it. `enterRegion()` is the only method that stamps a real
epoch and it has exactly two callers - `ShreddingReadBracketCustomizer.Bracket#invoke` and
`withReadBracket`. `openRegion()` stays public (removing it is a breaking change, and the unwind
probes build residue with it) but stamps `NO_ENTRY` explicitly and is `@Deprecated`; a region it
opens can never be the current region, on a thread that never entered *or* inside a proxied call,
and its own `closeRegion` is refused. `EPOCH` and `REGIONS` are both plain `ThreadLocal`s, and the
javadoc says why.

**§2.3 The sweep, conditional and loud.** `enterRegion()` discards regions on top whose epoch is not
the epoch in force *at entry*, stopping at the first one that matches: a nested call never touches
its caller's live region. What it discards it names at WARN, with the count and the first
`entity.field`. *Deviation, stated:* Cipher's rule is applied literally, so a `NO_ENTRY` region left
on a thread where nothing is in force (`NO_ENTRY == NO_ENTRY`) is not swept. It can serve nothing
(§2.4) and the enclosing unwind pops it; QUESTIONS S-4 records the option of sweeping it too, for
Cipher to rule on.

**§2.4 One predicate, four callers.** `recordDecoded` refuses (`SHRED-READ-UNSCOPED`, message
extended to name the residue case), `drain` returns empty, `pendingKeysFor` returns empty - an empty
drain is what `onPostLoad` turns into `SHRED-READ-UNVERIFIED`, so the read still refuses, in the
verifier's vocabulary rather than the converter's - and `closeRegion` refuses.

**§2.5 The close, and the merge with S-8.** Isis had not pushed S-8 within the agreed hour (Dollar
told), so this is built on a *separate method*: `closeRegion` keeps its body and calls
`refuseIfClosedUnderAnotherEntry(region, epochAtClose)` as its **last** statement, after the region's
own unpaid-debt refusal, so S-8's more specific message wins wherever both apply. The epoch in force
is captured *before* the unwind. The one line inside `unwindTo` is `restoreEpoch(region)`, and its
javadoc states the contract for whoever writes the next unwind path: **every pop of an entry region
must restore.** A merge that drops it fails
`CipherProbeRegionEpochTest.probe_an_inner_entry_and_its_caller_each_serve_only_their_own_decodes`
and `CipherProbeReadScopeTest`'s nested probe immediately.

**§2.6 Probes.** `CipherProbeRegionResidueTest` promoted from `src/test-pending` (S-4 R1 and R2,
green; R1 is now the stronger statement that the ownerless region cannot even be *armed*).
`CipherProbeRegionEpochTest`, six probes: a raw region on a never-entered thread; a raw region inside
an entry (S-4 itself), including `drain` and `pendingKeysFor`; closing a region opened outside an
entry; an inner entry and its caller each serving only their own decodes; the conditional sweep with
its WARN asserted; an inner entry that never restored the epoch refusing its caller's close.
`CipherProbeReadScopeTest` gains the two on the real read path: a repository call nested inside a
read bracket, and a raw region opened mid-call refusing that call's later decodes.
`CipherProbeBracketUnwindTest` unchanged: 0/200 write-scope leaks, 0/200 region drains, no
plaintext.

## Design addendum 3: blind index tenant binding (2026-09-10)

**Property.** *Every blind index value that exists is reachable and destroyed by the erasure of the
subject it was derived for.* It is not: `writeBlindIndexes` derives under `scope.tenantFor(of)` - the
field's declared tenant, else the ambient `TenantSupplier` - while `clearBlindIndexes` reaches the
row with `UPDATE t SET idx = NULL WHERE tenantColumn = ? AND subjectColumn = ?`, matching the row's
**stored `tenantColumn` value** against the tenant it was asked for. S-7 is the S-2 special case; the
general one needs no second tenant expression at all - any application whose tenant column holds
something else (a company id where the supplier yields a region, a trigger-written column, a row a
later `UPDATE` moved). The key dies, the ciphertext dies, and
`HMAC(secret, tenant | entity | field | normalised plaintext)` survives: a
cross-row correlator for the erased subject and, for a low-entropy value such as an email address, a
confirmation oracle for anyone with the index secret. The erasure proof reports success.

**What it must be keyed under.** The one value both sides can agree on: *that row's `tenantColumn`
value, as written by that write*. The write has it in the state array and the erasure matches on it;
neither the ambient tenant nor a declared expression is visible to the erasure at all.

**Options.** (a) **derive under the row's `tenantColumn` value**, read out of `Object[] state` in
`onPreInsert`/`onPreUpdate` beside the value being indexed - exact, one array lookup, no schema
change; needs the column to be a mapped basic property, a startup refusal rather than a runtime
surprise. (b) **keep today's key, refuse the write when the two disagree** - fail-closed and smaller,
but it makes a legitimate shape unusable instead of correct. (c) **drop the tenant from the HMAC
input** - one value would correlate across every tenant: refused. (d) **erase by subject only** -
erases another tenant's rows for a colliding subject id: refused. (e) **a second column** - correct,
but a schema change on the user's table.

**Recommendation: (a), with (b)'s refusals as its boundary.** Derive under `state[tenantColumn]`;
refuse at startup (`SHRED-CONFIG-001`) when `tenantColumn` is not a mapped, basic, `String` property
of the indexed entity, naming entity, index field and column; refuse the write when its value is null
or blank, because an index no `WHERE tenantColumn = ?` can match is an index no erasure can destroy.
S-7's startup refusal stays until this lands, then relaxes: what breaks erasure is disagreement with
the column, not a declared per-field tenant.

**Probes, RED first.** A `tenantColumn` differing from the ambient tenant: the erasure clears the
index (today it survives). The S-7 `Folder` shape: cleared, no startup refusal needed. A row a later
`UPDATE` moves: re-derived under the new value. A null or blank value at write: refused.
`tenantColumn` unmapped, on an embeddable, non-`String`, or named by column rather than property:
startup refusal, one probe each. And the proof's cleared-index count non-zero wherever one existed.

### Cipher review of addendum 3 (2026-09-10)

**APPROVED WITH CHANGES.** Seven, numbered. The property is stated correctly and it is the right
property. The survey of options is honest and (c) and (d) are refused for the right reasons. But (a)
as recommended does **not** close the finding it is written for, and I have the repro to show it -
`CipherProbeBlindIndexAmbientTenantTest.probe_a_blind_index_under_the_ambient_tenant_survives_that_subjects_erasure`
(`src/test-pending/java`, RED on `fa6f477`, no field declaring a tenant anywhere, nothing refused at
startup, the surviving bytes recomputable as
`HMAC(secret, org-a | Note | email | victim@example.test)` by the second probe in the same file).
Changes 1 and 4 are the load-bearing ones; do not start building before they are settled.

**1. `tenantColumn` is a column name, not a property name; the startup refusal as written refuses
every correct configuration.** "Refuse at startup when `tenantColumn` is not a mapped basic `String`
property" reads the annotation's value in the wrong namespace. `@BlindIndex(tenantColumn =
"tenant_id")` names the column the erasure's `UPDATE ... WHERE tenant_id = ?` matches on; the state
array and `persister.getPropertyNames()` are keyed by *property* names (`tenantId`). Written
literally, either every existing mapping fails startup, or the lookup misses and the write derives
under something unstated. The fix must resolve column to property through the persister's own
column mapping, case-insensitively and allowing for a quoted identifier, and refuse at startup
unless that resolution yields **exactly one** property that is basic, `String`-typed, mapped to the
entity's primary table, not a formula and not inside an embeddable. Name entity, index field,
`tenantColumn` and what was found, in the message.

**2. Resolve once, share the result, so the two sides cannot drift again.** S-7 exists because the
tenant the write derives under and the tenant the erasure matches on are computed in two places from
two different inputs. Adding a third input - a property index into a state array - without binding
it to the first two just moves the seam. `BlindIndexColumn` (it already carries table, column,
subject column, tenant column) is where the resolved property name/index belongs, computed once
during the startup scan and used by both `writeBlindIndexes` and `JdbcErasureStore`. One object, one
resolution, and a test that asserts the write path and the erasure path read the same field of it.

**3. Refuse null, blank and non-`String` at write time.** As the addendum says, plus the type: an
index no `WHERE tenantColumn = ?` can match is an index no erasure can destroy. Typed error, naming
entity, index field, column. `SHRED-UNVERIFIED-WRITE` is the closer vocabulary than
`SHRED-CONFIG-001` for a runtime refusal, but I do not insist; pick one and use it consistently.

**4. (a) alone does not close S-7b. The write must also refuse when the field's own resolved tenant
and the row's `tenantColumn` value disagree.** This is the change that decides the addendum. Work
the repro through the recommendation as written: the ciphertext of `email` is encrypted under the
data key for `(org-a, subject)` - the field's resolved tenant, the ambient supplier here - while
the index is now derived under `state[tenantColumn]` = `org-b`. An erasure for `(org-a, subject)`
destroys the data key and kills the ciphertext, and its `UPDATE ... WHERE tenant_id = 'org-a'`
matches no row: **the index still survives**, exactly as it does today. An erasure for
`(org-b, subject)` clears the index and destroys a key the ciphertext was never encrypted under:
the value stays readable. Making the derivation agree with the match column was never the broken
link - the broken link is that one erasure request has to reach all three of them.

  The invariant to enforce is therefore: *for a row to be erasable by one request, the tenant its
  data key was derived under, the tenant its index was derived under, and the value in its
  `tenantColumn` are one value.* Derive under `state[tenantColumn]` by all means - it documents
  itself, "key it under what the erasure will match" - but pair it with a write-time refusal when
  `Scope.tenantFor(index.ofFieldName())` is not equal to that value, message naming both, the field
  and the column. With that refusal the two derivations are equal by construction and (a) and (b)
  stop being alternatives.

  On "(b) makes a legitimate shape unusable instead of correct": the shape it calls legitimate - a
  tenant column holding something other than the tenant the value's key was derived under - is not
  erasable under *any* keying this module can choose, because the erasure is asked for one tenant
  and one subject. Refusing it at the write, loudly, naming both values, is the correct outcome and
  not a degradation. An application that genuinely needs an acting organisation distinct from an
  owning one must declare the `@Shredded` tenant as the owning one, which is what its tenant column
  holds, and that shape then works.

**5. Verify inside the erasure transaction rather than assume, in two parts.** After the `UPDATE`s
and before the record is appended, per indexed table:

  - `SELECT count(*) WHERE tenantColumn = ? AND subjectColumn = ? AND idx IS NOT NULL` must be zero,
    and the erasure is **refused** if it is not. It should be trivially zero - which is the point: it
    is the only runtime evidence that the `UPDATE` this module issued did what its row count claimed,
    against a table that may carry a trigger, a rule, a view or a rewritten column since the scan.
  - `SELECT count(*) WHERE subjectColumn = ? AND tenantColumn <> ? AND idx IS NOT NULL` is a **WARN**
    with the count, never a refusal: those rows may legitimately belong to a different tenant that
    happens to use the same subject identifier, and refusing would make one tenant's data block
    another tenant's erasure. But when they are the same person - change 7's bulk-update residual,
    among others - this line is the only place anyone will ever see it. Word it as "this subject also
    has N blind index value(s) under other tenant values, which this erasure does not destroy".

**6. No compatibility path for rows written under the old keying.** The branch is unreleased. Do not
build an erasure that tries the old tenant as well as the new one: an erasure that searches for an
index under two keys is an erasure that will keep finding reasons to search under a third. State in
the addendum that the change is a clean break, and that any pre-existing deployment (there are none)
would rebuild its index columns.

**7. State the residual the module cannot see, and pair it with change 5.** A bulk `UPDATE t SET
tenant_id = ?` in JPQL or native SQL fires no `onPreUpdate` and re-derives nothing, so a row moved
that way keeps an index under its old tenant and becomes unreachable to its own erasure again. The
module cannot detect it at write time; change 5's second half surfaces it at erasure time, which is the
moment anyone can act on it. `SECURITY-NOTES.md` states it beside the blind-index control, in one sentence: *a row whose
tenant column is changed by a bulk update outside Hibernate keeps an index derived under its former
tenant, and the erasure refuses rather than reporting success.*

**On relaxing S-7's startup refusal.** Agreed, and change 4 is what makes it safe: with the
write-time equality refusal in force, a `@Shredded(tenant = ...)` on an indexed field is allowed
exactly when its value is the value in the row's tenant column, checked per row per write rather
than guessed at scan time. Keep the startup refusal until change 4 is green.

**Probe list.** The addendum's six are right. Add: the `CipherProbeBlindIndexAmbientTenantTest`
shape above (no declared tenant anywhere, ambient tenant differing from the column) cleared by the
erasure; a write whose field tenant and column value disagree refused, naming both (change 4); a
`tenantColumn` naming a column that maps to two properties, and one that maps to none, refused at
startup (change 1); an erasure that finds an index still populated refused rather than recorded
(change 5); and the blind-index *query* helper still finding a row it wrote, since change 4 moves
what the query must compute under.

### Addendum 3 as built (2026-09-10, Thor)

All seven changes applied, each marked in the code with the section number below.

**§3.1 — change 1 (column, not property).** `tenantColumn` is resolved to a property through the
persister's own column mapping, case-insensitively and allowing a quoted identifier, in
`ShreddedModel.resolveTenantColumns`/`resolveTenantProperty`, once, during the startup scan. It must
yield **exactly one** property that is basic, `String`-typed, mapped to the entity's primary table
(the table the erasure's `UPDATE` names), not a formula, not the identifier and not itself
`@Shredded`; a match found only inside an `@Embeddable` or an `@ElementCollection` is refused with
that path in the message. Every refusal is `SHRED-CONFIG-001` naming entity, index field,
`tenantColumn` and what was found. The recommendation as written (`@BlindIndex(tenantColumn =
"tenant_id")` looked up among property names) would have refused every correct configuration:
`CipherProbeBlindIndexTenantColumnTest.probe_a_column_name_over_a_camel_case_property_starts_up` is
that regression, and it boots.

**§3.2 — change 2 (one resolution, one object).** The resolved property lives on `BlindIndexColumn`
(`tenantProperty`, an `Optional<String>` beside the `tenantColumn` it came from), so the write path
reads the property and the erasure path reads the column off one object.
`JdbcErasureStore` is constructed from exactly those objects (`model.blindIndexColumns()`).
`ShreddingStartupCheck` refuses an unresolved one, so a model built without an
`EntityManagerFactory` cannot silently write indexes under something nobody resolved. Probe:
`CipherProbeBlindIndexAmbientTenantTest.probe_one_object_carries_the_column_the_erasure_matches_and_the_property_the_write_reads`.

**§3.3 — change 3 (null, blank, non-`String` at write time).** `ShreddingEventListener.rowTenant`
refuses with `SHRED-UNVERIFIED-WRITE` (the closer vocabulary, as change 3 allows), naming entity,
index field and column. Two probes, on a fixture whose tenant column is deliberately nullable.

**§3.4 — change 4 (the one that closes S-13).** `writeBlindIndexes` refuses the write when
`Scope.tenantFor(index.ofFieldName())` is not equal to the row's `tenantColumn` value, naming both,
the field and the column; the index is then derived under that column value, so the two derivations
are equal by construction and (a) and (b) stop being alternatives. Cipher's repro
(`CipherProbeBlindIndexAmbientTenantTest`) was RED on `c6009aa` and is green as a **refusal**: the
shape it used - a tenant column holding something other than the tenant the value's key is derived
under - is erasable under no keying this module can choose, and it never reaches the table.
`OwnedNote` in the same file is that application shape declared correctly (`@Shredded(tenant =
"#{tenantId}")`, the owning organisation), and it erases key, ciphertext and index together, with no
index bytes left under any tenant value the row ever carried. S-7's startup refusal is relaxed on
change 4's terms; `CipherProbeBlindIndexTenantTest` is rewritten from "this mapping is refused at
boot" to "this row is refused at the write, and the agreeing row is written and erasable".

**§3.5 — change 5 (verify inside the erasure transaction).** `JdbcErasureStore.verifyCleared`, after
the `UPDATE`s and before the record is appended, per indexed table: a residual count for this
(tenant, subject) that is not zero **refuses** the erasure with the new `SHRED-ERASURE-004` and
rolls the transaction back, key destruction and record included; the same subject under a different
tenant value (`IS DISTINCT FROM`, so a null tenant column is counted) is a **WARN** with the count,
never a refusal. Probes: a `BEFORE UPDATE` trigger that puts the index straight back, and a second
row of the same subject under another tenant.

**§3.6 — change 6 (clean break).** The branch is unreleased and there is no compatibility path: an
erasure that searches for an index under two keys is an erasure that will keep finding reasons to
search under a third. Any pre-existing deployment (there are none) would rebuild its index columns.
Nothing in the code tries the old keying.

**§3.7 — change 7 (the residual the module cannot see).** Stated in `SECURITY-NOTES.md` beside the
blind-index control, paired with §3.5's WARN, which is where it surfaces. A tenant move made
*through* Hibernate is refused outright by the subject-immutability check (the tenant is in every
stored value's header), so the bulk update outside Hibernate is the only way a row's tenant column
can change under a live index -
`CipherProbeBlindIndexAmbientTenantTest.probe_a_row_cannot_be_moved_between_tenants_through_hibernate`
records that, so "the index follows the row" is checked rather than assumed.

### Addendum 3, change 8: the subject axis (2026-09-10, Thor — Cipher S-20)

**The invariant, in one line.** *For a row to be erasable by one request, the tenant and subject its
data key was derived under, the tenant and subject its index was derived under, and the values in
its `tenantColumn` and `subjectColumn` are one pair.*

Changes 1–4 bound the tenant half of that pair to the row. `subjectColumn` was left as S-13 found
`tenantColumn`: validated as a SQL identifier, interpolated into the erasure's `WHERE` and into both
of `verifyCleared`'s queries, and never resolved, never read at write time, never compared with
`Scope.subject()`. Change 8 applies changes 1, 2, 3 and 4 to it verbatim. It is not a new mechanism.

- **§3.8a (change 1, one column over).** `ShreddedModel.resolveSubjectProperty` resolves
  `subjectColumn` to a property through the persister's own column mapping, with
  `resolveTenantProperty`'s rules: exactly one match, basic, `String`, on the entity's primary
  table, not a formula, not itself `@Shredded`, not inside a component or an element collection.
  Every refusal is `SHRED-CONFIG-001` naming entity, index field, `subjectColumn` and what was
  found. The two resolvers are one method parameterised by axis, so the rules cannot drift apart.
- **The identifier case, decided.** Cipher left it open: the subject column *may* be the entity's
  identifier, and if it is, the write path must read the id or refuse and say so. **It is refused,
  explicitly.** Two reasons, both stated in the message. The identifier is not in the state array
  the write path reads, and under `GenerationType.IDENTITY` it does not exist at all at the moment
  `onPreInsert` derives the index. And `Scope.subject()` is a `SubjectId` — a string — while an
  identifier is a `Long`, a `UUID` or a `byte[]` as often as not, so the comparison change 8 exists
  to make would need a rendering this module would have to invent. An invented rendering is the same
  class of guess as a guessed row binding. An application that wants its id to be the subject maps
  it as an ordinary basic `String` property beside the id, or names that property's column.
- **§3.8b (change 2).** `BlindIndexColumn.subjectProperty`, an `Optional<String>` beside
  `subjectColumn`, on the same record as `tenantProperty`, resolved once, read by the write path
  (the property) and by the erasure path (the column). `ShreddingStartupCheck` refuses an unresolved
  one exactly as it refuses an unresolved `tenantProperty`.
- **§3.8c (change 3).** `ShreddingEventListener.rowSubject` refuses with `SHRED-UNVERIFIED-WRITE`
  when the state array's value for that property is null, blank or not a `String`.
- **§3.8d (change 4, the one that closes S-20).** `writeBlindIndexes` refuses the write when
  `scope.subject().value()` is not equal to the row's `subjectColumn` value, naming both, the field
  and the column, before any derivation. As on the tenant axis, deriving under the column value
  instead would only move the gap: the data key is per `(tenant, subject)`, so an index derived
  under a subject the key was not derived under is reachable by an erasure that destroys no key, and
  the key's own erasure reaches no index.

**Acceptance set, and the deviation it forces.** Cipher's two probes
(`CipherProbeBlindIndexSubjectColumnTest`) are promoted and green **as a refusal**, and this is the
same deviation, for the same reason, as change 4's on `Note`: `SplitNote`'s shape — a subject column
holding an owner reference while `@Shredded(subject = ...)` evaluates to a customer reference — is
erasable under no keying this module can choose, so the probe's original assertion (that the erasure
clears the index) is unbuildable on that fixture. Both probe methods now assert that the write never
reaches the table, so no HMAC of the plaintext exists to survive; `AlignedNote`, in the same file, is
the same application shape declared correctly (`subjectColumn = "customer_ref"`, the column the
subject expression reads) and erases key, ciphertext and index together, with no index bytes left
under any subject value the row ever carried. `CipherProbeBlindIndexSubjectColumnStartupTest` covers
one startup branch per refusal, plus the camel-case regression that must boot.
`CipherProbeBlindIndexAmbientTenantTest` and `CipherProbeBlindIndexTenantColumnTest` are unchanged
and green.

### Addendum 3, change 9: address the qualified table (2026-09-10, Thor — Cipher S-21)

**Direction taken: address the qualified table.** Cipher offered two, and refusing every
schema-qualified deployment would refuse `hibernate.default_schema`, which is how a large share of
enterprise deployments name their schema — a library that cannot boot there is not a library.

`ShreddedModel.tableName(Class)` read `@Table(name = ...)` and ignored `schema`, so every statement
this module builds for a user table — the blind-index `UPDATE`, `verifyCleared`'s two queries, the
post-hoc read-back, the `IDENTITY` rebind and the subject-immutability `SELECT` — named an
unqualified identifier and let the runtime connection's `search_path` decide which table it hit.

- **§3.9a.** New domain type `TableRef` (`schema`, `name`), parsed from Hibernate's own table
  expression: split on `.` outside quotes, unquote each part, each part validated against the
  identifier pattern `BlindIndexColumn` already uses. A quoted part that is not already folded
  lowercase is refused with `SHRED-CONFIG-001` saying so, rather than silently lowercased into
  another table's name. `sql()` renders `"schema"."name"`, quoted per part; `toString()` renders it
  for messages.
- **§3.9b.** `ShreddedModel.resolveTables` takes the table from the persister
  (`getMappedTableDetails().getTableName()`) for every `@Shredded` entity — indexed or not — and
  from the attribute's own `getContainingTableExpression()` for every `@Shredded` field, at startup,
  from the same metamodel change 1 already reads. `ShreddedField.table()` and
  `BlindIndexColumn.table()` are `TableRef`s from then on and `tableName(Class)` has no callers
  left. The annotation-derived name survives only as the provisional value for a model scanned
  without an `EntityManagerFactory` (this module's own unit tests), which writes no SQL.
- **§3.9c.** The `@SecondaryTable` refusal becomes real. It compared `tableName(type)` against
  itself — one value per entity, so `distinct().count()` was always 1 and the check could never
  fire. It now compares each shredded field's containing table against the entity's primary table,
  which is what it always meant to say, and it fires for a single `@Shredded` field too.
- **§3.9d.** Change 1's primary-table comparison stops misfiring. It compared a persister table
  expression (`public.owned_note` under `default_schema`) against an annotation-derived name
  (`owned_note`) and refused every `@BlindIndex` in such a deployment with a message about a
  secondary table that did not exist. Both sides are now `TableRef`s from the same source.
- **Residual, stated.** With neither `@Table(schema)` nor `hibernate.default_schema` set, Hibernate's
  own table expression is unqualified and this module's statements are too, so `search_path` still
  decides — as it does for Hibernate's own statements, which is the point: the module addresses
  exactly the table Hibernate addresses. This module's own `shredding_*` tables are unqualified
  deliberately and are expected on the runtime role's `search_path`. One sentence in
  `SECURITY-NOTES.md`.

**Acceptance set.** `CipherProbeNinthPassBlindIndexTest` promoted, all four methods green:
`@Table(schema = "app2")` now boots, writes and erases (its `probe_..._erased_or_refused_at_startup`
takes the erasure branch), `hibernate.default_schema` boots, and the two surfaces Cipher cleared
stay cleared. Plus the K1 probe Cipher did not build:
`probe_a_same_named_table_in_another_schema_earlier_on_the_search_path_is_not_touched` — a decoy
`schema_note` in `public`, ahead of `app2` on `search_path`, holding a row with the same owner id
and a live index column, which the erasure must leave untouched while clearing the real one.

## Design addendum 4: column identifiers (2026-09-10, revised after Cipher's review)

**Property (S-22, S-24).** *Every identifier interpolated into SQL addresses the column Hibernate's mapping addresses, or startup refuses
naming the mapping; and no erasure records `COMPLETE` unless Hibernate, on the erasure's own connection, sees a residual of zero.*

- **§4.1 `ColumnRef(String text, boolean quoted)`, core domain, JDK-only** (applied §4.13). It does not mirror `TableRef`, which imposes a
  quoting decision; `ColumnRef` reproduces Hibernate's. `sql()` renders `text` bare when unquoted, `"`-wrapped when quoted — never
  blanket-quoted, and a non-lowercase *unquoted* name is legal and stays bare so PostgreSQL folds it (applied §4.2). No `"` in `text`.
  Javadoc as `TableRef`'s: PostgreSQL only, any other dialect refused at startup.
- **§4.2 The parse is Hibernate's** (applied §4.1). Built only from the persister's `BasicValuedModelPart` (`getIdentifierMapping()`'s for
  the id). `getSelectionExpression()` is a dialect-quoted fragment, so it is parsed by `identifierHelper().toIdentifier(expr)` into
  `(getText(), isQuoted())` and never unquoted by hand; startup asserts both round-trips, `Identifier.render(dialect)` and `ColumnRef.sql()`
  equal to the original expression. Refused there, naming property and reason: `isFormula()` as a *flag*, `Column.assignmentExpression`, and
  a custom read or write expression (`@ColumnTransformer`) on any of the three columns — it mis-addresses by value as S-22 did by name
  (applied §4.3, §4.4).
- **§4.3 Annotation text is a lookup key, never an identifier.** `subjectColumn`/`tenantColumn` match the mapped columns case-sensitively,
  with no case-insensitive second pass, ever (applied §4.7); `@Shredded`'s column resolves by property name, its text never compared
  (applied §4.5). Refusals: unknown column, listing the mapped columns verbatim with their quoting and naming those differing *only by case*
  (applied §4.7); more than one property; the identifier; and by their real reason an association/`@JoinColumn` and a composite id in
  `singleIdColumn` (applied §4.6). `BlindIndexColumn.identifier`, `ShreddedModel.columnName(Field)`, `.unquote` and the two starter
  `quote()` helpers go; `singleIdColumn` returns a `ColumnRef`.
- **§4.4 Every statement takes `TableRef` + `ColumnRef` and nothing else** — blind-index `UPDATE`, both `verifyCleared` queries, header
  read-back, `IDENTITY` rebind, subject-immutability `SELECT`; no `String` identifier survives in a signature.
- **§4.5 The read-back is a Hibernate-rendered residual, not a count comparison** (applied §4.8). After the `UPDATE`, unconditionally, not
  only when `cleared=0` (applied §4.11): HQL rendered by Hibernate over the entity, subject and tenant bound as parameters, the index column
  reached through the persister's reference, counts the subject's rows whose index is not null. Zero passes; above zero refuses
  `SHRED-ERASURE-004` (`ErrorCodes.ERASURE_INDEX_RESIDUAL`), rolls the whole transaction back, destroys no key, records no `COMPLETE`. Row
  counts are never a refusal predicate — `AND <col> IS NOT NULL` makes `cleared` a subset of the subject's rows, so a nullable index or a
  retry is normal; `cleared` stays a logged diagnostic. The count runs on the erasure's own `Connection` through a `StatelessSession` bound
  to it: never a second connection, never a session that can flush (applied §4.9); if Hibernate cannot render onto it, stop and say so.
  Intended under READ COMMITTED, REPEATABLE READ and SERIALIZABLE: a row committed for the subject after the `UPDATE`'s snapshot refuses the
  erasure and is not a race to retry away (applied §4.10). Cost is one indexed `COUNT` per (erasure, blind-index column), measured and the
  number recorded here.
- **§4.6 `hibernate.globally_quoted_identifiers=true`, decided here** (applied §4.12): columns supported, every expression arrives quoted and
  §4.2 reproduces it verbatim; tables supported when the quoted parts are lowercase, else refused at startup by `TableRef` naming the setting.

**Probes, written before the hook**, all in the default build (`-Pprobes-pending` empty afterwards), Cipher's five in
`CipherProbeTenthPassTest` promoted and green by their real assertions, plus, one per §4.3 path:

`probe_a_quoted_mixed_case_column_boots_and_is_addressed_quoted` · `probe_an_unquoted_upper_case_column_is_addressed_folded`
`probe_a_reserved_word_column_quoted_by_the_mapping_is_cleared` · `probe_a_column_lookup_key_differing_only_by_case_is_refused_naming_the_case_only_match`
`probe_a_formula_column_is_refused_by_its_flag` (also `@Formula("owner_id")`) · `probe_a_column_transformer_on_the_subject_column_is_refused_at_startup` (and on the index column)
`probe_a_join_column_named_as_the_subject_column_is_refused_as_an_association` · `probe_a_column_name_containing_a_quote_character_is_refused` (on the parsed text)
`probe_a_quoted_column_whose_name_contains_a_dot_is_addressed_whole` · `probe_a_quoted_shredded_column_is_settled_at_startup_not_at_the_first_write`
`probe_a_composite_identifier_is_refused_by_its_real_reason` · `probe_globally_quoted_identifiers_boots_or_is_refused_by_its_real_reason`
*Read-back independence.* `probe_a_mis_addressed_erasure_is_caught_by_the_hibernate_rendered_residual` · `probe_a_partially_null_index_erases_without_refusing`
`probe_the_independence_check_takes_no_second_connection` · `probe_the_independence_check_cannot_flush_pending_writes`
`probe_a_row_inserted_for_the_subject_after_the_clear_refuses_the_erasure`
*Architecture.* ArchUnit: `ColumnRef`, like every core domain type, imports nothing outside the JDK.

### Cipher review of addendum 4

**APPROVED WITH CHANGES (13).** The shape is right: one type, built from the mapping, annotation text
demoted to a lookup key, every helper that quoted or unquoted by hand deleted, every statement
signature refusing a bare `String`. That closes S-22's root and S-24 with it. But §4a is built on a
factual error about what `getSelectionExpression()` returns, and as written it refuses the very
column its own required probe says must work; and §4d's check (i), as specified, refuses ordinary
erasures. Both are load-bearing, so this is not a nod-through.

#### The factual error, first, because changes 1-3 all follow from it

`SelectableMappingImpl.from(...)` sets `columnExpression = selectable.getText(dialect)` for a
column, and `org.hibernate.mapping.Column.getText(Dialect)` is
`assignmentExpression != null ? assignmentExpression : getQuotedName(dialect)`, where
`getQuotedName(Dialect)` is `dialect.openQuote() + name + dialect.closeQuote()` when `quoted`
(hibernate-core 7.4.5, the version this branch resolves through Spring Boot 4.1.1). So
`getSelectionExpression()` for `@Column(name = "\"Owner\"")` is literally `"Owner"`, **quote
characters included** — it is a SQL fragment, not a name. `getSelectableName()` is no better: its
`SelectablePath` is built from the same expression, or from `column.getQuotedName(dialect)`. There
is no unquoted name on the runtime mapping.

1. **`ColumnRef` carries `(text, quoted)`, and the parse is Hibernate's, not ours.** §4a's "`sql()`
   … admits no quote character in the name" applied to the raw selection expression refuses every
   quoted column — including the `"Owner"` probe §4a's own probe list requires. The only two ways
   out are to unquote by hand (the `ShreddedModel.unquote` §4b deletes, back again, and it is where
   S-22 hid) or to use Hibernate's own parse/render pair. Use the pair:
   `jdbcEnvironment.getIdentifierHelper().toIdentifier(selectionExpression)` gives an `Identifier`
   with `getText()` and `isQuoted()`; `Identifier.render(dialect)` renders it back. The refusal of a
   quote character then applies to `getText()`, where it belongs, and the injection guard is
   unweakened. Drop the "mirroring `TableRef`" framing wherever it means *re-rendering*: `TableRef`
   imposes a quoting decision, `ColumnRef` must reproduce Hibernate's.
2. **Quote if and only if the mapping quotes. Do not blanket-quote, and do not refuse mixed case.**
   `@Column(name = "OWNER_ID")` — unquoted, upper case, ordinary code — has `quoted=false`, text
   `OWNER_ID`, and the column PostgreSQL actually created is `owner_id`. Rendering `"OWNER_ID"`
   addresses a column that does not exist: startup passes and the erasure fails at erasure time.
   `sql()` must render exactly what Hibernate renders — bare when the mapping is unquoted, quoted
   when it is quoted. And unlike `TableRef.part`, `ColumnRef` must **not** refuse a non-lowercase
   unquoted name: that is a legal mapping addressing a folded column, and refusing it makes the
   module unusable on a large share of real entities. Mixed case is refused only where it is quoted
   *and* the module cannot render it verbatim.
3. **Refuse a formula on `isFormula()`, and on `assignmentExpression`, not on the text's shape.**
   §4a refuses "a selection expression that is not a plain identifier". `SelectableMapping.isFormula()`
   is a flag: test the flag. Today a `@Formula` arrives as a template containing `$PlaceHolder$`, so
   a shape test happens to work; that is a Hibernate internal, not a control, and
   `@Formula("owner_id")` is one refactor away from being a plain identifier. The second
   non-identifier door §4a misses entirely is `Column.assignmentExpression`: when it is set,
   `getText(dialect)` returns arbitrary SQL and never touches the name. Refuse both, naming the
   property.
4. **`@ColumnTransformer` is S-22's consequence through a door `ColumnRef` leaves open.** A subject
   or tenant column with `@ColumnTransformer(read = …, write = …)` has a perfectly plain identifier
   and stores something other than the value this module binds, so `WHERE subject_col = ?` matches
   nothing — mis-addressed by value instead of by name, with the same recorded `COMPLETE`. On the
   index column, a write expression also means `SET col = NULL` is not what Hibernate would write.
   Refuse at startup any of the three columns whose `SelectableMapping` has a non-null
   `getCustomReadExpression()` or custom write expression, naming the transformer.
5. **`@Shredded`'s column is resolved from the property, not matched from text at all.** §4b deletes
   `ShreddedModel.columnName(Field)`, which is right, but a `@Shredded` field *is* a mapped basic
   attribute (it carries the converter), so the persister already has its `BasicValuedModelPart`
   under the property name. Resolve it by property name and never compare annotation text for this
   one. That closes S-24 by construction rather than by a better refusal.
6. **Associations and the composite id are refused by their real reason.** `subjectColumn` or
   `tenantColumn` naming a `@JoinColumn` resolves to a `ToOneAttributeMapping`, not a
   `BasicValuedModelPart`, so under §4b it falls into "no column of that name, here are the ones I
   map" — which is false and sends the developer looking for a typo. Say the column is mapped by an
   association and that this module binds a basic property. Same standard for a composite
   `getIdentifierMapping()` in `singleIdColumn`. This is S-23's standard applied ahead of time.
7. **The case-sensitive lookup key stays — the refusal message is the whole control.** The trap is
   real and symmetric: `subjectColumn="OWNER_ID"` against a mapping that stores `owner_id`, and
   `subjectColumn="owner_id"` against a mapping that stores `OWNER_ID` for the same physical column,
   both refuse. Fail-closed is correct and no case-insensitive second pass may be added, not even as
   a warning — a second pass is the fold, back again. But the refusal must (a) list the mapped
   columns verbatim with their quoting, (b) say the match is case-sensitive against the *mapping*
   and not against the database, and (c) name the mapped columns that differ from the given text
   **only by case**. Without (c) the operator compares forty names by eye and guesses.
8. **§4d check (i) is specified wrong and would refuse legitimate erasures.** The `UPDATE` in
   `JdbcErasureStore.clearBlindIndexes` ends `AND <col> IS NOT NULL`, so its row count is the
   subject's rows *with a populated index* — always a subset of "the subject's rows". A nullable
   indexed field, a row written before the index column existed, a retry after a partial failure:
   each gives `cleared < count` with nothing wrong, and "mismatch → refuse" turns that into a
   fail-closed denial of erasure. The invariant to verify is not an equality of counts. It is:
   **after the `UPDATE`, a count rendered by Hibernate over the entity, with subject and tenant
   bound as parameters and the index column read through the persister's own reference, returns
   zero; anything above zero refuses.** That is §4d (ii) done properly and it subsumes (i): a
   mis-addressed `UPDATE` clears nothing, Hibernate's count still sees the row, the erasure refuses.
   Keep a count of the subject's rows if you want it, as a logged diagnostic, never as a refusal
   predicate.
9. **The independent count runs on the erasure's own connection and transaction, and must not be
   able to write.** A `Session` taken from the pool is a second connection, and every property §4d
   wants dies on it: it cannot see the uncommitted `UPDATE`; it takes a later snapshot, so under
   READ COMMITTED a concurrent commit makes the two disagree for no reason; it may carry a different
   `search_path`, which re-opens S-21's decoy on the verification side; and it is requested while
   this transaction holds `pg_advisory_xact_lock` and `SELECT … FOR UPDATE` rows, so a pool of one
   deadlocks. Worse, a stateful auto-flushing session flushes pending entity state at the query and
   can write blind indexes back **after** the clear. Required: Hibernate's SQL executed on
   `Connection c` — a `StatelessSession` built with `.connection(c)`, or the rendered SQL run on `c`
   — never a second connection, never a session that can flush. If Hibernate cannot be made to
   render onto this connection, stop and say so; do not quietly take a second one.
10. **Concurrency, stated as intent rather than tolerated as a race.** With change 9 applied both
    statements share one snapshot, so the only remaining divergence is a row committed for the
    subject after the `UPDATE`'s snapshot. With change 8 applied the answer is already right: a new
    row carrying a populated index for a subject whose key has just been destroyed **must** refuse
    the erasure. Write that into the design as the intended behaviour under READ COMMITTED,
    REPEATABLE READ and SERIALIZABLE, so nobody later "fixes" it into a retry.
11. **Ruling on the open point: unconditional. Not "only when `cleared=0`".** Three reasons.
    (a) `cleared=0` is not the only wrong answer — a mis-addressed *tenant* column clears a subset,
    not nothing, and the conditional check never fires on the case that costs a tenant their
    isolation. (b) A check that runs only on the failure path is never exercised by production or by
    a happy-path test, and it rots; every control in this module that mattered was one that ran
    every time. (c) The cost is one `COUNT` per (erasure, blind-index column), on indexed columns,
    on a connection that already holds the row locks, inside a transaction that already does an
    advisory lock, a `SELECT … FOR UPDATE`, a `DELETE`, a tombstone insert and a hash-chain append.
    Erasure is rare and human-initiated. Measure it and put the number in the design. If it is ever
    too slow the answer is an index on `(tenant, subject)`, not a control that switches itself off.
12. **`hibernate.globally_quoted_identifiers=true` is a named path, decided here.** It quotes every
    identifier, so every column expression *and* every table expression arrives quoted, which
    changes the answer for the whole module at once. The design must say what happens — supported,
    or refused at startup by an accurate message — and one probe must boot an application with it
    set. Discovering it at the first erasure is the S-24 pattern.
13. **`ColumnRef` stays JDK-only.** It is core domain: no `Identifier`, no `Dialect`, no Hibernate
    type on the record. The parse and the classification happen in the starter; the record carries
    `(String text, boolean quoted)` and renders with a `"` literal, PostgreSQL being the only
    dialect this module supports — state that in its javadoc as `TableRef` states it for tables, and
    state what happens if another dialect boots.

#### Probes I require

All in the default build, none in `src/test-pending/java` when the work lands; `-Pprobes-pending`
empty afterwards. Cipher's five in `CipherProbeTenthPassTest` promoted and green **by their real
assertions**, plus:

*Identifier resolution (one per §4b path, per the framework integration rule).*
`probe_a_quoted_mixed_case_column_boots_and_is_addressed_quoted` — `@Column(name = "\"Owner\"")` as
`subjectColumn`, **no** mapped lowercase twin, a legacy `owner` column present in the table: write,
erase, the index clears and the legacy column is untouched (change 2).
`probe_an_unquoted_upper_case_column_is_addressed_folded` — `@Column(name = "OWNER_ID")`: the
rendered SQL carries `owner_id` unquoted, never `"OWNER_ID"`, and the erasure clears (change 2).
`probe_a_reserved_word_column_quoted_by_the_mapping_is_cleared` — the S-22 repro `KeywordNote`,
green by `blindIndexColumnsCleared=1` and residual zero.
`probe_a_column_lookup_key_differing_only_by_case_is_refused_naming_the_case_only_match` (change 7).
`probe_a_formula_column_is_refused_by_its_flag`, with a `@Formula("owner_id")` variant that is a
plain identifier (change 3).
`probe_a_column_transformer_on_the_subject_column_is_refused_at_startup`, and the same on the index
column (change 4).
`probe_a_join_column_named_as_the_subject_column_is_refused_as_an_association` (change 6).
`probe_a_column_name_containing_a_quote_character_is_refused` — asserted on the parsed text.
`probe_a_quoted_column_whose_name_contains_a_dot_is_addressed_whole` — Thor's, kept.
`probe_a_quoted_shredded_column_is_settled_at_startup_not_at_the_first_write` — S-24, green by the
design's choice, never by a `PSQLException` out of `saveAndFlush` (change 5).
`probe_a_composite_identifier_is_refused_by_its_real_reason` — the `singleIdColumn` path (change 6).
`probe_globally_quoted_identifiers_boots_or_is_refused_by_its_real_reason` (change 12).

*Read-back independence.*
`probe_a_mis_addressed_erasure_is_caught_by_the_hibernate_rendered_residual` — swap the erasure's
`ColumnRef` for a decoy so the `UPDATE` matches nothing: `SHRED-ERASURE-004` (`ErrorCodes.ERASURE_INDEX_RESIDUAL`), whole
transaction rolled back, no key destroyed, no record appended, no `COMPLETE`. This is the probe that
fails the moment the residual is ever rebuilt from the erasure's own text.
`probe_a_partially_null_index_erases_without_refusing` — two rows for the subject, one with a null
index: `cleared=1`, no refusal. Red against §4d check (i) as written; it pins change 8.
`probe_the_independence_check_takes_no_second_connection` — `maximum-pool-size=1`, the erasure
completes (change 9).
`probe_the_independence_check_cannot_flush_pending_writes` — a session dirty with an insert for the
erased subject at erasure time: no index is written after the clear (change 9).
`probe_a_row_inserted_for_the_subject_after_the_clear_refuses_the_erasure` (change 10).

*Architecture.* An ArchUnit assertion that `ColumnRef`, like every other core domain type, imports
nothing outside the JDK (change 13).

I review the revised addendum before any code. Changes 1, 2, 8 and 9 are the ones that decide
whether this closes S-22 or moves it; the rest are the surfaces the fix opens.
