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
