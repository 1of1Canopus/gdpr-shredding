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

**200-row list: 1 statement, 2 with a `Page` count**, down from 401.

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
