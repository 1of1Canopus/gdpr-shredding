# Read-path design — ownership, row binding, cost

Thor, 2026-09-09, for Cipher before any code. Answers the fifth-pass design stop: C-33, C-39, C-40,
C-41 (one question), C-34, C-35 — all six reproduced here at `7efe689` with `./mvnw -Pprobes-pending
test` (7 failures: P1 `RETURNED [P1-CLEARALL-SECRET]`, P2 `RETURNED [ROW-A-VALUE, ROW-A-VALUE]`, P3
`200 rows, 401 statements`, unwind 21/200 bracket, 18/200 read scope, 0/200 write scope).

**Invariant.** No decrypted value is ever handed to application code without a verification recorded
against it, on any path, including error paths.

## 1. Ownership of per-thread state

The converter is blind — no session, no entity, no row, and no Hibernate 7.4 hook fires before it
(QUESTIONS #13/#16, twice accepted) — so state it consults must be thread-local. C-17/18/20/26/33/39/40
are one shape: the converter treats *presence of state* as *permission to return plaintext*.
Remove that authority rather than try again to perfect the ownership.

> **Ambient state may accuse. It may never authorise.**

- `convertToEntityAttribute` no longer returns plaintext. It decodes, decrypts, files
  `(header, plaintext)` into the current read region and returns a **placeholder**: the type's marker
  for `String`/`byte[]`, `null` for the types that cannot carry a sentinel (control 13's WARN list).
  The crypto is untouched. Plaintext is installed by `onPostLoad` alone — the one hook that knows the
  row (`event.getId()`, persister, session) — into the entity *and* the persistence context's loaded
  state, so dirty checking still compares plaintext to plaintext.
- Therefore **no state ⇒ no plaintext**, by construction not by accounting; **stale state ⇒ at worst
  a refusal or a stale value of the same row+field+subject**, never another subject's. C-39 and C-40
  stop being confidentiality findings.

| State | Created by | Destroyed by | Never cleared by |
|---|---|---|---|
| write scope | `onPreInsert`/`onPreUpdate`, tagged with the session | matching `Post*`, else that **session's own** after-completion callback | another session; any read path |
| read region (bracket + frame) | the repository proxy, or `withReadBracket` | the same call, by owner token | a transaction completion (C-33); another region |

- One `ThreadLocal<ShreddingState>`, two stacks, every entry carrying an owner token (write scopes
  also the session); `close(token)` unwinds to that token and refuses if it is absent. `clearAll()`
  is deleted; the transaction callback becomes `clearWriteScopesOwnedBy(session)`, which may not
  touch read regions — that alone closes C-33.
- **Session- or transaction-scoped storage: considered, rejected.** Ownership is session/call-scoped
  and now tagged as such; storage cannot be, because the converter cannot reach the session, so a
  session-keyed map still needs a thread-local to find it — the same object, one more indirection.
- **`StackOverflowError`/`Throwable` mid-unwind:** stop depending on unwind cleanup. A `finally` must
  *call* the pop, and at exhaustion that call throws again; no arrangement of `finally` fixes it
  (C-32 proved it). Entry points still restore stack sizes and the transaction callback still clears
  its own, but the argument rests on the placeholder rule. Residue on a pooled thread is bounded,
  cleared at the next region open, and can only cause `SHRED-READ-UNVERIFIED` or D6's stale value.
- **C-41 keeps its own answer**, because a wrong *write* scope is real authority: every flushed row
  is checked post-hoc in the same flush by the header re-read `refuseIfSubjectMoved` already does, so
  a row written under a stale subject is refused before commit, not left in the wrong erasure scope.

## 2. Framework integration matrix — one test per path, written before the hook

| Path | Outcome | Test |
|---|---|---|
| `find`, derived finder, JPQL/Criteria entity query, `Page`/`Slice` | verified by `onPostLoad`'s row-keyed install | `an_entity_load_installs_and_verifies_each_row` |
| `getReference`, lazy proxy init, eager association | verified on initialisation | `a_lazy_proxy_initialisation_is_verified` |
| ciphertext moved between subjects / tenants / rows | refused `SHRED-SUBJECT-MISMATCH` / `SHRED-ROW-MISMATCH` | CIPHER-01 probes + `probe_a_ciphertext_swapped_between_two_rows_of_one_subject_is_detected` |
| multi-row set: one row moved; two subjects | refused; both rows correct | `probe_a_moved_ciphertext_in_a_second_row_of_one_result_set`, `probe_two_rows_of_two_subjects_read_in_one_query` |
| scalar JPQL, `Tuple`, constructor DTO, interface projection, repository `@Query` | placeholder, then `SHRED-READ-UNVERIFIED` at region close | C-17 / C-18 probes, kept |
| `Stream`, `@Async`, consumption after the call returns | placeholder only; loudness may be absent, documented | `a_streaming_repository_method_yields_no_plaintext` |
| hand-written DAO, bare `EntityManager`, second EMF | placeholder unless an entity load on the instrumented EMF; >1 EMF refused at startup | `probe_a_second_entity_manager_factory_decrypts_a_moved_ciphertext` |
| native query | ciphertext; converter not invoked | existing |
| first-level-cache retry after a refusal | refused; instance evicted | `probe_a_refused_row_is_returned_on_the_retry_from_the_persistence_context` |
| second-level cache, `sharedCache.mode=ALL`, query cache | refused at startup | existing |
| embeddable, element collection, map key, `@OrderColumn` index | refused at startup `SHRED-CONFIG-001` | existing + C-37's probe |
| composite id, `@SecondaryTable`, `@Basic(fetch=LAZY)` | refused at startup | C-38's probe as a startup refusal; `a_lazy_shredded_field_is_refused_at_startup` |
| bulk JPQL update, detached write, criteria parameter | refused `SHRED-CONTEXT-001` | existing |
| a placeholder written back | refused `SHRED-PLACEHOLDER-001` | `a_placeholder_is_never_re_encrypted` |

## 3. Row binding (C-34)
The primary key is the only row identity an attacker holding `UPDATE` cannot forge; any extra
binding column travels with the ciphertext they copy. So **`rowId` (the canonical single-column
identifier) goes into the header and the value AAD**, format `SH1` v2 — no compatibility is owed on
an unreleased branch. It buys C-34, row-precise verification (C-26's whole class) and §4 at once.

The write path knows the row: `PreUpdateEvent.getId()`, and `PreInsertEvent.getId()` for assigned and
`SEQUENCE` ids. Under `@GeneratedValue(IDENTITY)` the id does not exist at bind time, so
`onPostInsert` — where it does — re-encrypts that row's shredded columns bound to the real id, one
`UPDATE`, same transaction. Refusing `IDENTITY` contradicts the CIPHER-16 ruling; leaving those rows
unbound leaves a permanent hole. **Assumption proved by a test before the hook**
(`the_insert_event_has_no_id_under_identity`); if the id is populated, the extra `UPDATE` is dropped.

## 4. Cost (C-35)

`onPostLoad` no longer re-reads the row. The converter already decrypted its bytes and files them
under `(entity, field, tenant, subject, rowId)` from the header; `onPostLoad` drains the key built
from `event.getId()` and the resolved subject and tenant, and a miss is an immediate refusal, not a
debt. **200-row list: 1 statement, 2 with a `Page` count, 0 per-row re-reads** — down from 401. The
write path keeps its one re-read per updated row, which now also carries C-41's post-hoc check;
batching it per flush is a later optimisation.

## 5. Deleted, kept, probes

**Deleted:** `clearAll()`; the whole read-scope stack (`READ_SCOPES`, `withRead`, `pushReadScope`/
`popReadScope`) — with no plaintext leaving the converter there is nothing to vouch for; the
`inReadBracket()` authority branch; `SHRED-READ-UNSCOPED`; `onPostLoad`'s `readStoredShreddedColumns`
call. **Kept:** the bracket `BeanPostProcessor` (loudness and the one-EMF check only), the frame as a
row-keyed multiset, `refuseIfSubjectMoved`, `refuseLoad`'s eviction, every startup refusal, the
reverse metamodel scan, all crypto and erasure code.
**New codes:** `SHRED-ROW-MISMATCH`, `SHRED-PLACEHOLDER-001`. **Probes:** the six pending ones move
to `src/test` expecting P1 refused, P2 `SHRED-ROW-MISMATCH`, P3 ≤ 2 statements for 200 rows and the
three unwind probes green — where one still leaks, its assertion becomes "leaks no plaintext", the
property this design can hold. C-37 and C-38 stay Isis's and are unaffected.

## 6. Open questions for Cipher

1. **D1.** Accept "the converter never returns plaintext; `onPostLoad` installs it"? Everything else
   follows. Recommendation: yes.
2. **D2.** A projection yields a placeholder or `null`, refused loudly only at region close and
   quiet outside one: fail-closed but silent. Recommendation: accept as a documented residual — the
   alternative is an authority I cannot make leak-proof.
3. **D3.** `IDENTITY` rows re-encrypted by a second `UPDATE` in the same transaction to bind the
   generated id. Recommendation: accept, subject to §3's assumption test.
4. **D4.** Installing plaintext in `onPostLoad` mutates the loaded state through Hibernate SPI.
   Recommendation: accept, with a load-then-flush probe proving no shredded column is rewritten.
5. **D5.** Format `SH1` v2, no migration path, unreleased branch. Recommendation: accept.
6. **D6.** After a `StackOverflowError`, residue can install a stale plaintext for the identical
   row+field+subject. Recommendation: a residual; removing it needs a liveness signal the JVM does
   not offer.
