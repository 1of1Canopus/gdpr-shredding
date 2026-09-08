# SECURITY-NOTES — GDPR Shredding

What this module protects against, what it does not, and what an operator has to do themselves.
Written for the person who will be asked, in an audit, "and how do you know the data is gone?"

Every finding below is a **residual**: documented on purpose, not engineered away, because the
alternative would be a control that cannot be made true. Cipher's spec review of 2026-09-08 is the
source; the numbered controls it defines are implemented and tested (see `docs/index.md`).

## What crypto-shredding actually claims

Each data subject's personal fields are encrypted under that subject's own 256-bit data key. To
erase, the key row is deleted. The ciphertext stays where it is, so the audit row, the accounting
row and the foreign key all survive; the personal data in them stops being readable.

That is a claim about **future access to live systems and to data-at-rest copies**. It is not a
claim that no plaintext copy exists anywhere.

## Residuals

### Wrapped-key resurrection
An insider who can read the key table can snapshot it before an erasure and restore the row
afterwards. The ciphertext never moved, so the plaintext comes straight back. This is the honest
bound of the whole technique and no amount of engineering inside this library closes it.
`probe_a_wrapped_key_row_restored_after_erasure_decrypts_the_value` asserts exactly this behaviour,
so nobody can later claim otherwise. Mitigate it operationally: separate the database role that can
read `shredding_data_key` from the role that runs the application, audit reads of that table, and
put the master key somewhere the same person cannot reach (a KMS, which is a Pro adapter).

### Backups, PITR archives, WAL, replicas and logical decoding slots
A base backup taken before the erasure holds the wrapped key. So does every WAL segment covering
the period, every streaming replica that has not caught up, and every logical-decoding slot.
The erasure is complete **only at `erasedAt + shredding.erasure.backup-retention`**, and the
erasure record states that date so the proof of erasure can print it. Set that property to your
real retention, not to a number that reads well.

### MVCC dead tuples
`DELETE` marks the row dead; the bytes stay in the heap page until `VACUUM` reclaims them, and a
`VACUUM FULL` or a page-level forensic read can still see them. This is also why the erasure is a
plain `DELETE` and not "overwrite, then delete": under MVCC the overwrite writes a *second* tuple
holding the same key and reclaims nothing, so it buys an assurance it cannot deliver.

### JVM memory
Heap dumps, core dumps and swap hold unwrapped data keys and decrypted plaintext. Key material is
held as `byte[]` and zeroised after use, never as `String`, but the JVM may have copied a buffer
before the wipe. Disable heap dumps on production, or treat a heap dump as personal data.

### Cache window across a cluster
Erasure evicts the local unwrapped-key cache immediately and publishes an invalidation, but another
node can hold the key for up to `shredding.data-key-cache.ttl` (default 60s). That window is real.
The proof of erasure states it. Shorten the TTL if 60 seconds is too long for you; there is no
setting that makes it zero on every node at once.

### The blind index
`@BlindIndex` makes equality lookups possible on an encrypted column, and equality lookups are a
leak. Even truncated to `shredding.blind-index.bits` (default 64) and even without any key, the
index is an equality and frequency oracle: identical values collide, so an attacker with the table
learns which rows share a value and how common each value is. Over a low-entropy field such as an
email address a full-width index would be an offline dictionary outright. Two consequences:

- the index is a **prefilter**; the query path always re-verifies by decrypting the candidates;
- **an erasure nulls the erased subject's blind-index columns**, always, with no property to turn
  that off. An index that survives an erasure keeps the erased subject searchable and linkable for
  ever, which defeats the product.

Do not put a blind index on a field you do not actually query by.

### The data subject of a persisted row is only checked when this process loaded it
Control 14 forbids a persisted row's data subject from changing: re-encrypting under another
subject's key would move the row out of the first subject's erasure scope, so their erasure would
leave it readable. Hibernate's `PreUpdateEvent` carries the hydrated Java state, not the stored
blob, so the previous subject cannot be read back from the row at that moment. The listener instead
remembers the subject each row loaded (or was inserted) under, in a per-thread map bounded to
10 000 entries, and refuses an update whose resolved subject differs.

The gap: if that entry has been evicted, or the entity is merged in a thread that never loaded it -
a detached object arriving from another request, say - the check cannot fire and the update is
allowed. This is a residual until Cipher chooses one of the two stricter designs in QUESTIONS #4
(a shadow subject column, or reading the stored blob in `PreUpdate` at the cost of a round trip per
shredded update).

### Erased subjects are tombstoned, and the tombstone holds no key material
`shredding_erased_subject` records `(tenant, subject, erased_at)` and nothing else. There is no key
in it, wrapped or otherwise: the key rows are deleted outright, exactly as control 6 requires, and
this table is not a copy of them.

It exists for one reason. A write that was merely blocked on the erasure's `SELECT ... FOR UPDATE`
resumes the moment the erasure commits, finds no key row, concludes the subject has no key yet, and
mints a fresh one - undoing the erasure inside a millisecond, with nothing in the erasure log to say
so. Found by `probe_concurrent_write_encrypts_under_a_destroying_key`. With the tombstone,
`JdbcKeyProvider.mint` refuses for an erased subject and the racing write fails with
`SHRED-ERASED-001`.

The tombstone is therefore part of what makes control 11 enforceable at all, not a weakening of
control 6. It does mean the set of erased subject ids is retained: an id, never a key, and the same
id the audit and accounting rows already carry, which is the whole point of the technique.

### What a proof of erasure attests
That a key was destroyed and when, chained and anchored so a later rewrite is detectable. It does
**not** attest that no plaintext copy exists in an application log, a CSV export, a search index, a
support ticket or a PDF the application itself produced. Those are the application's problem, and
`PostErasureHook` is the seam for dealing with them - which is why a failed hook makes the erasure
`PARTIAL` and never `COMPLETE`.

## Threats the module does close, and how

| Threat | Control |
|---|---|
| Data key re-derivable from the master, making erasure a no-op | keys are 256 random bits, never derived (control 1) |
| Entity/field name collision in the AAD | length-prefixed canonical AAD (control 2) |
| Nonce reuse under one key | random 96-bit nonce, per-key counter, hard refusal at 2^32 and rotation (control 3) |
| Plaintext fallback on an unrecognised column | strict format, typed error, no lenient parse (controls 4 and 17) |
| Master key in `/env`, `/configprops`, logs or `toString` | explicit exclusion, `byte[]` not `String`, never in a message (control 5) |
| Unprovable erasure or false proof | key deletion and the record in one transaction (control 6) |
| Key used after it was claimed by an erasure | state checked on read as well as write (control 7) |
| Rewritten erasure log | module B's keyed-from-birth chain, anchor row, append-only triggers (control 8) |
| Enumerable subject hash in the log | HMAC pseudonym with an HKDF-separated pepper (control 9) |
| Erased subject still searchable | erasure nulls the blind-index columns (control 10) |
| Hibernate re-writing a shredded column on flush | write refusal plus a byte-identical sentinel round trip (control 11) |
| Second-level cache serving plaintext after erasure | startup refusal unless explicitly allowed (control 12) |
| Silent `null` reads | one policy per application, `null` requires an explicit property and WARNs (control 13) |
| SpEL reaching a bean or a static type | `SimpleEvaluationContext`, parsed at bootstrap (control 14) |
| Cross-tenant key reuse for the same subject id | tenant in the key PK, the wrap AAD, the value AAD and the index subkey (control 15) |
| KMS outage read as an erasure | `KEY_UNAVAILABLE` and `KEY_DESTROYED` are different failures (control 16) |
| Half-migrated plaintext column | core refuses it; the batch migrator is Pro (control 17) |
| Crypto supply chain | JDK only, no BouncyCastle, no provider install (control 18) |
| Erasure reported complete while work is outstanding | a failed hook makes it `PARTIAL` (control 19) |
| A racing write minting a fresh key for an erased subject | the `shredding_erased_subject` tombstone, holding no key material (QUESTIONS #3) |
| A decrypted value reaching a generated `toString` | a record or Lombok-rendered `@Shredded` entity fails startup (QUESTIONS #9) |

## Operating notes

- **Back up the keys table separately from the data**, or use a KMS. A single backup that holds
  both is a backup that undoes every erasure it contains.
- **Run the application with a role that has INSERT and SELECT on `shredding_erasure`**, not the
  owner. The append-only triggers stop the runtime role; only the owner can disable them.
- **Never store `shredding.erasure-log.hmac-secret` beside the datasource password.** If one
  compromise yields both, the chain key is not a second factor, it is decoration. Module B's rule.
- **Losing the master key erases everyone.** The startup health check reports whether it can unwrap
  a known key; wire it into your readiness probe.
- The erasure-log HMAC secret is **not** a data key and is **never** destroyed by an erasure.
  Destroying it would break the very record that proves the erasure happened.
