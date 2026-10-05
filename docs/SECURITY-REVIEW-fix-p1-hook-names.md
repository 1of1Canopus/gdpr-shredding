# Security review: fix/p1-hook-name-code-points (PR 22)

## Pass 1 (2026-10-05), head 8134d70

**Verdict: MERGE WITH FIXES** (P-2, INFO).

### Build
`CIPHER_PROBE_MAVEN=1 ./mvnw -B verify`, Docker up: BUILD SUCCESS, 321 + 239 + 17 = 577 tests,
0 failures, 0 skipped. CI on 8134d70: Build & test, DCO, Reference guard, Vulnerability scan,
Release dry run green; Cipher probes still running at review time.

### P-1 (LOW), confirmed closed
`probe_non_bmp_hook_name_breaks_the_chain` is green. Decoder now steps by code point; the encoder
(`ErasureChain.field`) is unchanged.

### Attacks tried
| Attack | Result |
|---|---|
| 4-byte code points at field start, end, alone; empty name; name holding `\|4:true` and a surrogate pair | Round trip exact. |
| Record linked by the unchanged encoder (= what a 0.1.x writer stored) with non-BMP names, decoded and verified | Verifies. The hash binds the record objects, not the stored column, and the encoder did not change, so no record's hash changes. Before the fix such rows decoded INVALID / verified BROKEN; they were always validly written and now read correctly. The CHANGELOG entry says so. |
| Lone surrogates in name and detail | Encoder and decoder both count the UTF-8 replacement byte `?` (1 byte): boundary holds. PostgreSQL stores `?`, so `"a\uD800"` and `"a?"` share a hash. Writer-side input only (a DB attacker cannot store a lone surrogate); not a finding. |
| Length prefix ending inside a code point, longer than the remaining material, `-1`, `+1`, `01` | Accepted. P-2. |

### P-2 (INFO): decodeHooks accepts non-canonical length prefixes
The loop stops when the running count reaches **or passes** the declared length, the tail may run
out before the length is met, and `Integer.parseInt` accepts signs and leading zeros. A stored
`hook_outcomes` value that `hookMaterial` never writes therefore decodes instead of failing as
"not in canonical form". The chain hash binds the decoded objects, so the meaning of a record
cannot change undetected: severity INFO (malleable stored representation, contract not enforced).
Pre-existing for 2- and 3-byte characters; present in the loop this PR rewrites.

Repro: `internal/gdpr-shredding/probes/CipherProbeP1ReviewTest.java` (internal), three probes red
on 8134d70: `probe_length_prefix_ending_inside_a_code_point_is_accepted`,
`probe_length_prefix_longer_than_the_material_is_accepted`,
`probe_non_canonical_length_digits_are_accepted`; two regression tests green.

Fix (Isis, correction only): in `JdbcErasureStore.decodeHooks`, refuse the length text unless it
matches `0|[1-9][0-9]*` before parsing, and after the byte loop throw
`ShreddingException(ErrorCodes.INVALID, "hook_outcomes is not in canonical form")` when
`seen != byteLength`. Add the probe file to `gdpr-shredding-core/src/test/.../adapter/jdbc/` first.
Add a CHANGELOG line under the P-1 entry.
