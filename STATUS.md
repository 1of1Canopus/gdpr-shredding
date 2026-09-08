# STATUS — GDPR Shredding free core

Branch `feat/shredding-core`. `main` holds the plan commit only.
Full `./mvnw -B clean verify` green with Docker up.

## Tasks

| # | Task | State |
|---|---|---|
| 1 | Plan (`docs/plans/core-plan.md`), committed to `main` | done |
| 2 | Build skeleton, `commit-msg` hook, CI, Dependabot, ArchUnit | done |
| 3 | Crypto primitives: HKDF, AES-GCM, canonical AAD, `EncryptedValue` | done |
| 4 | Keys: `KeyProvider` SPI, master key, bounded cache, per-key counter, rotation | done |
| 5 | Erasure chain, JDBC store, anchor, triggers, verifier | done |
| 6 | `ErasureService`, hooks, blind index, tombstone | done |
| 7 | Starter: converters, write-path listeners, SpEL, properties, startup refusals, actuator | done |
| 8 | Sample: customer, audit table, erasure endpoint, end-to-end proof | done |
| 9 | Docs, `SECURITY-NOTES.md`, `CHANGELOG.md`, `QUESTIONS.md`, draft PR | done |

## Tests

| Module | Tests | Notes |
|---|---|---|
| `gdpr-shredding-core` | 62 | includes 11 Cipher probes and the Testcontainers PostgreSQL suite |
| `gdpr-shredding-spring-boot-starter` | 12 | 3 Cipher probes |
| `gdpr-shredding-sample` | 10 | 3 Cipher probes, full Spring Boot context on Testcontainers PostgreSQL |
| **total** | **84** | |

Nothing is skipped and nothing is `@Disabled`.

## Coverage (`gdpr-shredding-core`, from `target/site/jacoco/jacoco.csv`)

| Counter | Covered | Total | % |
|---|---|---|---|
| LINE | 923 | 1107 | **83.4%** (gate 80%) |
| INSTRUCTION | 4543 | 5614 | 80.9% |
| METHOD | 185 | 222 | 83.3% |
| BRANCH | 229 | 402 | 57.0% |
| COMPLEXITY | 259 | 423 | 61.2% |

Branch coverage is the weak number. Most of the uncovered branches are defensive validation in
`EncryptedValue`, `Identifiers` and the JDBC mapping; the security-relevant ones are covered by the
probes.

## Cipher's 19 probes

All nineteen are written and green. Each was RED before its fix; where the control was part of the
first draft, RED was demonstrated by removing the control and re-running (evidence below).

| Probe | Where | State |
|---|---|---|
| `probe_a_wrapped_key_row_restored_after_erasure_decrypts_the_value` | core `CipherProbeErasureTest` | green (documented residual + asserts `SECURITY-NOTES.md` states it) |
| `probe_field_and_entity_names_collide_in_the_aad` | core `CipherProbeAadTest` | green |
| `probe_ciphertext_moved_between_rows_still_decrypts` | core `CipherProbeFieldCipherTest` | green |
| `probe_reading_an_erased_entity_rewrites_the_column_on_flush` | sample `SampleEndToEndTest` | green |
| `probe_second_level_cache_serves_plaintext_after_erasure` | starter `CipherProbeStartupTest` | green |
| `probe_entity_tostring_leaks_the_decrypted_value` | sample `SampleEndToEndTest` | green |
| `probe_blind_index_still_matches_the_erased_subject` | core `CipherProbeJdbcTest` | green |
| `probe_blind_index_matches_the_same_value_across_tenants` | core `CipherProbeBlindIndexTest` | green |
| `probe_spel_expression_reaches_a_bean_or_a_static_type` | starter `CipherProbeSpelTest` | green |
| `probe_changing_the_subject_expression_moves_a_row_out_of_erasure_scope` | sample `SampleEndToEndTest` | green |
| `probe_key_store_outage_reads_as_erased` | core `CipherProbeFieldCipherTest` | green |
| `probe_crash_between_key_destruction_and_the_erasure_record` | core `CipherProbeJdbcTest` | green |
| `probe_concurrent_write_encrypts_under_a_destroying_key` | core `CipherProbeJdbcTest` | green (found a real bug, see below) |
| `probe_an_unkeyed_or_unanchored_erasure_chain_reports_intact` | core `CipherProbeErasureTest` | green |
| `probe_tenant_b_decrypts_tenant_a_value_for_the_same_subject_id` | core `CipherProbeFieldCipherTest` | green |
| `probe_core_reads_a_plaintext_column_as_plaintext` | core `CipherProbeFormatTest` | green |
| `probe_master_key_appears_in_actuator_env` | starter `CipherProbeActuatorTest` | green |
| `probe_encryption_passes_the_per_key_2_32_limit` | core `CipherProbeFieldCipherTest` | green |
| `probe_a_failed_post_erasure_hook_reports_complete` | core `CipherProbeErasureTest` | green |

### RED evidence

- `probe_field_and_entity_names_collide_in_the_aad`: first draft concatenated the AAD components
  without a length prefix; the probe failed, the length-prefixed form fixed it.
- `probe_core_reads_a_plaintext_column_as_plaintext`: first draft had a `decodeOrPlaintext` that
  handed back unrecognised bytes; the probe failed to compile against the strict `decode`, which is
  the API that replaced it.
- `probe_blind_index_matches_the_same_value_across_tenants`: run against a draft whose HKDF info
  omitted the tenant; the probe failed with two identical index values.
- `probe_ciphertext_moved_between_rows_still_decrypts`, `probe_key_store_outage_reads_as_erased`,
  `probe_encryption_passes_the_per_key_2_32_limit`: run against drafts with the entity/field AAD
  component removed, with the outage swallowed as an erasure, and with the rotation removed. All
  three failed.
- `probe_a_wrapped_key_row_restored_after_erasure_decrypts_the_value`: failed because
  `SECURITY-NOTES.md` did not yet exist to state the residual.
- `probe_concurrent_write_encrypts_under_a_destroying_key`: failed against the implementation as
  designed - see below.

## The one real bug the probes found

A write that was racing an erasure blocked on the key row's `FOR UPDATE`, then found the row gone,
concluded the subject simply had no key yet, and minted a new one. The erasure was undone within
milliseconds and nothing in the erasure log said so.

Fixed with a `shredding_erased_subject` tombstone holding no key material: the key rows are still
deleted outright, and `mint` refuses for a tombstoned subject. Recorded as QUESTIONS #3, because it
adds a table Cipher's section does not name.

## Open questions

Ten, in `QUESTIONS.md`. The ones that want an answer before Cipher's pass: **#1** (one converter
class per field, and whether to generate them instead), **#3** (the tombstone), **#4** (the bounded
map behind subject immutability, and its gap), **#8** (no cross-node cache invalidation in the free
core) and **#10** (the regulatory citations are unverified placeholders).

## Deliberately not done

- No cross-node cache invalidation (QUESTIONS #8); the 60-second window is documented instead.
- No batch migrator for existing plaintext columns; Pro only, per control 17.
- No `PostErasureHook` retry scheduler. A failed hook makes the erasure `PARTIAL` and the outcome is
  in the log; who retries it is the application's decision.
- The spec body's "100k encryptions, no nonce collision" property test is **not** written. Cipher
  replaced it: 100 000 draws from 2^96 collide with probability about 2^-64, so the test cannot fail
  even against a badly broken generator. What is tested instead is that the nonce comes from a
  `RandomSource` we control, that a narrow generator is detectable, and that the per-key counter
  refuses and rotates.
