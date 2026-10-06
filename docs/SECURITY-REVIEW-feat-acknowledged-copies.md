# Security review: feat/acknowledged-copies (PR 26, audit-table coverage PR 1b)

## Pass 1 (2026-10-06)

Reviewed head `7ee6c62`, diff against `5269b34` (main with PRs 24 and 25). Checklist: the design's
section 3c, 3c.6 and 3c.7 including rev 5 items 1-4, section 8, the rulings C3, C8, C11, C12 and the
rev 5 condition (append guard reads the latest record after the advisory lock, inside the READ
COMMITTED pin), the integration surface rows that 1b owns, and the attack list of the brief.

### Verdict: pending (in progress)

### Build and tests (PostgreSQL 16 by digest, Docker up, `CIPHER_PROBE_MAVEN=1 ./mvnw verify`)

| module | tests | failures | errors | skipped |
| --- | --- | --- | --- | --- |
| core | 531 | 0 | 0 | 0 |
| starter | 284 | 0 | 0 | 0 |
| sample | 22 | 0 | 0 | 0 |

Exit 0, licence check clean. Every existing `CipherProbe*` class ran unchanged and green, including
the re-enabled #C-30 probe and the RC-3 history-trigger WARN case. The builder's numbers match.

### Rulings on the open points

- **#C-31 (the `-009`/`-010` messages print identifiers without escaping control characters): in
  this PR, not a separate one.** Rev 5 item 3 is part of 1b's definition and says *every* WARN and
  exception message that prints an operator-chosen identifier escapes it. 1b edits the `-010`
  trigger, publication and slot messages and now prints the same identifier twice in one message,
  raw in the finding and escaped in the acknowledgement remedy. The helper (`LogText.escape`)
  exists; applying it is a correction, not a mechanism, so the one-mechanism rule does not move it
  out. A separate PR would cost two more passes for the same lines. Recorded as finding C-26-2
  below with a probe.
- **#C-32 (mechanism commit `727ce91` carries a `docs(...)` subject): accepted, closed without a
  code change.** It is pushed, and history on a pushed branch is never rewritten. The merge commit
  subject is the PR title, which is a correct `feat(jdbc)` line, so `main`'s first-parent history
  is right. Condition: the PR body names `727ce91` as the commit that carries the mechanism, so a
  reader of the branch history is not misled. Process note for the builder: when the hook refuses
  a subject for length, shorten the subject; never change its type.
