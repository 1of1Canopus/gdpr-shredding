
## Commit convention
Conventional Commits, enforced by `.githooks/commit-msg`. After cloning run `git config core.hooksPath .githooks`. Full rules: see the lane conventions (15/specs/SHARED-CONVENTIONS.md or 14/AGENTS.md).

## Hand-off probes (`src/test-pending/java`)
A security-review probe is committed to the repo, never to a session scratchpad or any other place
invisible to git. Cipher commits a new, failing probe under `<module>/src/test-pending/java/...`,
mirroring the package it will live in once fixed. That directory is not part of the default build:
`./mvnw verify` never compiles or runs it, so a red probe cannot fail CI or move the coverage
numbers before anyone has fixed the thing it demonstrates.

```
./mvnw -Pprobes-pending test      compiles and runs src/test-pending/java too, in every module
```

The engineering agent fixing the finding runs the profile to reproduce the probe red, fixes the
production code, confirms it green under the profile, then `git mv`s the file into `src/test/java`
so it is compiled and run by the ordinary, no-profile build from then on -
`src/test-pending/java` is a staging area for a probe that does not have a fix yet, never a
permanent home for one that does.
