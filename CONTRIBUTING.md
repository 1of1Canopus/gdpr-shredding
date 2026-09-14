## Commit convention
[Conventional Commits](https://www.conventionalcommits.org), enforced by `.githooks/commit-msg`. After cloning run `git config core.hooksPath .githooks`. Subject line: `<type>(<scope>): <imperative, lowercase, no trailing period>`, max 72 characters, one of `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`, `revert`, `merge`.

## Licence of your contribution

This project is licensed under the [Functional Source License, Version 1.1, ALv2 Future
License](./LICENSE) ("FSL-1.1-ALv2"). Unlike Apache-2.0, FSL has no built-in contribution
clause, so we ask for two things from every pull request, both of them the lightweight kind
(no signed PDF, no CLA bot with legal review):

1. **Sign off every commit under the [Developer Certificate of Origin 1.1](https://developercertificate.org/)**
   (the same mechanism the Linux kernel and most CNCF projects use). Add `-s` to your commit:

   ```bash
   git commit -s -m "fix: ..."
   ```

   That appends a `Signed-off-by: Your Name <you@example.com>` trailer, which is your
   certification that you wrote the contribution or otherwise have the right to submit it
   under the DCO. `ci.yml` checks that every commit in the pull request carries one; a PR
   with an unsigned commit will not pass.

2. **You license your contribution under the project's licence, and grant HouseDevinci the
   right to relicense it.** By submitting a pull request you agree that your contribution is
   licensed to HouseDevinci under FSL-1.1-ALv2 (the same terms as the rest of the project),
   and that HouseDevinci may relicense your contribution under the Grant of Future License in
   `LICENSE` (the automatic conversion to Apache-2.0 two years after each version's release)
   or under any other licence the project moves to in the future, on the same terms as the
   rest of the codebase. This is the whole inbound-licensing agreement ("simple CLA"); the DCO
   sign-off above is how it is recorded, there is nothing further to sign.

No CLA bot, no separate form: the DCO trailer plus this paragraph is the whole agreement.

## Hand-off probes (`src/test-pending/java`)

A security-review probe is committed to the repo, never to a session scratchpad or any other
place invisible to git. The security review commits a new, failing probe under
`<module>/src/test-pending/java/...`, mirroring the package it will live in once fixed. That
directory is not part of the default build: `./mvnw verify` never compiles or runs it, so a
red probe cannot fail CI or move the coverage numbers before anyone has fixed the thing it
demonstrates.

```
./mvnw -Pprobes-pending test      compiles and runs src/test-pending/java too, in every module
```

The engineer fixing the finding runs the profile to reproduce the probe red, fixes the
production code, confirms it green under the profile, then `git mv`s the file into
`src/test/java` so it is compiled and run by the ordinary, no-profile build from then on -
`src/test-pending/java` is a staging area for a probe that does not have a fix yet, never a
permanent home for one that does.

## Planning and security records

Project planning and review records are maintained privately; security reports go to security@housedevinci.com.
