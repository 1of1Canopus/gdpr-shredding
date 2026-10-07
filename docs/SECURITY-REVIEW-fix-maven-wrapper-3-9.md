# Security review: fix/maven-wrapper-3-9 (PR #30)

## Pass 1 (2026-10-07)

Scope: ee02c3c (probe W1), 2bd139d (wrapper back to 3.9.16, Dependabot ignore, changelog).
Trigger: the v0.2.0 release run 37553784648 failed at Central Portal validation
("Bundle has content that does NOT have a .pom file: parent, core, starter") after the
Dependabot bump of the wrapper to Maven 3.10.0 (PR 17, merged by hand by the maintainer; this
repository has no auto-merge workflow, so the gate rule was not bypassed).

**Verdict: MERGE WITH FIXES** (W1-a, W1-b, D-1, C-1 in this PR). B-1 is a design stop with
its own PR and blocks the next release tag, not this merge.

### Evidence

| Check | Result |
|---|---|
| `git diff v0.1.1 -- .mvn/wrapper/maven-wrapper.properties` | empty (byte-identical) |
| distribution sha256 recomputed from repo.maven.apache.org | `5af3b743...89ce` matches the file; sha512 matches the published `.sha512` |
| `./mvnw -v` | Apache Maven 3.9.16 |
| Local bundle, Maven 3.9.16, `deploy -Prelease` (version 9.9.9, gpg skipped, dummy server, upload refused 401) | 45 entries, all jar/pom/checksum |
| Same, wrapper mutated to 3.10.0 | 63 entries; 6 foreign: `maven-metadata-local.xml` x3, `_remote.repositories` x3; parent pom and several checksums missing. Reproduces the Portal refusal locally, before any upload |
| Probe W1, wrapper 3.10.0 + plugin 0.11.0 | WEAK (mutation detected) |
| Probe W1, PR head | FIXED |
| Full suite with `CIPHER_PROBE_MAVEN=1` | not re-run here (the Maven probes exceed the 600 s tool limit; stopped on coordinator instruction). Evidence is CI on 2bd139d: 6/6 green, including the Cipher probes check |
| Dependabot name | PR 17 body: "Updates `org.apache.maven:apache-maven`" in the `maven` ecosystem, directory `/`, group `minor-and-patch`. The ignore matches that name only; `org.sonatype.central:central-publishing-maven-plugin` bumps are not affected. `>= 3.10` also holds back 4.x, which is intended |
| Replay refusal for a retry | release.yml line 410 counts only PENDING..PUBLISHED; the FAILED 0.2.0 deployment does not block a retry |

### Findings

**W1-a (MEDIUM) - the probe un-weakens on any 1.x plugin, against its own rule.**
Repro (function sourced against fixture files): wrapper 3.10.0 + plugin 1.0.0 -> FIXED;
3.10.0 + 2.0.0 -> FIXED. The comment says "revisit when a plugin version documents support",
but the code clears the weakness on a major bump nobody verified. Fix (Isis,
tools/cipher-probe-release-pipeline.sh): add `FIRST_CENTRAL_PUBLISHING_SUPPORTING_MAVEN_3_10=""`
next to the probe; WEAK when wrapper >= 3.10 and (the constant is empty, or plugin version
sorts below it with `sort -V`). Comment states: set only with a link to the plugin release
note and a green Portal validation. Probe `probe_w1_plugin_major_bump_clears_the_weakness`:
fixture 3.10.0 + 1.0.0 must be WEAK.

**W1-b (LOW) - parser accepts inputs it should refuse.**
Repro: two `distributionUrl` lines (3.9.16 then 3.10.0; Java properties: last wins, so 3.10.0)
-> FIXED; bare version `3` -> FIXED. Missing file -> WEAK but prints a sed error (acceptable).
CRLF 3.10.0 -> WEAK (correct). Fix: WEAK unless exactly one `distributionUrl` line; strip `\r`;
require `^[0-9]+\.[0-9]+(\.[0-9]+)?$` before comparing. Probe
`probe_w1_duplicate_distribution_url_reads_the_first`: fixture above must be WEAK.

**D-1 (LOW) - `.github/dependabot.yml` has no `cooldown`.** Global rule of 2026-09-21: 7-day
cooldown on every ecosystem. Both `maven` and `github-actions` entries lack it. Fixed in this
PR: one `cooldown: { default-days: 7 }` block per ecosystem, same file already touched, not a
mechanism. Probe `probe_dependabot_ecosystem_without_cooldown` (parse every `updates[]` entry,
WEAK if any lacks `cooldown.default-days >= 7`).

**C-1 (INFO) - changelog states a release that never reached Central.** `[0.2.0] - 2026-10-07`
reads as published; the tag v0.2.0 points at e550406, before this fix, and the Portal refused
it. Do not move a signed tag. Fix: the retry ships as 0.2.1 (maintainer's call); the changelog
says 0.2.0 was tagged but never published and moves the 0.2.0 content under 0.2.1.

**B-1 (MEDIUM, DESIGN STOP) - no bundle allowlist before upload.**
Pre-existing, exposed by this incident. The release step "Confirm the bundle contains exactly
the three published coordinates" is presence-only (grep for three paths and the sample) and
runs after `deploy` has uploaded. The CI dry run is `verify -Prelease`, which never assembles
`central-bundle.zip`. Reproduced above: the 3.10 bundle is detectable locally with a plain
listing. Property that must hold: no bundle reaches the Portal unless every entry matches
`com/housedevinci/<published artifactId>/<version>/<artifactId>-<version>[-sources|-javadoc].(jar|pom)[.asc|.md5|.sha1|.sha256|.sha512]`
and every published coordinate has its pom, jar(s) and signatures. Paths it must cover: CI on
every pull request (bundle assembled without upload), and the release job before the upload.
Note: `-Dcentral.skipPublishing=true` did not stop the upload attempt in this run; the
no-upload switch is part of the design. Thor writes the design page; Cipher reviews it; own
PR. Required before the next release tag.

### What this PR cannot prove

The only proof that 3.9.16 + plugin 0.11.0 produces an accepted bundle is a Portal
validation. This PR cannot upload. The local listing above shows the 3.9.16 bundle has the
same shape as the one 0.1.1 shipped, which is strong but not the validator. The retry release
run must show: deployment state **VALIDATED** for `gdpr-shredding <version> (<sha>)`, the
bundle listing in the log with no `maven-metadata*` or `_remote.repositories` entry, and the
checksum comparison step green. Pattern recorded: a dry run that stops before the external
validator proves nothing, unless it reproduces the validator's rule locally (B-1).
