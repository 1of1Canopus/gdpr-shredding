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

## Pass 2 (2026-10-07)

Head reviewed: e349e0a. CI on e349e0a: 6/6 required checks green (Build & test, Cipher
probes, DCO sign-off, Reference guard, Release dry run, Vulnerability scan) plus the
Dependabot config check. Full `verify` and `CIPHER_PROBE_MAVEN=1` not re-run locally (CI is
cited instead, per brief).

Method: the W1 function `probe_maven_wrapper_is_compatible_with_central_publishing` was
extracted verbatim from `tools/cipher-probe-release-pipeline.sh` and executed against scratch
fixtures (one `.mvn/wrapper/maven-wrapper.properties` + one `pom.xml` per row). WEAK = return 0.

| Wrapper input | Constant | Plugin | Result | Expected |
|---|---|---|---|---|
| 3.9.16 LF (shipped) | empty | 0.11.0 | FIXED | FIXED |
| 3.10.0 | empty | 0.11.0 | WEAK | WEAK |
| 3.10.0 | empty | 1.0.0 | WEAK | WEAK |
| 4.0.0 | empty | 0.11.0 | WEAK | WEAK |
| 3.9.16 CRLF | empty | 0.11.0 | FIXED | FIXED |
| 3.10.0 CRLF | empty | 0.11.0 | WEAK | WEAK |
| duplicate url (3.9.16 then 3.10.0) | empty | 0.11.0 | WEAK | WEAK |
| no distributionUrl | empty | 0.11.0 | WEAK | WEAK |
| missing properties file | empty | 0.11.0 | WEAK | WEAK |
| `distributionUrl = ...` (spaces) | empty | 0.11.0 | WEAK | WEAK (unparsed) |
| version `3.x` | empty | 0.11.0 | WEAK | WEAK |
| plugin property absent | empty | none | WEAK | WEAK |
| 3.9.16-SNAPSHOT | empty | 0.11.0 | FIXED | FIXED (3.9 line) |
| 3.10.0-SNAPSHOT | empty | 0.11.0 | WEAK | WEAK |
| 3.10.0-rc-1 | empty | 0.11.0 | WEAK | WEAK |
| 3.10.0 | 1.2.0 | 1.1.0 | WEAK | WEAK |
| 3.10.0 | 1.2.0 | 1.2.0 | FIXED | FIXED |
| 3.10.0 | 1.2.0 | 1.10.0 | FIXED | FIXED (numeric, not lexical) |
| 3.10.0 | 1.2.0 | 0.11.0 | WEAK | WEAK |
| 3.9.16 | 1.2.0 | 0.11.0 | FIXED | FIXED |
| 3.10.0 | 1.2.0 | **1.2.0-SNAPSHOT** | **FIXED** | WEAK (C-30-1) |
| 3.10.0 | 1.2.0 | **`${x}`** | **FIXED** | WEAK (C-30-1) |
| url `.../3.10.0/apache-maven-3.10.0-bin.zip#/apache-maven-3.9.16-bin.zip` | empty | 0.11.0 | **FIXED** | WEAK (C-30-2) |

CR strip, decided: a CRLF properties file naming 3.9.16 is a valid wrapper file (mvnw's
`trim` drops the CR), so the rule requires **FIXED**. Mutation (both `tr -d '\r'` removed):
3.9.16 CRLF still FIXED, 3.10.0 CRLF still WEAK. The strip is therefore not observable through
this probe, because the version `sed` ends in `.*` and swallows the CR and `grep -c
'^distributionUrl='` is unaffected. The probe gives the right verdict with or without it;
the strip is defence in depth. Not a finding.

dependabot.yml (parsed with a YAML parser, not grep): `maven` has `cooldown: {default-days: 7}`
and keeps the ignore `org.apache.maven:apache-maven` `>= 3.10`; `github-actions` has
`cooldown: {default-days: 7}`. D-1 closed.

Prior findings: W1-a closed (empty constant reads WEAK for every plugin on 3.10+, constant set
compares numerically). W1-b closed (duplicate, missing, CRLF, malformed rows above). D-1
closed. C-1 and B-1 stay open as coordinator/maintainer decisions, recorded in pass 1, not
blocking this verdict per brief.

### New findings

**C-30-1 (LOW). The plugin version is not validated, so a non-release plugin counts as
"supports 3.10" once the constant is set.** Latent today (constant empty), live the day it is
filled in. Repro: rows `1.2.0-SNAPSHOT` and `${x}` above (`sort -V` orders `1.2.0` before both).
The function's own rule is "unreadable is weak", and it already applies that to the wrapper
version but not to the plugin version. Fix (Isis), `tools/cipher-probe-release-pipeline.sh`,
`probe_maven_wrapper_is_compatible_with_central_publishing`: after `plugin=` read, require
`[[ "$plugin" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0` (release versions only; a property
reference or qualifier is weak). Probe: `probe_w1_accepts_unparsed_plugin_version`.

**C-30-2 (INFO). The wrapper version comes from the last `apache-maven-X-bin.zip` text in the
URL, not from the path mvnw downloads.** Repro: the fragment row above reads FIXED while the
download is 3.10.0. A Dependabot bump never produces this shape, but the fix is one line and
it completes W1-b's "strict parse". Fix (Isis), same function: replace the `sed` extraction
with a full-match on `^https://repo\.maven\.apache\.org/maven2/org/apache/maven/apache-maven/([^/]+)/apache-maven-([^/]+)-bin\.zip$`
via `[[ =~ ]]`, require `BASH_REMATCH[1] == BASH_REMATCH[2]`, then apply the existing semver
check; anything else returns 0. Probe: `probe_w1_reads_version_from_url_suffix_not_path`.

Both probes are in the internal probe folder (`cipher-probe-pr30-pass2.sh`) and read WEAK on
e349e0a; add them to the W1 block of the suite before the fix. Either fix is tooling only,
not a new mechanism; no design page needed.

### Verdict

**MERGE WITH FIXES**: C-30-1 (LOW), C-30-2 (INFO). No HIGH, no MEDIUM. C-1 and B-1 are still open
as recorded.
