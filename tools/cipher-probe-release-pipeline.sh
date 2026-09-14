#!/usr/bin/env bash
#
# Cipher probes for the Maven Central release pipeline (branch feat/release-pipeline).
#
# Every probe below asserts a WEAKNESS. Each one PASSES while its finding is open and must
# FLIP TO FAILING once the matching finding from the security review is fixed. A probe
# that starts failing is the signal that the item is closed; delete it in the same PR that
# fixes it.
#
# The first block (M-, L-, I-ids) is the first pass, on 645397d: all FIXED at 30aec6f
# except the one reclassified as not-a-finding; see the note on
# probe_release_job_can_exec_an_unverified_maven_distribution below, which replaces it.
# The second block (N-ids) is the re-verification of 30aec6f: all WEAK there, all FIXED at
# 1da507e.
# The third block (F-ids) is the final verification of 1da507e, after the FSL-1.1-ALv2
# licence switch: all WEAK there.
#
#   tools/cipher-probe-release-pipeline.sh            static probes only (seconds)
#   CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh   + the two build probes
#
# Exit code is 0 once every probe has flipped to FIXED, 1 while any weakness is still
# there (`[ "$pass" -eq 0 ]` on the last line). The header of this file used to claim the
# opposite; the code was always right and the sentence was wrong. This file is evidence,
# not a CI gate: nothing in .github/ runs it.
#
set -uo pipefail
cd "$(dirname "$0")/.."

WF=.github/workflows/release.yml
pass=0; flipped=0

probe() { # probe <name> <"still weak" message>; body returns 0 when the weakness is present
  local name="$1" msg="$2"; shift 2
  if "$@"; then
    printf 'WEAK    %-52s %s\n' "$name" "$msg"; pass=$((pass + 1))
  else
    printf 'FIXED   %-52s\n' "$name"; flipped=$((flipped + 1))
  fi
}

# ---------------------------------------------------------------------------
# M4 - the workflow_dispatch version input is validated with a line-oriented grep,
#      so a value containing a newline passes and injects extra lines into
#      $GITHUB_OUTPUT. Extracts the actual "Derive the release version" step body from
#      release.yml and runs it for real against the malicious input, so this probe tests
#      the workflow's own current logic and not a frozen copy of the old snippet.
# ---------------------------------------------------------------------------
probe_multiline_version_accepted() {
  local step out rc
  step=$(awk '
    /- name: Derive the release version/ { infield=0; instep=1 }
    instep && /run: \|/ { inrun=1; next }
    instep && !inrun && /^      - name:/ && !/Derive the release version/ { exit }
    inrun && /^      - name:/ { exit }
    inrun { print }
  ' "$WF")
  [ -n "$step" ] || return 0   # step vanished: cannot prove the fix, count as still weak
  out="$(mktemp)"
  GITHUB_EVENT_NAME=workflow_dispatch \
  INPUT_VERSION="$(printf '0.1.0\nmalicious=1')" \
  GITHUB_OUTPUT="$out" \
  bash -c "$step" >/dev/null 2>&1
  rc=$?
  # Weak: the step exited 0 (accepted the input) and the injected extra line landed in
  # $GITHUB_OUTPUT. Fixed: the step rejected the multiline input (non-zero exit).
  if [ "$rc" -eq 0 ] && grep -q '^malicious=1$' "$out" 2>/dev/null; then
    rm -f "$out"; return 0
  fi
  rm -f "$out"; return 1
}

# ---------------------------------------------------------------------------
# M3 - the release job restores the setup-java maven cache, which covers
#      ~/.m2/wrapper/dists. mvnw execs an existing distribution without ever
#      re-checking distributionSha256Sum, so a poisoned cache entry runs
#      arbitrary Maven in the job that holds the signing key.
# ---------------------------------------------------------------------------
probe_release_job_restores_maven_cache() {
  local job
  job="$(awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  publish:$/ {f=1} f' "$WF")"
  grep -q 'cache: maven' <<<"$job"
}

# Re-verification of 30aec6f. The probe that used to sit here,
# probe_mvnw_skips_checksum_for_existing_distribution, grepped the vendored `mvnw` for a
# checksum re-check inside its "found existing MAVEN_HOME, exec it" branch. That probe was
# refused: no Maven Wrapper script re-checks an unpacked distribution
# (distributionSha256Sum is only ever compared against the freshly downloaded zip), and the
# only marker that would satisfy the text match - a sidecar checksum file written at install
# time - is writable by exactly the attacker M3 describes, in the same write that plants the
# poisoned distribution. It would have turned the probe green without adding a control.
# Reclassified as NOT A FINDING: the property is not ours to hold.
#
# It is replaced, not dropped, by the probe below, which asserts the operational property
# that does close M3 and that this repository does control: the signing job restores no
# Maven cache, and it removes ~/.m2/wrapper/dists BEFORE the first mvnw invocation, so
# `[ -d "$MAVEN_HOME" ]` is always false there and mvnw always takes the download-and-verify
# path. Weak if the cache comes back, if the removal step disappears, or if it drifts below
# the first mvnw call.
probe_release_job_can_exec_an_unverified_maven_distribution() {
  local job first_mvnw rm_dists
  job=$(awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  publish:$/ {f=1} f' "$WF")
  grep -q 'cache: maven' <<<"$job" && return 0          # cache back: weak
  rm_dists=$(printf '%s\n' "$job" | grep -n 'rm -rf ~/\.m2/wrapper/dists' | head -1 | cut -d: -f1)
  [ -n "$rm_dists" ] || return 0                                    # no removal step: weak
  first_mvnw=$(printf '%s\n' "$job" | grep -n '\./mvnw' | head -1 | cut -d: -f1)
  [ -n "$first_mvnw" ] || return 0                                  # no mvnw at all: cannot prove it
  [ "$rm_dists" -lt "$first_mvnw" ] && return 1                     # removed before any mvnw: FIXED
  return 0
}

# ---------------------------------------------------------------------------
# M5 - any ref can release: no environment gate, no check that the tag's commit
#      is an ancestor of main, no requirement that the tag be signed.
# ---------------------------------------------------------------------------
probe_release_job_has_no_environment_gate() { ! grep -q '^\s*environment:' "$WF"; }
probe_release_does_not_check_tag_ancestry()  { ! grep -q 'merge-base' "$WF"; }
probe_release_does_not_verify_tag_signature() { ! grep -qE 'verify-tag|--verify-signatures' "$WF"; }

# ---------------------------------------------------------------------------
# M7 - Apache-2.0 is declared in the POM and there is no licence text anywhere.
# ---------------------------------------------------------------------------
probe_no_licence_file_in_the_repository() {
  # Not `git ls-files | grep -q`: this file runs under `set -o pipefail`, `grep -q` exits as
  # soon as it matches, and `git ls-files` then dies of SIGPIPE with status 141, which
  # pipefail promotes to the pipeline's status. The probe then reads WEAK on a tree that does
  # have a LICENSE - observed here, intermittently, on the first matching line of a long
  # listing. Materialise the listing first, so the exit status compared is grep's own.
  local tracked
  tracked="$(git ls-files)"
  ! grep -qiE '^(LICENSE|LICENCE|NOTICE)(\..*)?$' <<<"$tracked"
}

# ---------------------------------------------------------------------------
# L1 - the jars that are signed and uploaded come from the `clean deploy` build,
#      a third build that is never compared against the two the reproducibility
#      script checks.
# ---------------------------------------------------------------------------
probe_published_jars_are_never_checksum_compared() {
  ! grep -qE 'sha256|shasum' "$WF"
}

# ---------------------------------------------------------------------------
# L2 - concurrency is keyed on the ref, so a tag push and a workflow_dispatch for
#      the same version can release at the same time.
# ---------------------------------------------------------------------------
probe_concurrency_group_is_ref_scoped_not_version_scoped() {
  grep -q 'group: release-\${{ github.ref }}' "$WF"
}

# ---------------------------------------------------------------------------
# L3 - checkout leaves the GITHUB_TOKEN in .git/config for every Maven plugin
#      that runs in the release job.
# ---------------------------------------------------------------------------
probe_checkout_persists_credentials() { ! grep -q 'persist-credentials' "$WF"; }

# ---------------------------------------------------------------------------
# L4 - signed jars and .asc files of a FAILED release are uploaded anyway. Scoped to the
#      single step that uploads them: a whole-file grep for both strings anywhere false-
#      positives once the workflow legitimately has an unrelated `if: always()` step
#      (e.g. a `docker compose down` teardown) that has nothing to do with the evidence
#      upload.
# ---------------------------------------------------------------------------
probe_evidence_uploaded_even_when_the_release_failed() {
  awk '
    /^      - name:.*[Rr]elease evidence/ { instep=1; found=0 }
    instep && /if: always\(\)/ { found=1 }
    instep && /\*\.asc/ { has_asc=1 }
    instep && /^      - name:/ && !/[Rr]elease evidence/ { instep=0 }
    END { exit !(found && has_asc) }
  ' "$WF"
}

# ---------------------------------------------------------------------------
# I4 - `-X` makes Maven print env.CENTRAL_TOKEN and env.MAVEN_GPG_PASSPHRASE in
#      clear. The workflow does not use it today; nothing stops it being added.
# ---------------------------------------------------------------------------
probe_nothing_forbids_maven_debug_in_the_release_job() {
  ! grep -qE 'refusing.*(-X|--debug)|forbid.*debug' "$WF"
}

# ---------------------------------------------------------------------------
# M1 - licence gate: a dependency passes when ANY one of its declared licences is
#      on the allowlist, so `Apache-2.0 OR GPL-3.0` slips through. Runs a real build
#      against a synthetic dependency in a throwaway clone, through `verify` so the
#      tools/check-third-party-licences.sh denial pass (M1/M2 fix) actually runs -
#      the plugin's own allowlist stops at `package` and would report FIXED for the
#      wrong reason.
# ---------------------------------------------------------------------------
probe_licence_gate_accepts_a_dual_apache_or_gpl_dependency() {
  [ "${CIPHER_PROBE_MAVEN:-0}" = "1" ] || { echo "        (skipped: set CIPHER_PROBE_MAVEN=1)" >&2; return 0; }
  local work rc; work=$(mktemp -d)
  cat > "$work/syn.pom" <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>example.synthetic</groupId><artifactId>syn-dual</artifactId><version>1.0</version><packaging>jar</packaging>
<name>syn-dual</name><licenses>
  <license><name>Apache-2.0</name><url>http://example.invalid</url></license>
  <license><name>GPL-3.0</name><url>http://example.invalid</url></license>
</licenses></project>
EOF
  : > "$work/empty.txt"; (cd "$work" && jar cf syn.jar empty.txt)
  git clone -q --no-hardlinks . "$work/tree" || return 1
  (
    cd "$work/tree" || exit 1
    ./mvnw -B -q org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
      -Dfile="$work/syn.jar" -DpomFile="$work/syn.pom" >/dev/null 2>&1 || exit 1
    perl -0pi -e 's{<dependencies>}{<dependencies>\n    <dependency><groupId>example.synthetic</groupId><artifactId>syn-dual</artifactId><version>1.0</version></dependency>}' \
      gdpr-shredding-core/pom.xml
    ./mvnw -B -pl gdpr-shredding-core -am verify \
      -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true -Denforcer.skip=true >/dev/null 2>&1
  )
  rc=$?
  rm -rf "$work"
  # exit 0 from the build == the GPL-3.0 half was ignored == the weakness is present
  return "$rc"
}

# ===========================================================================
# Re-verification of 30aec6f: probes for the findings the fixes introduced.
# Every one of these asserts a weakness that is present at 30aec6f and must flip
# to FIXED when the matching N-finding from the security review's "Re-verification
# (30aec6f)" pass is closed.
# ===========================================================================

# Runs tools/check-third-party-licences.sh against ONE synthetic dependency line, in a
# throwaway tree, so the repository's own target/ files cannot mask the result.
# Echoes the script's exit code: 0 = the dependency passed the gate.
licence_verdict() { # licence_verdict <notices line>
  local work rc
  work=$(mktemp -d)
  mkdir -p "$work/tools" "$work/mod/target"
  cp tools/check-third-party-licences.sh "$work/tools/"
  printf '\nLists of 1 third-party dependencies.\n%s\n' "$1" > "$work/mod/target/THIRD-PARTY-NOTICES.txt"
  # N1: the script now takes the module build directory and packaging as arguments (it
  # checks one module's own notices, not a tree-wide `find`); jar is the packaging exercised
  # by every synthetic case below.
  "$work/tools/check-third-party-licences.sh" "$work/mod/target" jar >/dev/null 2>&1
  rc=$?
  rm -rf "$work"
  return "$rc"
}

# ---------------------------------------------------------------------------
# N2 - the denial pass matches hyphenated SPDX ids and the literal substring "gpl".
#      Real POMs declare licences in prose. "GNU General Public License v3" contains no
#      "gpl" at all, and "Mozilla Public License, Version 2.0" is not the string "mpl-2.0",
#      so both pass the all-of denial pass on their permissive half - the exact M1 hole,
#      respelled. The script's own comment claims it catches "GNU General Public License v3".
# ---------------------------------------------------------------------------
probe_denial_pass_misses_prose_licence_names() {
  licence_verdict '     (Apache-2.0) (GNU General Public License v3) x (c.s:syn:1.0 - no url defined)' &&
  licence_verdict '     (Apache-2.0) (Mozilla Public License, Version 2.0) x (c.s:syn:1.0 - no url defined)'
}

# ---------------------------------------------------------------------------
# N3 - the coordinate the denial pass matches is taken from the FIRST "(g:a:v - " group on
#      the line, and a dependency's own <name> is attacker-controlled text that lands on
#      that line ahead of its real coordinate. A dependency named
#      "evil (ch.qos.logback:logback-core:1.5.6 - http://x)" is read as logback-core, which
#      is on the coordinate allowlist, so every licence it declares is skipped. Second half:
#      a line whose version carries a character outside [\w.-] matches no coordinate at all
#      and is silently skipped rather than failing the build - a fail-open parser.
# ---------------------------------------------------------------------------
probe_denial_pass_coordinate_can_be_forged_by_the_dependency_name() {
  licence_verdict '     (GPL-3.0) evil (ch.qos.logback:logback-core:1.5.6 - http://x) (c.s:evil:1.0 - no url defined)' &&
  licence_verdict '     (GPL-3.0) x (c.s:syn:1.0+build - no url defined)'
}

# ---------------------------------------------------------------------------
# N10 - a licence line carrying an empty "()" token makes the script die on
#       "tok_list[@]: unbound variable" under set -u, abandoning every file and line it had
#       not reached yet. It exits 1, so it fails closed, but on a shell error rather than a
#       verdict, and it stops scanning.
# ---------------------------------------------------------------------------
probe_denial_pass_crashes_on_an_empty_licence_token() {
  local work out
  work=$(mktemp -d); mkdir -p "$work/tools" "$work/mod/target"
  cp tools/check-third-party-licences.sh "$work/tools/"
  printf '\nLists of 1 third-party dependencies.\n     () x (c.s:syn:1.0 - no url defined)\n' \
    > "$work/mod/target/THIRD-PARTY-NOTICES.txt"
  out=$("$work/tools/check-third-party-licences.sh" "$work/mod/target" jar 2>&1)
  rm -rf "$work"
  grep -q 'unbound variable' <<<"$out"
}

# ---------------------------------------------------------------------------
# N1 - the exec:exec denial pass is inherited by every module, so it runs on
#      gdpr-shredding-parent FIRST, before any module has produced a THIRD-PARTY-NOTICES.txt.
#      The script fails closed when it finds none, so `./mvnw verify` fails on any clean
#      checkout - which is what ci.yml and the release runner do. It only passes in a
#      working tree because the PREVIOUS build's notices files are still on disk when the
#      parent's verify runs (each module is cleaned when its own turn comes), which also
#      means the parent's pass is reading stale evidence.
# ---------------------------------------------------------------------------
probe_verify_fails_on_a_clean_checkout() {
  [ "${CIPHER_PROBE_MAVEN:-0}" = "1" ] || { echo "        (skipped: set CIPHER_PROBE_MAVEN=1)" >&2; return 0; }
  local work rc
  work=$(mktemp -d)
  git clone -q --no-hardlinks . "$work/tree" || { rm -rf "$work"; return 1; }
  ( cd "$work/tree" && ./mvnw -B verify \
      -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true >/dev/null 2>&1 )
  rc=$?
  rm -rf "$work"
  [ "$rc" -ne 0 ]   # non-zero on a clean checkout == the weakness is present
}

# ---------------------------------------------------------------------------
# Post-release finding (2026-09-10, run 34419387032) - scripts/verify-reproducible.sh always
# builds with -DskipTests, so its two builds never produce target/surefire-reports/. license-
# maven-plugin's add-third-party execution (addOutputDirectoryAsResourceDir defaults to true,
# includes "**/*.txt") registers outputDirectory (target/) as a live project resource at
# package phase; maven-source-plugin's jar-no-fork execution, bound to the same phase, reads
# project.getResources() at the moment IT runs and archives every target/*.txt it finds into
# the sources jar - THIRD-PARTY-NOTICES.txt deterministically, but also
# target/surefire-reports/*.txt whenever tests actually ran before package, which is never
# byte-identical run to run. A real `clean deploy -Prelease` (what the release job runs) DOES
# run tests, so its sources jars differed from what verify-reproducible.sh had already
# checksummed for the same tree: gdpr-shredding-core-0.1.0-sources.jar and
# gdpr-shredding-spring-boot-starter-0.1.0-sources.jar both failed "Confirm the deployed jars
# match the reproducibility check", while the main jars, javadoc jars and POMs matched.
#
# Behavioural probe: clones HEAD, runs the real scripts/verify-reproducible.sh to get its
# recorded sha256 for each sources jar, then runs a real `clean verify -Prelease
# -Dgpg.skip=true` (tests running, same outputTimestamp) and compares the sources jars it
# produces against those checksums. Weak while either sources jar differs.
# ---------------------------------------------------------------------------
probe_sources_jar_differs_from_a_build_that_actually_ran_tests() {
  [ "${CIPHER_PROBE_MAVEN:-0}" = "1" ] || { echo "        (skipped: set CIPHER_PROBE_MAVEN=1)" >&2; return 0; }
  local work rc
  work=$(mktemp -d)
  git clone -q --no-hardlinks . "$work/tree" || { rm -rf "$work"; return 1; }
  (
    cd "$work/tree" &&
    ts="$(scripts/git-commit-timestamp.sh)" &&
    REPRODUCIBLE_SHA_FILE="$PWD/repro-sha.txt" scripts/verify-reproducible.sh &&
    ./mvnw -B -q clean verify -Prelease -Dgpg.skip=true -Dproject.build.outputTimestamp="$ts" &&
    for jar in gdpr-shredding-core/target/*-sources.jar gdpr-shredding-spring-boot-starter/target/*-sources.jar; do
      name="$(basename "$jar")" &&
      actual="$(shasum -a 256 "$jar" | cut -d' ' -f1)" &&
      expected="$(awk -v n="$name" '$2==n{print $1}' repro-sha.txt)" &&
      [ -n "$expected" ] && [ "$actual" = "$expected" ] || exit 1
    done
  ) >/dev/null 2>&1
  rc=$?
  rm -rf "$work"
  [ "$rc" -ne 0 ]   # a mismatch, a missing jar, or a build failure: weakness present (WEAK)
}

# ---------------------------------------------------------------------------
# N4 - the L5 bundle assertion looks for the bundle in gdpr-shredding-sample/target/. The
#      plugin writes it to the TOP-LEVEL project's target/ (reproduced: a real
#      `deploy -Prelease` on a 0.1.0 checkout produced ./target/central-publishing/
#      central-bundle.zip, 45 files, no gdpr-shredding-sample). The step therefore always
#      fails with "was not created": the bundle is never inspected, and the two steps
#      after it - L1's checksum comparison and L4's evidence upload, both `if: success()` -
#      never run.
# ---------------------------------------------------------------------------
probe_bundle_assertion_points_at_the_wrong_path() {
  grep -q 'gdpr-shredding-sample/target/central-publishing/central-bundle.zip' "$WF"
}

# ---------------------------------------------------------------------------
# N5 - the tag-signature check is skipped, with a warning and exit 0, whenever
#      vars.RELEASE_SIGNING_KEY_ID is unset: a security control whose default is off.
#      Second half: even when it is set, `git verify-tag` only asserts that SOME key in the
#      keyring made a good signature, never that it was that key id (reproduced with two
#      throwaway keys: a tag signed by the second one verifies with exit 0). The binding
#      needs `git verify-tag --raw` and a VALIDSIG match on the full 40-hex fingerprint.
# ---------------------------------------------------------------------------
probe_tag_signature_check_is_optional_and_unbound() {
  local step
  step=$(sed -n '/- name: Verify the tag signature/,/^      - name:/p' "$WF")
  grep -q '::warning::' <<<"$step" && return 0        # skips when unset: weak
  grep -q 'VALIDSIG' <<<"$step" || return 0           # no key binding: weak
  return 1
}

# ---------------------------------------------------------------------------
# N6 - the I4 debug guard matches three literal flags. `--errors` (the long form of -e) is
#      not one of them, and neither is -Dorg.slf4j.simpleLogger.defaultLogLevel=debug in
#      MAVEN_OPTS, which turns on the identical DEBUG stream. Reproduced against this
#      repository: both a plain -X run and a MAVEN_OPTS slf4j-debug run print
#      "[DEBUG] env.CENTRAL_TOKEN: <value>" and "[DEBUG] env.MAVEN_GPG_PASSPHRASE: <value>"
#      in clear.
# ---------------------------------------------------------------------------
probe_debug_guard_misses_the_slf4j_log_level() {
  local guard
  guard=$(awk '/- name: Refuse Maven debug output in this job/{i=1} i&&/run: \|/{r=1;next} r&&/^      - name:/{exit} r{print}' "$WF")
  [ -n "$guard" ] || return 0
  MAVEN_ARGS='' MAVEN_OPTS='-Dorg.slf4j.simpleLogger.defaultLogLevel=debug' \
    bash -c "$guard" >/dev/null 2>&1 && return 0    # guard passed a debug setting: weak
  MAVEN_ARGS='' MAVEN_OPTS='--errors' bash -c "$guard" >/dev/null 2>&1 && return 0
  return 1
}

# ---------------------------------------------------------------------------
# N6 (run 34389977548, tag v0.1.0): the first version of the guard matched the bare words
#      `simpleLogger` and `defaultLogLevel` unconditionally, so it refused the workflow's
#      OWN job-level MAVEN_OPTS pin (`-Dorg.slf4j.simpleLogger.defaultLogLevel=info`) on
#      every run, before anything was uploaded - the guard's synthetic env cases above
#      never exercised the real job env, so this hole shipped past them. This probe reads
#      the workflow's actual declared MAVEN_ARGS/MAVEN_OPTS out of its own "env:" block
#      (not a hardcoded copy) and runs the real guard step body against exactly that env:
#      weak if the guard refuses its own declared pin.
# ---------------------------------------------------------------------------
probe_debug_guard_refuses_its_own_maven_opts_pin() {
  local guard maven_args maven_opts rc
  guard=$(awk '/- name: Refuse Maven debug output in this job/{i=1} i&&/run: \|/{r=1;next} r&&/^      - name:/{exit} r{print}' "$WF")
  [ -n "$guard" ] || return 0
  maven_args=$(awk -F'"' '/^  MAVEN_ARGS:/{print $2; exit}' "$WF")
  maven_opts=$(awk -F'"' '/^  MAVEN_OPTS:/{print $2; exit}' "$WF")
  [ -n "$maven_opts" ] || return 0   # env pin vanished: cannot prove the fix, count as weak
  MAVEN_ARGS="$maven_args" MAVEN_OPTS="$maven_opts" bash -c "$guard" >/dev/null 2>&1
  rc=$?
  [ "$rc" -ne 0 ]   # guard refused the workflow's own declared MAVEN_ARGS/MAVEN_OPTS: weak
}

# ---------------------------------------------------------------------------
# N8 - the ancestry check is `if: github.event_name == 'push'`, so a workflow_dispatch run
#      on any branch skips it entirely and releases whatever is on that ref. Same set of
#      people can do either, so it is not a narrower privilege.
# ---------------------------------------------------------------------------
probe_ancestry_check_skips_the_dispatch_path() {
  local step
  step="$(sed -n '/- name: Verify the released commit is on main/,/^      - name:/p' "$WF")"
  grep -q "event_name == 'push'" <<<"$step"
}

# ---------------------------------------------------------------------------
# N7 - RETIRED. Verified FIXED (the release runbook's scratch-keyring sanity check now
#      runs in a subshell, so its `trap ... EXIT` fires on any step failure, not only on
#      shell exit). The release runbook that this probe read is maintained privately and
#      is out of scope for this public probe suite; it is no longer checked here.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# N11 - I1 from the first pass was never closed: the release profile still passes
#       --pinentry-mode loopback that maven-gpg-plugin 3.2.8 adds by itself whenever a
#       passphrase is supplied, and the comment still credits the flag as "required
#       because there is no tty".
# ---------------------------------------------------------------------------
probe_gpg_arguments_comment_still_credits_the_wrong_actor() {
  grep -q 'required because there is no tty' pom.xml
}

# ---------------------------------------------------------------------------
# N12 - the probe suite is not run by anything: `grep -rl 'cipher-probe' .github/` returns
#       zero files. This is the mechanical reason N6 reached a tagged release. Returns 0
#       (WEAK) unless some workflow under .github/workflows/ invokes this suite
#       unconditionally - a `run:` line naming the script, on a step with no
#       `continue-on-error: true` anywhere in that step.
# ---------------------------------------------------------------------------
probe_probe_suite_is_not_run_by_ci() {
  local wf
  for wf in .github/workflows/*.yml; do
    [ -f "$wf" ] || continue
    if _probe_suite_wired_unconditionally_in "$wf"; then
      return 1   # a workflow runs the suite unconditionally: FIXED
    fi
  done
  return 0   # no such job anywhere: WEAK
}

# N13: strip full-line comments first, same standard as the release guard's own static
# check (.github/workflows/release.yml, `grep -vE '^\s*#'`) - a single `#` used to be enough
# to disable the suite while the probe still reported it FIXED. Then split the file into
# per-JOB blocks (not per-step), because GitHub counts a job skipped by a job-level `if:` as
# satisfying a required status check: a step-scoped check alone cannot see that. A job block
# is the fix only when it invokes the script in a `run:` line AND carries no `if:` and no
# `continue-on-error:` anywhere in that block - job-level or step-level, `true` or any other
# value, since a skipped/soft-failed job is exactly as blind as a deleted one.
#
# N14: a substring/regex match on the `run:` line is still fooled by a trailing comment -
# `run: true # CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` runs `true` and
# reports the probe suite FIXED. Same belt as the MAVEN_OPTS guard elsewhere in this file:
# stop pattern-matching, require the trimmed value of the `run:` line to be string-equal to
# the exact command. No YAML parser - this is still line-oriented - but equality instead of
# substring match refuses any decoration (comment, prefix, substitution) without needing one.
_probe_suite_wired_unconditionally_in() {
  local wf="$1"
  local want='CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh'
  grep -vE '^[[:space:]]*#' "$wf" | awk -v RS='\n  [A-Za-z0-9_.-]+:[[:space:]]*\n' -v want="$want" '
      {
        n = split($0, lines, "\n")
        matched = 0
        guarded = 0
        for (i = 1; i <= n; i++) {
          line = lines[i]
          if (match(line, /^[[:space:]]*(-[[:space:]]+)?run:[[:space:]]*/)) {
            val = substr(line, RLENGTH + 1)
            gsub(/^[[:space:]]+/, "", val)
            gsub(/[[:space:]]+$/, "", val)
            if (val == want) { matched = 1 }
          }
          if (line ~ /^[[:space:]]*(-[[:space:]]+)?(if|continue-on-error):/) { guarded = 1 }
        }
        if (matched && !guarded) { found = 1 }
      }
      END { exit(found ? 0 : 1) }
    '
}

# ---------------------------------------------------------------------------
# N13 - the N12 probe above split ci.yml into per-STEP blocks and only refused
#       `continue-on-error: true` in the same step as the `run:` line. It reported FIXED for
#       a job-level `if: false`, a job-level `continue-on-error: true`, a step-level `if:
#       false`, and the `run:` line commented out with a single `#` - four ways to disable
#       the job while the probe that is supposed to guard it still passes. Applies each
#       mutation to a scratch copy of ci.yml and asserts probe_probe_suite_is_not_run_by_ci
#       reports WEAK (returns 0) for every one. WEAK before the fix above, FIXED after.
# ---------------------------------------------------------------------------
probe_suite_probe_accepts_a_disabled_probes_job() {
  local base d rc overall
  base="$(mktemp -d)"
  mkdir -p "$base/.github/workflows"
  cp .github/workflows/ci.yml "$base/.github/workflows/ci.yml"
  overall=0

  # a: job-level `if: false` on cipher-probes
  d="$base/a"; mkdir -p "$d/.github/workflows"
  sed 's/^  cipher-probes:$/  cipher-probes:\n    if: false/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  # b: job-level `continue-on-error: true` on cipher-probes
  d="$base/b"; mkdir -p "$d/.github/workflows"
  sed 's/^  cipher-probes:$/  cipher-probes:\n    continue-on-error: true/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  # c: step-level `if: false` on the step running the probe suite
  d="$base/c"; mkdir -p "$d/.github/workflows"
  sed 's/^\([[:space:]]*\)run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline\.sh$/\1if: false\n&/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  # d: the `run:` line commented out
  d="$base/d"; mkdir -p "$d/.github/workflows"
  sed 's/^\([[:space:]]*\)run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline\.sh$/\1# run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline.sh/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  for d in a b c d; do
    ( cd "$base/$d" && probe_probe_suite_is_not_run_by_ci )
    rc=$?
    # rc 1 ("FIXED") on a disabled-job mutation means probe_probe_suite_is_not_run_by_ci was
    # fooled into believing the suite still runs unconditionally: the N13 weakness is present.
    [ "$rc" -eq 0 ] || overall=1
  done

  rm -rf "$base"
  [ "$overall" -ne 0 ]   # a mutation slipped past: weakness present (WEAK)
}

# ---------------------------------------------------------------------------
# N14 - the N13 fix still matched the `run:` line by substring, so a trailing comment after
#       the command (`run: true # CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh`)
#       runs `true` and still reads as wired. Also cover the `run: |` multi-line form, where
#       the command appears on a line of the block after another command has already run -
#       that must be refused too, since the `run:` line itself is just `|`. Applies both
#       mutations to a scratch copy of ci.yml and asserts probe_probe_suite_is_not_run_by_ci
#       reports WEAK (returns 0) for both. WEAK before the fix above, FIXED after.
# ---------------------------------------------------------------------------
probe_suite_probe_accepts_a_trailing_comment_disable() {
  local base d rc overall
  base="$(mktemp -d)"
  mkdir -p "$base/.github/workflows"
  cp .github/workflows/ci.yml "$base/.github/workflows/ci.yml"
  overall=0

  # a: the command hidden after a trailing comment on a `run: true` line
  d="$base/a"; mkdir -p "$d/.github/workflows"
  sed 's/^\([[:space:]]*\)run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline\.sh$/\1run: true # CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline.sh/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  # b: the command hidden inside a `run: |` multi-line block, after another command
  d="$base/b"; mkdir -p "$d/.github/workflows"
  sed 's/^\([[:space:]]*\)run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline\.sh$/\1run: |\n\1  true\n\1  CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline.sh/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  for d in a b; do
    ( cd "$base/$d" && probe_probe_suite_is_not_run_by_ci )
    rc=$?
    # rc 1 ("FIXED") on a disabled-job mutation means probe_probe_suite_is_not_run_by_ci was
    # fooled into believing the suite still runs unconditionally: the N14 weakness is present.
    [ "$rc" -eq 0 ] || overall=1
  done

  rm -rf "$base"
  [ "$overall" -ne 0 ]   # a mutation slipped past: weakness present (WEAK)
}


# ===========================================================================
# Final verification of 1da507e (F-ids). Everything below asserts a weakness
# introduced or left open by the licence switch and the N-fix pass.
# ===========================================================================

# Sources the helper functions of tools/check-third-party-licences.sh without running its
# argument dispatch (which would `exit 1` on no args and kill the probe run).
_source_licence_lib() {
  local lib
  lib="$(mktemp)"
  sed '/^if \[ "\${1:-}" = "--self-test" \]/,$d' tools/check-third-party-licences.sh >"$lib"
  # shellcheck disable=SC1090
  source "$lib"
  rm -f "$lib"
}

# ---------------------------------------------------------------------------
# F1 - <excludedGroups>com\.housedevinci</excludedGroups> is not anchored. license-maven-plugin
#      wraps a group pattern as "[^:]*(" + pattern + ")[^:]*:[^:]+" and matches it against
#      "groupId:artifactId" with Matcher.matches(), so the pattern is a SUBSTRING test on the
#      groupId: com.housedevinci-evil and xcom.housedevinci are excluded too, and an excluded
#      dependency is checked by neither gate (it never reaches includedLicenses and never
#      appears in THIRD-PARTY-NOTICES.txt for the denial pass to read).
#      Weak while the pattern in pom.xml matches a lookalike groupId under that wrapping.
# ---------------------------------------------------------------------------
probe_excluded_groups_pattern_also_excludes_lookalike_groups() {
  local pat
  pat=$(grep -o '<excludedGroups>[^<]*</excludedGroups>' pom.xml | sed 's/<[^>]*>//g')
  [ -n "$pat" ] || return 1
  perl -e '
    my ($pat, @ga) = @ARGV;
    my $re = qr/^[^:]*($pat)[^:]*:[^:]+$/;
    for my $ga (@ga) { exit 0 if $ga =~ $re; }   # a lookalike matched: still weak
    exit 1;
  ' "$pat" "com.housedevinci-evil:evil-dep" "xcom.housedevinci:evil-dep"
}

# ---------------------------------------------------------------------------
# F2 - N3 respelled through the dependency's URL. parse_notices collects "(...)"" groups with
#      [^()]*, which cannot span a nested pair, so a dependency whose own <url> contains
#      "(ch.qos.logback:logback-core:1.5.6 - x)" makes THAT the last paren group on the line.
#      The real coordinate is dropped, the forged one is on ALLOWED_COORDINATES, and the
#      dependency's GPL-3.0 half is never checked. The plugin's count header still matches,
#      so nothing else catches it.
#      Weak while the script reports a clean notices file for such a line.
# ---------------------------------------------------------------------------
probe_denial_pass_coordinate_can_be_forged_by_the_dependency_url() {
  local d rc
  d="$(mktemp -d)"
  cat >"$d/THIRD-PARTY-NOTICES.txt" <<'EOF'
Lists of 1 third-party dependencies.
     (Apache-2.0) (GPL-3.0) evil-url (example.synth:evil-b:1.0 - http://x/(ch.qos.logback:logback-core:1.5.6 - y))
EOF
  tools/check-third-party-licences.sh "$d" jar >/dev/null 2>&1
  rc=$?
  rm -rf "$d"
  [ "$rc" -eq 0 ]   # exit 0 on a GPL-3.0 line: still weak
}

# ---------------------------------------------------------------------------
# F3 - `VALIDSIG <fpr> ...` names the key that MADE the signature. On a key with a signing
#      subkey (git tag -s uses it even when -u names the primary) that is the SUBKEY
#      fingerprint; the PRIMARY fingerprint - the one the release runbook tells the
#      maintainer to put in RELEASE_SIGNING_KEY_ID, via `gpg --fingerprint` - is the LAST field of the same
#      line. Reproduced: with a primary+signing-subkey key the step's grep does not match and
#      the release is refused with "is not signed by <fpr>".
#      Weak while the grep anchors the fingerprint to field 1 instead of the primary-key field.
# ---------------------------------------------------------------------------
probe_tag_signature_binds_the_signing_subkey_not_the_primary_key() {
  local step
  step="$(sed -n '/- name: Verify the tag signature/,/^      - name:/p' "$WF")"
  grep -q 'VALIDSIG \${fingerprint} ' <<<"$step"
}

# ---------------------------------------------------------------------------
# F4 - the deny list carries the bare pattern "mpl" for Mozilla. Normalisation strips
#      punctuation, so "mpl" is a substring of "example", "simplified", "template",
#      "compliance": "Simplified BSD License" and any licence URL on example.com are DENIED.
#      Fail-closed, but it breaks the build on a permissive dependency the allowlist accepts.
#      Weak while a permissive name containing the letters m-p-l is denied.
# ---------------------------------------------------------------------------
probe_denial_list_denies_permissive_names_containing_mpl() {
  ( _source_licence_lib
    is_denied_token "Simplified BSD License" || is_denied_token "https://example.com/LICENSE" )
}

# ---------------------------------------------------------------------------
# F5 - the copyleft patterns are version-pinned where the id is not: "eupl12" misses
#      "EUPL v1.1" and "EUPL-1.1" (copyleft), "sspl10" misses a bare "SSPL" and "SSPL-2.0",
#      and OSL-3.0 / CPAL are absent entirely. Each only matters in the cumulative-dual case
#      the denial pass exists for (permissive half passes includedLicenses, copyleft half
#      must be caught here) - which is exactly N2's scenario.
#      Weak while any of them is allowed.
# ---------------------------------------------------------------------------
probe_denial_list_misses_eupl_1_1_bare_sspl_and_osl() {
  ( _source_licence_lib
    ! is_denied_token "EUPL v1.1" || ! is_denied_token "SSPL" || ! is_denied_token "OSL-3.0" )
}

# ---------------------------------------------------------------------------
# F6 - pom.xml's licence-allowlist comment still reads "Apache-2.0    the licence of this
#      project". Since 1da507e the project is FSL-1.1-ALv2. A stale Apache-2.0 claim about
#      our own code, in the file that is published to Maven Central, is the one place a
#      licensee would look to contradict LICENSE.
#      Weak while the comment survives.
# ---------------------------------------------------------------------------
probe_pom_comment_still_calls_apache_the_licence_of_this_project() {
  grep -q 'the licence of this project' pom.xml
}

# ---------------------------------------------------------------------------
# F7 - CONTRIBUTING.md states no inbound licence terms. Under Apache-2.0 the inbound grant
#      was conventional (ASF SS5); FSL-1.1-ALv2 has no contribution clause at all, and this
#      repository is about to be made public with a paid Pro edition beside it. Without a DCO
#      or an explicit grant, a merged outside PR arrives with no licence to relicense it.
#      Weak while the file says nothing about the licence of a contribution.
# ---------------------------------------------------------------------------
probe_contributing_states_no_inbound_licence_terms() {
  ! grep -qiE 'licen[cs]e|developer certificate of origin|\bDCO\b|copyright' CONTRIBUTING.md
}

# ---------------------------------------------------------------------------
# F8 - RETIRED. Verified FIXED (the release runbook's release-signing-key instructions
#      and Central Portal namespace organisation both now spell the licensor
#      "HouseDevinci", matching LICENSE/NOTICE/the POM). The release runbook that this
#      probe read is maintained privately and is out of scope for this public probe
#      suite; it is no longer checked here.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# F9 - SampleEndToEndTest asserts that the 4th tool call in the minute is BUDGET_EXCEEDED,
#      but BudgetLimit windows are epoch-aligned and TUMBLING (windowStart =
#      floorDiv(now, size) * size), so the four calls reset the counter whenever a window
#      boundary falls between them. Observed for real: one ./mvnw -B verify on a clean tree
#      failed at SampleEndToEndTest:155, three re-runs were green. The auto-configuration
#      already offers the seam - agentGuardClock is @ConditionalOnMissingBean(name = ...) -
#      so the test can supply a clock it controls.
#      Weak while the test defines no clock of its own.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# G1 - F2 respelled FORWARD. F2 closed the case where a URL's nested "(...)" splits the
#      coordinate group; the depth-aware scan fixed that. But the scan still trusts "the
#      LAST top-level group", and a dependency's own <url> is free text that can simply
#      CLOSE its own coordinate group and open a fresh, allowlisted one after it:
#        <url>http://x) (ch.qos.logback:logback-core:1.5.6 - http://y</url>
#      renders as two top-level groups, the last of which is on ALLOWED_COORDINATES, so the
#      dependency is skipped and its GPL-3.0 declaration is never checked. The plugin's own
#      count header still matches (one line in, one line parsed), so the count backstop that
#      catches a silently-dropped line does not fire here either.
#      Weak while the script reports a clean notices file for such a line.
# ---------------------------------------------------------------------------
# F9 (the sample end-to-end test taking its timestamps from the wall clock instead of the
# application's injected clock) has no probe here: this product's sample end-to-end test makes
# no assertion about a timestamp at all, so there is no wall-clock dependency for a probe to
# detect. The clock IS injected in this product (the starter builds the erasure service with a
# Clock bean) and the starter's own tests fix it; that is a different mechanism with its own
# tests, not this probe's target.

probe_denial_pass_coordinate_can_be_forged_by_a_trailing_group() {
  local d rc
  d="$(mktemp -d)"
  cat >"$d/THIRD-PARTY-NOTICES.txt" <<'EOF'
Lists of 1 third-party dependencies.
     (GPL-3.0) evil-trailing (example.synth:evil-c:1.0 - http://x) (ch.qos.logback:logback-core:1.5.6 - http://y)
EOF
  tools/check-third-party-licences.sh "$d" jar >/dev/null 2>&1
  rc=$?
  rm -rf "$d"
  [ "$rc" -eq 0 ]   # exit 0 on a GPL-3.0 line: still weak
}

# ---------------------------------------------------------------------------
# G2 - ci.yml's `dco` job decides a commit is a merge commit, and therefore exempt from the
#      sign-off requirement, by matching its SUBJECT against "Merge branch"* /
#      "Merge remote-tracking"*. A subject is free text chosen by the committer, so an
#      ORDINARY single-parent commit titled `Merge branch 'x' into y` is exempted from the
#      DCO check with no sign-off at all. Whether a commit is a merge is decided by its
#      parent count (%P), which the committer cannot forge.
#      Weak while the job branches on the subject instead of the parent count.
# ---------------------------------------------------------------------------
probe_dco_check_is_skipped_by_a_forged_merge_subject() {
  local w=.github/workflows/ci.yml
  [ -f "$w" ] || return 0
  grep -q '"Merge branch"\*' "$w"
}

# ---------------------------------------------------------------------------
# G3 - the parent-count exemption that closed G2 is broader than "a real merge". ANY
#      commit with two or more parents is exempt, and a merge commit's tree is not
#      constrained by its parents: an "evil merge" can carry content that exists in NO
#      parent. So an octopus merge (three parents), or a two-parent commit whose second
#      parent is an unrelated branch rather than the base, ships unsigned-off content
#      while the gate reports "all commits are signed off".
#
#      Behavioural probe: extracts the real dco step body from ci.yml and runs it against
#      a synthetic repository containing an octopus merge that adds a file present in none
#      of its three parents. Returns 0 (WEAK) while the gate passes that repository.
# ---------------------------------------------------------------------------
probe_dco_exempts_an_octopus_merge_carrying_unsigned_content() {
  local w=.github/workflows/ci.yml body repo rc
  [ -f "$w" ] || return 0
  body="$(awk '
    /name: Verify every commit in this pull request is signed off/ { instep=1 }
    instep && /run: \|/ { inrun=1; next }
    inrun && /^  [a-z-]+:$/ { exit }
    inrun { sub(/^          /, ""); print }
  ' "$w")"
  [ -n "$body" ] || return 0   # step vanished: cannot prove the fix, count as still weak

  repo="$(mktemp -d)"
  (
    cd "$repo" || exit 1
    git init -q -b main . && git config user.name t && git config user.email t@e.com
    echo v1 > base.txt && git add -A
    git commit -q -m "$(printf 'feat: base\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q -b a && echo a > a.txt && git add -A
    git commit -q -m "$(printf 'feat: a\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q main && git checkout -q -b b && echo b > b.txt && git add -A
    git commit -q -m "$(printf 'feat: b\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q main
    git merge -q --no-commit --no-ff a b >/dev/null 2>&1 || true
    # content present in NO parent, and no Signed-off-by trailer anywhere
    echo BACKDOOR > evil.txt && git add -A
    git commit -q -m "Merge branches 'a' and 'b'"
  ) >/dev/null 2>&1 || { rm -rf "$repo"; return 0; }

  local base head
  base="$(git -C "$repo" rev-list --max-parents=0 HEAD)"
  head="$(git -C "$repo" rev-parse HEAD)"
  ( cd "$repo" && BASE_SHA="$base" HEAD_SHA="$head" \
      bash -c "$body" ) >/dev/null 2>&1
  rc=$?
  rm -rf "$repo"
  # exit 0 means the gate accepted an octopus merge carrying unsigned-off content: WEAK.
  [ "$rc" -eq 0 ]
}


# ---------------------------------------------------------------------------
# G4 - the G3 fix reads `auto="$(git merge-tree --write-tree "$1" "$2" 2>/dev/null | head -1)"`.
#      git merge-tree exits 1 when the merge it computes CONFLICTS. It still writes a tree,
#      so head -1 succeeds - but the step runs under `set -euo pipefail`, so pipefail hands
#      the pipeline git's 1, the assignment takes that status, and set -e kills the whole
#      step there: mid-loop, before the sign-off check, before any ::error:: annotation,
#      with 2>/dev/null hiding git's message. A legitimate, fully SIGNED-OFF back-merge
#      that resolved a conflict is rejected with no output at all.
#
#      Behavioural probe: extracts the real dco step body from ci.yml and runs it against a
#      synthetic repository whose back-merge resolved a real conflict and IS signed off.
#      That range is compliant and must pass. Returns 0 (WEAK) while the step exits
#      non-zero.
# ---------------------------------------------------------------------------
probe_dco_step_aborts_silently_on_a_conflicted_back_merge() {
  local w=.github/workflows/ci.yml body repo rc
  [ -f "$w" ] || return 0
  body="$(awk '
    /name: Verify every commit in this pull request is signed off/ { instep=1 }
    instep && /run: \|/ { inrun=1; next }
    inrun && /^  [a-z-]+:$/ { exit }
    inrun { sub(/^          /, ""); print }
  ' "$w")"
  [ -n "$body" ] || return 0   # step vanished: cannot prove the fix, count as still weak

  repo="$(mktemp -d)"
  (
    cd "$repo" || exit 1
    git init -q -b main . && git config user.name t && git config user.email t@e.com
    printf 'line\n' > c.txt && git add -A
    git commit -q -m "$(printf 'feat: base\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q -b feature && printf 'feature-side\n' > c.txt && git add -A
    git commit -q -m "$(printf 'feat: f\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q main && printf 'main-side\n' > c.txt && git add -A
    git commit -q -m "$(printf 'feat: base moves on\n\nSigned-off-by: T <t@e.com>')"
    git rev-parse HEAD > .base
    git checkout -q feature
    # both sides edited the same line: the automatic merge conflicts, git merge-tree exits 1
    git merge --no-commit --no-ff main >/dev/null 2>&1 || true
    printf 'resolved\n' > c.txt && git add c.txt
    git commit -q -m "$(printf "Merge branch 'main' into feature\n\nSigned-off-by: T <t@e.com>")"
  ) >/dev/null 2>&1 || { rm -rf "$repo"; return 0; }

  local base head
  base="$(cat "$repo/.base")"
  head="$(git -C "$repo" rev-parse HEAD)"
  ( cd "$repo" && BASE_SHA="$base" HEAD_SHA="$head" \
      bash -c "$body" ) >/dev/null 2>&1
  rc=$?
  rm -rf "$repo"
  # every commit in this range carries a Signed-off-by. Non-zero means the step aborted
  # on the conflicted merge-tree instead of checking them: WEAK.
  [ "$rc" -ne 0 ]
}


# ===========================================================================
# Design-stop build (2026-09-14): probes for the mechanisms the amended release-pipeline
# design adds. Same rule as every block above - each asserts a WEAKNESS, reads WEAK while
# the mechanism is missing or wrong, and flips to FIXED when it is built.
# ===========================================================================

CI=.github/workflows/ci.yml

# Extracts the body of a `run: |` block for a named step, from a named workflow file.
step_body() { # step_body <workflow> <step name>
  awk -v want="- name: $2" '
    index($0, want) { instep=1; next }
    instep && /run: \|/ { inrun=1; next }
    instep && !inrun && /^      - name:/ { exit }
    inrun && /^      - name:/ { exit }
    # A run block also ends at the next job header (two-space indent): the last step of a job
    # is followed by "  <next-job>:", not by another "- name:". Without this the extracted
    # body ran on into the next job and failed for a reason that has nothing to do with the
    # step under test.
    inrun && /^  [a-z][a-z0-9-]*:/ { exit }
    inrun { print }
  ' "$1"
}

# Prints the 1-based line number of a named step in a workflow, or nothing.
step_line() { # step_line <workflow> <step name>
  grep -n -- "- name: $2" "$1" | head -1 | cut -d: -f1
}

# ---------------------------------------------------------------------------
# The environment check must be its OWN job that the key-holding job depends on. As the
# first step of the publish job it is worthless: the environment's secrets are bound to a
# job when it is scheduled, so the refusal lands after the signing key and the Central
# token are already in the runner.
# ---------------------------------------------------------------------------
probe_preflight_is_not_its_own_job() {
  grep -q '^  preflight:$' "$WF" || return 0                      # no such job: weak
  local pub
  pub="$(awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  publish:$/ {f=1} f' "$WF")"
  grep -q 'needs: preflight' <<<"$pub" || return 0                # publish does not wait: weak
  # The preflight job must hold nothing worth stealing: no environment, no secret.
  local pre
  pre="$(awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  preflight:$/ {f=1} f' "$WF")"
  grep -q 'environment:' <<<"$pre" && return 0         # it holds the environment: weak
  grep -q 'secrets\.' <<<"$pre" && return 0            # it can see a secret: weak
  return 1
}

# Runs the real preflight step body against a stubbed `gh`, so the probe tests the
# workflow's own current logic rather than a frozen copy of it.
_preflight_verdict() { # _preflight_verdict <gh stub body>; echoes the step's exit code
  local body stub rc
  body="$(step_body "$WF" "Require a reviewer-gated \`release\` environment and a protected main")"
  [ -n "$body" ] || { echo 0; return; }      # step vanished: cannot prove the fix
  stub="$(mktemp -d)"
  printf '#!/usr/bin/env bash\n%s\n' "$1" > "$stub/gh"
  chmod +x "$stub/gh"
  ( PATH="$stub:$PATH" GITHUB_REPOSITORY=1of1Canopus/gdpr-shredding bash -c "$body" ) >/dev/null 2>&1
  rc=$?
  rm -rf "$stub"
  echo "$rc"
}

# ---------------------------------------------------------------------------
# "We could not read the gate" must be a refusal. A private repository on this plan answers
# nothing for environments and rulesets, and `environment: release` does not fail there -
# GitHub creates the environment implicitly, with no protection rules at all.
# ---------------------------------------------------------------------------
probe_preflight_passes_when_the_gates_cannot_be_read() {
  [ "$(_preflight_verdict 'exit 1')" -eq 0 ]
}

# ---------------------------------------------------------------------------
# An environment that exists but requires no reviewer is not a gate.
# ---------------------------------------------------------------------------
probe_preflight_accepts_an_environment_with_no_reviewer() {
  local stub_body
  stub_body='case "$*" in
  *environments/release*) echo "{\"name\":\"release\",\"protection_rules\":[{\"type\":\"wait_timer\",\"wait_timer\":0}]}" ;;
  *rules/branches/main*) echo "[{\"type\":\"required_status_checks\",\"parameters\":{\"required_status_checks\":[{\"context\":\"Build & test\"},{\"context\":\"DCO sign-off\"},{\"context\":\"Cipher probes\"},{\"context\":\"Reference guard\"}]}}]" ;;
  *) exit 1 ;;
esac'
  [ "$(_preflight_verdict "$stub_body")" -eq 0 ]
}

# ---------------------------------------------------------------------------
# A ruleset that does not require the four checks is not a gate either. Same stub, with a
# reviewer present and one required check missing.
# ---------------------------------------------------------------------------
probe_preflight_accepts_main_without_the_required_checks() {
  local stub_body
  stub_body='case "$*" in
  *environments/release*) echo "{\"name\":\"release\",\"protection_rules\":[{\"type\":\"required_reviewers\",\"reviewers\":[{\"type\":\"User\"}]}]}" ;;
  *rules/branches/main*) echo "[{\"type\":\"required_status_checks\",\"parameters\":{\"required_status_checks\":[{\"context\":\"Build & test\"}]}}]" ;;
  *) exit 1 ;;
esac'
  [ "$(_preflight_verdict "$stub_body")" -eq 0 ]
}

# Control: with both gates real, preflight must PASS. A gate that refuses everything is not
# a gate, it is a broken workflow, and it would be "fixed" by deleting it.
probe_preflight_refuses_even_when_both_gates_are_real() {
  local stub_body
  stub_body='case "$*" in
  *environments/release*) echo "{\"name\":\"release\",\"protection_rules\":[{\"type\":\"required_reviewers\",\"reviewers\":[{\"type\":\"User\",\"reviewer\":{\"login\":\"someone\"}}]}]}" ;;
  *rules/branches/main*) echo "[{\"type\":\"required_status_checks\",\"parameters\":{\"required_status_checks\":[{\"context\":\"Build & test\"},{\"context\":\"DCO sign-off\"},{\"context\":\"Cipher probes\"},{\"context\":\"Reference guard\"}]}}]" ;;
  *) exit 1 ;;
esac'
  [ "$(_preflight_verdict "$stub_body")" -ne 0 ]
}

# ---------------------------------------------------------------------------
# A re-run of a green run, or a second tag for a version already cut, would sign and upload
# a second bundle for a version a human has already seen.
# ---------------------------------------------------------------------------
probe_release_does_not_refuse_a_replay() {
  local body
  body="$(step_body "$WF" "Refuse a replay of a version that already exists")"
  [ -n "$body" ] || return 0                                      # no such step: weak
  grep -q 'repo1.maven.org' <<<"$body" || return 0     # does not ask Maven Central: weak
  grep -q 'central.sonatype.com/api/v1/publisher' <<<"$body" || return 0
  return 1
}

probe_replay_check_runs_after_the_upload() {
  local replay deploy
  replay="$(step_line "$WF" 'Refuse a replay of a version that already exists')"
  deploy="$(step_line "$WF" 'Verify, licence check, sign, upload')"
  [ -n "$replay" ] && [ -n "$deploy" ] || return 0                # missing: weak
  [ "$replay" -lt "$deploy" ] && return 1                         # before the upload: FIXED
  return 0
}

# Runs the real replay-check step body against a stubbed `curl`, so the probe tests the
# workflow's own current logic rather than a frozen copy of it. Central and the Portal's
# published-check both answer clean (part 1 and 2 of the step must pass so the probe
# exercises part 3, the deployment list).
_replay_verdict() { # _replay_verdict <curl stub body>; echoes the step's exit code
  local body stub rc
  body="$(step_body "$WF" 'Refuse a replay of a version that already exists')"
  [ -n "$body" ] || { echo 0; return; }      # step vanished: cannot prove the fix
  stub="$(mktemp -d)"
  printf '#!/usr/bin/env bash\n%s\n' "$1" > "$stub/curl"
  chmod +x "$stub/curl"
  ( PATH="$stub:$PATH" CENTRAL_USERNAME=probe CENTRAL_TOKEN=probe VERSION=9.9.9-cipher-probe \
      bash -c "$body" ) >/dev/null 2>&1
  rc=$?
  rm -rf "$stub"
  echo "$rc"
}

# ---------------------------------------------------------------------------
# RP-4 - the replay check only ever asked for page 0 of the Portal deployment list. A
# VALIDATED-but-not-yet-published deployment for this version sitting behind a hundred
# newer ones on page 1 was invisible to it. Page 0 here answers with 100 unrelated
# deployments (a full page - the signal to keep paging); page 1 carries the clash. Weak if
# the step stops after page 0 and reports no clash; fixed if it pages on and refuses.
# ---------------------------------------------------------------------------
probe_replay_check_reads_only_the_first_page() {
  local stub_body rc
  stub_body='
case "$*" in
  *repo1.maven.org*) printf "404" ;;
  *api/v1/publisher/published*) echo "{\"published\":false}" ;;
  *api/v1/publisher/deployments*page=0*) jq -cn "{deployments: [range(100) | {deploymentName: (\"other-\" + (. | tostring)), deploymentState: \"PUBLISHED\"}]}" ;;
  *api/v1/publisher/deployments*page=1*) echo "{\"deployments\":[{\"deploymentName\":\"gdpr-shredding 9.9.9-cipher-probe (deadbeef)\",\"deploymentState\":\"VALIDATED\"}]}" ;;
  *api/v1/publisher/deployments*) echo "{\"deployments\":[]}" ;;
  *) exit 1 ;;
esac'
  rc="$(_replay_verdict "$stub_body")"
  [ "$rc" -eq 0 ]   # weak: the run 1 page over exhausted the clash and still passed
}

# ---------------------------------------------------------------------------
# Two deployments of the same version are indistinguishable on the Portal unless the name
# says which commit each was built from.
# ---------------------------------------------------------------------------
probe_deployment_name_does_not_name_the_released_commit() {
  local body
  body="$(step_body "$WF" 'Verify, licence check, sign, upload')"
  grep -q 'deployment.name=' <<<"$body" || return 0
  grep -q 'GITHUB_SHA' <<<"$body" || return 0
  grep -q '<deploymentName>${deployment.name}</deploymentName>' pom.xml || return 0
  return 1
}

# ---------------------------------------------------------------------------
# The bytes that must be compared are the ones that went over the wire. The jars left in
# each module's target/ are a sibling of the bundle, not the bundle.
# ---------------------------------------------------------------------------
probe_bundle_comparison_reads_the_build_directory_not_the_bundle() {
  local body
  body="$(step_body "$WF" 'Confirm the uploaded bundle matches the reproducibility check')"
  [ -n "$body" ] || return 0                                      # no such step: weak
  grep -q 'central-bundle.zip' <<<"$body" || return 0  # not reading the bundle: weak
  grep -q 'unzip' <<<"$body" || return 0
  grep -qE '^\s*for jar in gdpr-shredding-core/target' <<<"$body" && return 0
  return 1
}

# A jar that was proved reproducible and then never uploaded is a silent hole in the other
# direction: the bundle would be missing an artifact and every entry it does contain matches.
probe_bundle_comparison_misses_a_jar_absent_from_the_bundle() {
  local body
  body="$(step_body "$WF" 'Confirm the uploaded bundle matches the reproducibility check')"
  [ -n "$body" ] || return 0
  grep -q 'MISSING FROM BUNDLE' <<<"$body" || return 0
  return 1
}

# ---------------------------------------------------------------------------
# RP-5 - poms in the bundle were never compared, only jars. Central consumes the pom
# bytes, and the window this whole comparison exists to close (proved build vs. what was
# uploaded) applies to them identically. Two places have to record and compare *.pom:
# scripts/verify-reproducible.sh's collect()/comparison, and the bundle-comparison step's
# find, which must walk *.pom alongside *.jar.
# ---------------------------------------------------------------------------
probe_reproducibility_check_never_records_poms() {
  grep -q '\*\.pom' scripts/verify-reproducible.sh || return 0
  return 1
}

probe_bundle_comparison_never_reads_poms() {
  local body
  body="$(step_body "$WF" 'Confirm the uploaded bundle matches the reproducibility check')"
  [ -n "$body" ] || return 0
  grep -qE "find \"\\\$work\" .*'\\*\\.pom'" <<<"$body" || return 0
  return 1
}

# ---------------------------------------------------------------------------
# The reference guard: one definition, its own job, the self-test run by CI, the jar loop
# covering the main jar.
# ---------------------------------------------------------------------------
probe_reference_guard_pattern_is_defined_more_than_once() {
  local files n
  files="$(git ls-files)"
  n="$(grep -lE "QUESTIONS\\\\\.md\|STATUS\\\\\.md" <<<"$files" >/dev/null 2>&1; grep -c . /dev/null)"
  # Count the tracked files that carry a pattern definition line.
  n=0
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    grep -q "docs\[/\]plans" "$f" 2>/dev/null && n=$((n + 1))
  done <<<"$files"
  [ "$n" -eq 1 ] && return 1     # exactly one definition: FIXED
  return 0
}

probe_reference_guard_is_not_its_own_job() {
  grep -q '^  reference-guard:$' "$CI" || return 0
  local job
  job="$(awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  reference-guard:$/ {f=1} f' "$CI")"
  grep -q 'check-private-references.sh --tree' <<<"$job" || return 0
  grep -q 'check-private-references.sh --self-test' <<<"$job" || return 0
  return 1
}

probe_jar_guard_skips_the_main_jar() {
  grep -q 'for jar in "\$module"/target/\*\.jar' tools/check-private-references.sh || return 0
  return 1
}

# ---------------------------------------------------------------------------
# R-3 - the dead internal/** exemption protected nothing (this repository has no
# internal/ directory and by design never will), was wrong for the model (a top-level
# internal/ is world-readable in a public repository), and had no self-test case. Weak
# while the pathspec is still there.
# ---------------------------------------------------------------------------
probe_guard_still_exempts_internal_directory() {
  # Looks for the actual pathspec, not any mention of the word: a historical comment
  # explaining why the carve-out was removed is the right residue and must not re-trip
  # this probe (same rule as the DCO grandfather-exemption comment elsewhere).
  grep -q -- ":!internal/\*\*" tools/check-private-references.sh && return 0
  return 1
}

# ---------------------------------------------------------------------------
# The licence gate: the denial pass has to be wired into the build (without it the pom's
# includedLicenses string is the licence-name pattern N9 forbids as the only gate), and a
# carve-out must not be able to outlive the dependency it was written for.
# ---------------------------------------------------------------------------
probe_denial_pass_is_not_wired_into_the_build() {
  grep -q 'check-third-party-licences.sh' pom.xml || return 0
  grep -q '<artifactId>exec-maven-plugin</artifactId>' pom.xml || return 0
  return 1
}

probe_licence_carve_out_can_outlive_its_dependency() {
  grep -q -- '--check-unused' tools/check-third-party-licences.sh || return 0
  grep -q -- 'check-third-party-licences.sh --check-unused' "$CI" || return 0
  return 1
}

# ---------------------------------------------------------------------------
# The dry run's jar assertions are only worth anything against the jar a release produces,
# and a release runs the tests.
# ---------------------------------------------------------------------------
probe_release_dryrun_skips_the_tests() {
  local job
  job="$(awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  release-dryrun:$/ {f=1} f' "$CI")"
  [ -n "$job" ] || return 0
  grep -q 'mvnw .*-DskipTests.*-Prelease' <<<"$job" && return 0
  return 1
}

probe_sources_jar_contents_are_never_asserted() {
  local job
  job="$(awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  release-dryrun:$/ {f=1} f' "$CI")"
  grep -q 'unzip -Z1' <<<"$job" || return 0
  return 1
}

# ---------------------------------------------------------------------------
# RP-3 - the sources-jar assertion allowlists extensions, not paths, so a build-output path
# riding in on an allowlisted extension (target/classes/META-INF/spring-configuration-
# metadata.json is exactly this shape, generated on every build) sweeps straight through.
# Extracts the real step body from ci.yml and runs it, for real, against a synthetic
# sources jar that is otherwise clean and carries exactly that one entry.
# ---------------------------------------------------------------------------
probe_sources_jar_assertion_is_extension_only_not_path_based() {
  command -v zip >/dev/null 2>&1 || { echo "        (skipped: zip not installed)" >&2; return 0; }
  local body work rc
  body="$(step_body "$CI" 'Confirm each sources jar holds sources, resources and the licence texts only')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  mkdir -p "$work/gdpr-shredding-core/target" "$work/gdpr-shredding-spring-boot-starter/target" \
           "$work/src/com/housedevinci/shredding" "$work/src/META-INF" "$work/src/classes/META-INF"
  : > "$work/src/com/housedevinci/shredding/Foo.java"
  : > "$work/src/META-INF/LICENSE"
  : > "$work/src/META-INF/NOTICE"
  : > "$work/src/classes/META-INF/spring-configuration-metadata.json"
  ( cd "$work/src" && zip -q -r "$work/gdpr-shredding-core/target/gdpr-shredding-core-0.1.0-sources.jar" . ) >/dev/null 2>&1
  cp "$work/gdpr-shredding-core/target/gdpr-shredding-core-0.1.0-sources.jar" \
     "$work/gdpr-shredding-spring-boot-starter/target/gdpr-shredding-spring-boot-starter-0.1.0-sources.jar"
  ( cd "$work" && bash -c "$body" ) >/dev/null 2>&1
  rc=$?
  rm -rf "$work"
  # Weak: the step passed (exit 0) despite the build-output path. Fixed: it refused (non-zero).
  [ "$rc" -eq 0 ]
}


echo "the security review release-pipeline probes  (WEAK = finding still open)"
echo
probe probe_multiline_version_accepted                       "M4 newline in the version input passes validation"   probe_multiline_version_accepted
probe probe_release_job_restores_maven_cache                 "M3 release job restores the maven/wrapper cache"     probe_release_job_restores_maven_cache
probe probe_release_job_can_exec_unverified_maven_dist       "M3 the signing job can exec an unverified dist"      probe_release_job_can_exec_an_unverified_maven_distribution
probe probe_release_job_has_no_environment_gate              "M5 no environment / reviewer gate"                   probe_release_job_has_no_environment_gate
probe probe_release_does_not_check_tag_ancestry              "M5 a tag on any commit can release"                  probe_release_does_not_check_tag_ancestry
probe probe_release_does_not_verify_tag_signature            "M5 the tag is not required to be signed"             probe_release_does_not_verify_tag_signature
probe probe_no_licence_file_in_the_repository                "M7 Apache-2.0 declared, no LICENSE anywhere"         probe_no_licence_file_in_the_repository
probe probe_published_jars_are_never_checksum_compared       "L1 the deployed jars are never compared"             probe_published_jars_are_never_checksum_compared
probe probe_concurrency_group_is_ref_scoped                  "L2 concurrency keyed on the ref, not the version"    probe_concurrency_group_is_ref_scoped_not_version_scoped
probe probe_checkout_persists_credentials                    "L3 GITHUB_TOKEN left in .git/config"                 probe_checkout_persists_credentials
probe probe_evidence_uploaded_when_release_failed            "L4 signed jars of a failed release are uploaded"     probe_evidence_uploaded_even_when_the_release_failed
probe probe_nothing_forbids_maven_debug                      "I4 nothing stops -X being added to the release"      probe_nothing_forbids_maven_debug_in_the_release_job
probe probe_licence_gate_accepts_dual_apache_or_gpl          "M1 Apache-2.0 OR GPL-3.0 passes the gate"            probe_licence_gate_accepts_a_dual_apache_or_gpl_dependency
echo
probe probe_denial_pass_misses_prose_licence_names           "N2 prose GPL/MPL names pass the denial pass"         probe_denial_pass_misses_prose_licence_names
probe probe_denial_pass_coordinate_can_be_forged             "N3 the dependency <name> forges the coordinate"      probe_denial_pass_coordinate_can_be_forged_by_the_dependency_name
probe probe_denial_pass_crashes_on_empty_licence_token       "N10 empty () token kills the scan under set -u"      probe_denial_pass_crashes_on_an_empty_licence_token
probe probe_verify_fails_on_a_clean_checkout                 "N1 ./mvnw verify fails on a fresh clone"             probe_verify_fails_on_a_clean_checkout
probe probe_sources_jar_differs_from_a_test_run               "post-release: sources jar not reproducible with tests running" probe_sources_jar_differs_from_a_build_that_actually_ran_tests
probe probe_bundle_assertion_points_at_the_wrong_path        "N4 the L5 bundle path is not where it is written"    probe_bundle_assertion_points_at_the_wrong_path
probe probe_tag_signature_check_is_optional_and_unbound      "N5 tag signature check is off by default"            probe_tag_signature_check_is_optional_and_unbound
probe probe_debug_guard_misses_the_slf4j_log_level           "N6 --errors and slf4j debug walk past the guard"     probe_debug_guard_misses_the_slf4j_log_level
probe probe_debug_guard_refuses_its_own_maven_opts_pin       "N6 the guard refuses the workflow's own MAVEN_OPTS"  probe_debug_guard_refuses_its_own_maven_opts_pin
probe probe_ancestry_check_skips_the_dispatch_path           "N8 workflow_dispatch skips the ancestry check"       probe_ancestry_check_skips_the_dispatch_path
probe probe_gpg_arguments_comment_credits_the_wrong_actor    "N11 I1 was never closed"                             probe_gpg_arguments_comment_still_credits_the_wrong_actor
probe probe_probe_suite_is_not_run_by_ci                      "N12 nothing in .github/ runs this suite"             probe_probe_suite_is_not_run_by_ci
probe probe_suite_probe_accepts_a_disabled_probes_job          "N13 the N12 probe misses a disabled probes job"      probe_suite_probe_accepts_a_disabled_probes_job
probe probe_suite_probe_accepts_a_trailing_comment_disable      "N14 a trailing comment still hides a disabled job"   probe_suite_probe_accepts_a_trailing_comment_disable
echo
probe probe_excluded_groups_also_excludes_lookalike_groups   "F1 com.housedevinci-evil is excluded too"            probe_excluded_groups_pattern_also_excludes_lookalike_groups
probe probe_denial_pass_coordinate_forged_by_the_url         "F2 a URL with parens forges the coordinate"          probe_denial_pass_coordinate_can_be_forged_by_the_dependency_url
probe probe_tag_signature_binds_the_subkey_not_the_primary   "F3 VALIDSIG field 1 is the signing subkey"           probe_tag_signature_binds_the_signing_subkey_not_the_primary_key
probe probe_denial_list_denies_simplified_bsd                "F4 bare mpl denies example/simplified"               probe_denial_list_denies_permissive_names_containing_mpl
probe probe_denial_list_misses_eupl_1_1_and_bare_sspl        "F5 EUPL 1.1 / SSPL / OSL-3.0 are allowed"            probe_denial_list_misses_eupl_1_1_bare_sspl_and_osl
probe probe_pom_comment_calls_apache_the_project_licence     "F6 pom.xml still claims Apache-2.0 for us"           probe_pom_comment_still_calls_apache_the_licence_of_this_project
probe probe_contributing_has_no_inbound_licence_terms        "F7 no inbound licence terms for contributions"       probe_contributing_states_no_inbound_licence_terms

echo
probe probe_denial_pass_coordinate_forged_by_a_trailing_group "G1 a URL can append an allowlisted coordinate"      probe_denial_pass_coordinate_can_be_forged_by_a_trailing_group
probe probe_dco_check_skipped_by_a_forged_merge_subject      "G2 a forged 'Merge branch' subject skips the DCO"   probe_dco_check_is_skipped_by_a_forged_merge_subject
probe probe_dco_exempts_an_octopus_merge                    "G3 an octopus/evil merge skips the DCO entirely"    probe_dco_exempts_an_octopus_merge_carrying_unsigned_content
probe probe_dco_aborts_on_a_conflicted_merge                "G4 the dco step crashes with no output"             probe_dco_step_aborts_silently_on_a_conflicted_back_merge

echo
probe probe_preflight_is_not_its_own_job                     "preflight is not a job the key-holder needs"        probe_preflight_is_not_its_own_job
probe probe_preflight_passes_when_gates_unreadable           "an unreadable gate is treated as a pass"            probe_preflight_passes_when_the_gates_cannot_be_read
probe probe_preflight_accepts_no_required_reviewer           "an environment with no reviewer passes"             probe_preflight_accepts_an_environment_with_no_reviewer
probe probe_preflight_accepts_main_without_the_checks        "main without the four checks passes"                probe_preflight_accepts_main_without_the_required_checks
probe probe_preflight_refuses_when_both_gates_are_real       "preflight refuses even a correctly gated repo"      probe_preflight_refuses_even_when_both_gates_are_real
probe probe_release_does_not_refuse_a_replay                 "a re-run can upload a second bundle"                probe_release_does_not_refuse_a_replay
probe probe_replay_check_runs_after_the_upload               "the replay check lands after the upload"            probe_replay_check_runs_after_the_upload
probe probe_replay_check_first_page_only                     "RP-4 a clash on page 1 of deployments is missed"    probe_replay_check_reads_only_the_first_page
probe probe_deployment_name_omits_the_released_commit        "two deployments of a version look identical"        probe_deployment_name_does_not_name_the_released_commit
probe probe_bundle_comparison_reads_the_build_directory      "the comparison reads target/, not the bundle"       probe_bundle_comparison_reads_the_build_directory_not_the_bundle
probe probe_bundle_comparison_misses_an_absent_jar           "a jar missing from the bundle is not noticed"       probe_bundle_comparison_misses_a_jar_absent_from_the_bundle
probe probe_reproducibility_check_never_records_poms         "RP-5 verify-reproducible.sh never collects *.pom"   probe_reproducibility_check_never_records_poms
probe probe_bundle_comparison_never_reads_poms                "RP-5 the bundle comparison never reads *.pom"       probe_bundle_comparison_never_reads_poms
probe probe_reference_guard_pattern_defined_twice            "the guard pattern has more than one definition"     probe_reference_guard_pattern_is_defined_more_than_once
probe probe_reference_guard_is_not_its_own_job               "the guard is not a check of its own"                probe_reference_guard_is_not_its_own_job
probe probe_jar_guard_skips_the_main_jar                     "the jar scan skips the published main jar"          probe_jar_guard_skips_the_main_jar
probe probe_guard_exempts_internal_directory                 "R-3 the dead internal/** exemption is still there"  probe_guard_still_exempts_internal_directory
probe probe_denial_pass_is_not_wired_into_the_build          "the licence denial pass is not run by the build"    probe_denial_pass_is_not_wired_into_the_build
probe probe_licence_carve_out_can_outlive_its_dependency     "a dead licence carve-out can sit in the file"       probe_licence_carve_out_can_outlive_its_dependency
probe probe_release_dryrun_skips_the_tests                   "the dry run asserts on jars a release never makes"  probe_release_dryrun_skips_the_tests
probe probe_sources_jar_contents_are_never_asserted          "nothing asserts what a sources jar contains"        probe_sources_jar_contents_are_never_asserted
probe probe_sources_jar_allowlist_is_extension_only          "RP-3 the sources-jar check is extension-only"       probe_sources_jar_assertion_is_extension_only_not_path_based

echo
echo "still weak: $pass    fixed: $flipped"
[ "$pass" -eq 0 ]
