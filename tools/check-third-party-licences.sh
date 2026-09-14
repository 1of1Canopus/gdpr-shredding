#!/usr/bin/env bash
#
# All-of denial pass over ONE module's generated THIRD-PARTY-NOTICES.txt, outside the
# license-maven-plugin allowlist execution (pom.xml, third-party-notices). The plugin's
# <includedLicenses> is an any-of *permission* check: a dependency passes if ANY one of its
# declared licences is on the allowlist, which is the legally correct answer for a genuinely
# dual-licensed artifact (logback: EPL-2.0 OR LGPL-2.1; jakarta.annotation-api: EPL-2.0 OR
# GPL-2.0-with-classpath-exception) but also the wrong answer for a dependency whose POM
# lists two CUMULATIVE licences, e.g. "Apache-2.0 OR GPL-3.0" declared as two licence blocks.
# The plugin has no way to tell the two cases apart; this script is the second pass that does,
# by only ever allowing the exception for a coordinate a human wrote down. See
# the security review's M1/M2/N2/N3/N9/N10 findings.
#
# Never add <excludedLicenses> to the plugin execution instead of this script: it makes the
# build pass AND deletes the GPL-3.0 declaration from the notices file that ships as release
# evidence (M2). The denial pass must run outside the plugin, against the evidence the plugin
# already produced, so a rejected dependency's full licence declaration stays on record.
#
# N1: this script is invoked per module, not once for the whole tree. `pom.xml`'s
# `check-third-party-licences` execution passes two arguments: ${project.build.directory}
# and ${project.packaging}. Running against a tree-wide `find` meant the PARENT module's
# `verify` (which runs first in the reactor, before any module has built) either failed
# closed on a clean checkout - breaking every fresh clone and CI run - or, in a working tree
# with stale target/ directories left from an earlier build, silently validated the PREVIOUS
# build's notices file instead of the current one. Each module now checks only its own.
#
#   tools/check-third-party-licences.sh <module-build-dir> <module-packaging>
#   tools/check-third-party-licences.sh --self-test
#   tools/check-third-party-licences.sh --check-unused   (after a full build, see below)
#
# Exit 0: the module's THIRD-PARTY-NOTICES.txt is clean (or the module is `pom`-packaged and
#         declares no notices file at all - a parent POM ships no dependencies of its own).
# Exit 1: a denied licence token was found, a dependency line could not be parsed, the parsed
#         dependency count does not match the plugin's own header, or (for a jar/war/etc.
#         module) no notices file exists at all.
#
set -uo pipefail
cd "$(dirname "$0")/.."

# Coordinates that are known, by a human, to be genuinely dual-licensed under a permissive
# OR a copyleft term (never both applying at once). An exception is a coordinate, never a
# licence-token pattern: it names precisely which dependency the human accepted. N9: this is
# the ONLY form of exception. There is deliberately no licence-token carve-out (e.g. for
# "classpath-exception") any more - a dependency needing one is admitted here, by a human, by
# coordinate, the same way logback is.
#
# Re-derived for THIS repository's resolved runtime tree on 2026-09-14, never inherited: the
# same list in another product is a carve-out for another dependency tree, and a carve-out
# that is not needed here would sit in the file waiting for a coincidence. Derivation: the
# gate was run over every module's generated THIRD-PARTY-NOTICES.txt with the allowlist
# emptied, and these are exactly the four coordinates it denied, each declaring the Eclipse
# disjunctive pair (the notices line for each is quoted below, from
# gdpr-shredding-spring-boot-starter/target/THIRD-PARTY-NOTICES.txt):
#
#   (EPL-2.0) (LGPL-2.1-only) Logback Classic Module (ch.qos.logback:logback-classic:1.5.38 ...)
#   (EPL-2.0) (LGPL-2.1-only) Logback Core Module    (ch.qos.logback:logback-core:1.5.38 ...)
#   (EPL-2.0) (GPL2 w/ CPE)   Jakarta Annotations API (jakarta.annotation:jakarta.annotation-api:3.0.0 ...)
#   (EPL-2.0) (GPL2 w/ CPE)   jakarta.transaction API (jakarta.transaction:jakarta.transaction-api:2.0.1 ...)
#
# The fourth (jakarta.transaction-api) is not on the reference product's list; it enters this
# tree through Spring Data JPA. It is the same disjunctive Eclipse shape as
# jakarta.annotation-api, which a human already accepted, and is filed as a QUESTION for the
# record rather than admitted silently.
#
# `--check-unused` (run from CI after a full build, over every module's notices file) fails
# if any entry here was never actually needed, so this list cannot outlive its dependency.
ALLOWED_COORDINATES=(
  "ch.qos.logback:logback-classic"
  "ch.qos.logback:logback-core"
  "jakarta.annotation:jakarta.annotation-api"
  "jakarta.transaction:jakarta.transaction-api"
)

# Denied licence tokens (normalised, case-insensitive). Any dependency declaring ANY of
# these among its licences fails, regardless of what else it also declares.
#
# N2: matching used to be done on the raw token - an exact-string match against a handful of
# hyphenated SPDX ids, plus a substring check for the literal letters "gpl". Real POMs write
# prose ("GNU General Public License, version 3"), and prose licence names contain none of
# those substrings, so they passed the denial pass on their permissive half - the exact M1
# hole, respelled. Matching is now done on a NORMALISED form (lowercased, everything that is
# not [a-z0-9] stripped) against both SPDX-id fragments and prose word-patterns, so
# "GPL-3.0", "GPL 3.0", "gplv3", "GPL_3" and "GNU General Public License v3" all normalise to
# a form containing "gpl3" / "generalpubliclicense" and are all denied the same way.
# F4: the bare pattern "mpl" was a substring of ordinary permissive-licence prose and URLs -
# "si-mpl-ified" (Simplified BSD License), "exa-mpl-e" (example.com), "te-mpl-ate",
# "co-mpl-iance" - so a permissive dependency the plugin's own allowlist accepts got DENIED
# here on a false-positive substring hit. Fail-closed, but the failure mode is a red build on
# a licence we ship under ourselves, which is exactly the kind of false alarm that gets a gate
# weakened. Mozilla's own id fragments (mpl11, mpl20, mpl10, mozillapubliclicense) already
# catch every real MPL spelling without the bare substring, so "mpl" is dropped, not replaced.
#
# F5: several copyleft patterns were pinned to one version where the id is not, so a
# neighbouring version walked past the pass while still failing the plugin's own allowlist
# (N2's scenario, respelled): "eupl12" missed "EUPL v1.1" / "EUPL-1.1"; "sspl10" missed a bare
# "SSPL" and "SSPL-2.0". Both are now unpinned ("eupl", "sspl") - neither substring occurs in
# any permissive licence name, so unpinning adds no false positive. OSL-3.0 (Open Software
# License, strong copyleft) and CPAL (Common Public Attribution License) were absent
# entirely and are added.
DENIED_PATTERNS=(
  # "gpl" as a bare substring catches every SPDX spelling in one go: GPL-1.0/2.0/3.0, every
  # "-only"/"-or-later" suffix, GPLv2/GPLv3, and (because the letters "gpl" occur inside
  # "lgpl" and "agpl" too) LGPL and AGPL in all their versions, with no separate entries
  # needed. It does NOT catch prose that spells the words out without the letters "g", "p",
  # "l" running together ("GNU General Public License" has no contiguous "gpl") - that is
  # what "generalpubliclicense" below is for.
  gpl
  sspl
  cddl10 cddl11
  mpl11 mpl20 mpl10
  cpol
  eupl
  busl11
  elastic20
  osl30
  cpal
  ccbyncsa ccbync ccbysa
  # Prose word-patterns, for spellings that contain none of the SPDX-id fragments above.
  generalpubliclicense
  lessergeneralpublic
  affero
  mozillapubliclicense
  commondevelopmentanddistribution
  cddl
  serversidepublic
  businesssourcelicense
  businesssource
  europeanunionpublic
  opensoftwarelicense
  commonpublicattribution
  noncommercial
)

# Any occurrence of one of these substrings, in the normalised token, denies it outright -
# this is deliberately a substring test (not an exact-match test like the coordinate
# allowlist): "gpl30" must deny "GNU General Public License, version 3.0 (GPL-3.0)" and every
# other real-world spelling variant, not just the bare id.
is_denied_token() {
  local raw="$1" norm p
  # Normalise: lowercase, strip everything that is not [a-z0-9].
  norm="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
  [ -n "$norm" ] || return 1   # an empty token (N10: a bare "()") denies nothing, matches nothing
  for p in "${DENIED_PATTERNS[@]}"; do
    [[ "$norm" == *"$p"* ]] && return 0
  done
  return 1
}

is_allowed_coordinate() {
  local coord="$1" c
  # "${a[@]:-}" rather than "${a[@]}": under `set -u`, bash 3.2 (the macOS system bash this
  # is also run on by hand) treats an EMPTY array's unsuffixed expansion as an unbound
  # variable and aborts. An empty allowlist is a legitimate end state here - `--check-unused`
  # exists precisely to drive entries out - and it must mean "nothing is carved out", never
  # "the gate crashes".
  for c in "${ALLOWED_COORDINATES[@]:-}"; do
    [ -n "$c" ] || continue
    [ "$coord" = "$c" ] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------------------
# Parses one THIRD-PARTY-NOTICES.txt on stdin. Each dependency line looks like:
#   (Apache-2.0) Gson (com.google.code.gson:gson:2.13.2 - https://...)
#   (Apache-2.0) (GPL-3.0) syn-dual (example.synthetic:syn-dual:1.0 - no url defined)
#
# N3: the coordinate is read from the LAST "(...)" group on the line, never the first. The
# earlier version took the first `(group:artifact:version - url)`-shaped group with a
# non-greedy match, and a dependency's own POM <name> is free text that lands on the SAME
# line, BEFORE its real coordinate - a dependency named
# "evil (ch.qos.logback:logback-core:1.5.6 - http://x)" was read as logback-core (on the
# coordinate allowlist) and skipped entirely, licences unchecked. The notices format always
# places the real coordinate last, so the last paren group is the one that is trusted, and
# its content is validated against the g:a:v shape (version now allowing `+`, in addition to
# `.` and `-`, since Maven versions legally contain it) before being trusted as a coordinate.
#
# F2: [^()]* cannot span a nested pair, so a dependency's own project <url> - free text on the
# same line, inside the coordinate group - could contain a balanced "(...)" and make the
# scanner return that INNER group as the "last" one, dropping the real (outer) coordinate.
# Scanning is now depth-aware: it walks the line character by character, tracking paren
# depth, and collects only DEPTH-1 ("top-level") groups - a group whose own parens are never
# nested inside another paren the rest of the line owns. The last top-level group is the one
# trusted as the coordinate, exactly as before, but a nested pair inside it (a URL's own
# "(bar)") is now part of that group's content instead of splitting it into two. The line is
# additionally required to END with the closing ")" of that last top-level group; anything
# trailing it is not a valid notices line and falls to UNPARSEABLE (fail closed, as today). A
# legitimate URL with a balanced pair, e.g. ".../wiki/Foo_(bar)", now parses cleanly instead
# of tripping UNPARSEABLE and the count check as it did under the old flat scan.
#
# A line that starts like a dependency line (a leading run of "(...)" groups) but whose last
# top-level paren group does not parse as a coordinate is NOT skipped - it is printed as
# UNPARSEABLE, and the caller fails the build on it (fail closed, per N3: "a line with no
# parsable coordinate fails closed").
# ---------------------------------------------------------------------------------------
parse_notices() {
  perl -ne '
    if (/^\s*((?:\([^()]*\)\s*)+)(\S.*)$/) {
      my ($lic_run, $rest) = ($1, $2);

      # Depth-aware top-level group scan: walk char by char, tracking paren depth. A
      # top-level group opens at depth 0->1 and closes at depth 1->0; everything between,
      # including any nested "(...)" inside it, is its content verbatim.
      my @parens;
      my $depth = 0;
      my $cur = "";
      my $ends_at_close = 0;
      for my $ch (split //, $rest) {
        if ($ch eq "(") {
          $cur .= $ch if $depth > 0;
          $depth++;
        } elsif ($ch eq ")") {
          $depth--;
          if ($depth == 0) {
            push @parens, $cur;
            $cur = "";
            $ends_at_close = 1;
          } else {
            $cur .= $ch;
            $ends_at_close = 0;
          }
        } else {
          $cur .= $ch if $depth > 0;
          $ends_at_close = 0 if $depth == 0 && $ch !~ /\s/;
        }
      }
      # The line must end with the closing paren of its last top-level group (only
      # trailing whitespace after it) and must not be left mid-group (depth != 0).
      my $trailing_ok = ($depth == 0 && $ends_at_close);

      # G1: F2 closed the case where a URL nested parens split the coordinate group; the
      # depth-aware scan above fixed that. But trusting "the last top-level group" by
      # POSITION alone is still forgeable FORWARD: a dependency own url is free text
      # that can simply close its own group early and open a fresh, allowlisted one after
      # it - e.g. url = http://x) (ch.qos.logback:logback-core:1.5.6 - http://y
      # renders as two top-level groups, the last of which is a real, allowlisted
      # coordinate, so the actual (denied) coordinate before it is never checked. The
      # coordinate cannot be recovered by position when the line is attacker-shaped, so
      # stop trying: count how many top-level groups are coordinate-shaped and require
      # EXACTLY ONE. Zero means no coordinate at all; two or more is genuine ambiguity
      # (which one is real) - both fall to UNPARSEABLE, fail closed, same as an
      # unparseable line always has.
      my $coord_re = qr/^\s*([\w.\-]+):([\w.\-]+):([\w.+\-]+)\s*-\s*.*$/;
      my @coord_like = grep { $_ =~ $coord_re } @parens;

      if (@parens && $trailing_ok && @coord_like == 1) {
        my $last = $coord_like[0];
        if ($last =~ $coord_re) {
          my ($g, $a, $v) = ($1, $2, $3);
          my @tokens;
          while ($lic_run =~ /\(([^()]*)\)/g) { push @tokens, $1; }
          print "OK\t$g:$a:$v\t" . join("|", @tokens) . "\n";
          next;
        }
      }
      print "UNPARSEABLE\t$rest\n";
    }
  '
}

# Runs the full gate against one notices file. Prints denial / parse-failure diagnostics on
# stderr, prefixed with the file. Returns non-zero on any denial or parse failure.
check_notices_file() {
  local notices="$1" status=0 expected_count="" parsed_count=0

  expected_count="$(grep -oE 'Lists of [0-9]+ third-party dependenc(y|ies)' "$notices" \
    | grep -oE '[0-9]+' | head -1 || true)"

  while IFS=$'\t' read -r kind a b; do
    if [ "$kind" = "UNPARSEABLE" ]; then
      echo "check-third-party-licences: DENIED unparseable dependency line in $notices: $a" >&2
      status=1
      continue
    fi
    parsed_count=$((parsed_count + 1))
    coord="$a"; tokens="$b"
    ga="${coord%:*}"
    if is_allowed_coordinate "$ga"; then
      continue
    fi
    # N10: an empty "()" token must not crash the scan under `set -u`. `IFS='|' read -ra`
    # on an empty string leaves the array unset in some bash versions rather than empty,
    # so both the split and every later expansion of it are defensive.
    tok_list=()
    IFS='|' read -ra tok_list <<<"$tokens" || true
    for tok in "${tok_list[@]:-}"; do
      [ -n "$tok" ] || continue
      if is_denied_token "$tok"; then
        echo "check-third-party-licences: DENIED licence '$tok' on $coord (from $notices)" >&2
        status=1
      fi
    done
  done < <(parse_notices <"$notices")

  if [ -n "$expected_count" ] && [ "$parsed_count" -ne "$expected_count" ]; then
    echo "check-third-party-licences: DENIED $notices declares $expected_count dependencies but only $parsed_count parsed cleanly" >&2
    status=1
  fi

  return "$status"
}

# ---------------------------------------------------------------------------------------
# --self-test: a table test covering every phrasing from N2's repro table, run against the
# in-process is_denied_token function directly (no Maven, no notices file). Every "should
# deny" row must return denied; every "should allow" row must return not-denied.
# ---------------------------------------------------------------------------------------
run_self_test() {
  local failures=0

  # tokens that must be DENIED (the N2 repro table, plus the original SPDX spellings).
  local -a deny_cases=(
    "GPL-3.0"
    "GPLv3"
    "GNU General Public License v3"
    "GNU General Public License, version 3"
    "GNU Lesser General Public License, version 2.1"
    "GNU Affero General Public License v3"
    "Mozilla Public License, Version 2.0"
    "MPL 2.0"
    "Common Development and Distribution License (CDDL) v1.0"
    "CDDL-1.0"
    "Server Side Public License, v 1"
    "SSPL-1.0"
    "European Union Public Licence 1.2"
    "EUPL-1.2"
    "Business Source License 1.1"
    "BUSL-1.1"
    "Creative Commons Attribution-NonCommercial 4.0"
    "CC-BY-NC-4.0"
    "GPL-3.0-with-classpath-exception"
    "GPL2 w/ CPE"
    # F5: version-pinned patterns missing the neighbouring version, and licences that were
    # absent from the table entirely.
    "EUPL v1.1"
    "EUPL-1.1"
    "SSPL"
    "SSPL-2.0"
    "OSL-3.0"
    "Open Software License"
    "CPAL"
    "Common Public Attribution License"
  )
  # tokens that must be ALLOWED (permissive licences this project actually ships under).
  local -a allow_cases=(
    "Apache-2.0"
    "Apache License 2.0"
    "MIT"
    "BSD-3-Clause"
    "EPL-2.0"
    "Public Domain"
    ""
    # F4: the bare "mpl" pattern used to deny these on a false-positive substring hit.
    "Simplified BSD License"
    "BSD 2-Clause Simplified License"
    "https://example.com/licence.txt"
    "The Apache Software License (example)"
  )

  local c
  for c in "${deny_cases[@]}"; do
    if is_denied_token "$c"; then
      echo "self-test OK    deny  '$c'"
    else
      echo "self-test FAIL  deny  '$c' was NOT denied"
      failures=$((failures + 1))
    fi
  done
  for c in "${allow_cases[@]}"; do
    if is_denied_token "$c"; then
      echo "self-test FAIL  allow '$c' was denied"
      failures=$((failures + 1))
    else
      echo "self-test OK    allow '$c'"
    fi
  done

  # F2: parser-level cases, run through the real check_notices_file / parse_notices path
  # against a synthetic notices file - is_denied_token alone cannot exercise the paren-depth
  # scan. Case 1 is the URL-forgery repro: a dependency's own <url> contains a balanced
  # "(...)" that must NOT be read as the coordinate. Case 2 is the false-positive this fix
  # also removes: a legitimate URL with a balanced pair (Wikipedia-style) must parse cleanly
  # instead of tripping UNPARSEABLE.
  local work
  work="$(mktemp -d)"

  printf 'Lists of 1 third-party dependencies.\n     (Apache-2.0) (GPL-3.0) evil-url (example.synth:evil-b:1.0 - http://x/(ch.qos.logback:logback-core:1.5.6 - y))\n' \
    > "$work/THIRD-PARTY-NOTICES.txt"
  if check_notices_file "$work/THIRD-PARTY-NOTICES.txt" >/dev/null 2>&1; then
    echo "self-test FAIL  parse 'evil-url' forged coordinate via a parenthesised <url> was NOT denied"
    failures=$((failures + 1))
  else
    echo "self-test OK    parse 'evil-url' forged coordinate via a parenthesised <url> is denied"
  fi

  printf 'Lists of 1 third-party dependencies.\n     (Apache-2.0) Foo (com.example:foo:1.0 - https://en.wikipedia.org/wiki/Foo_(bar))\n' \
    > "$work/THIRD-PARTY-NOTICES.txt"
  if check_notices_file "$work/THIRD-PARTY-NOTICES.txt" >/dev/null 2>&1; then
    echo "self-test OK    parse legitimate URL with balanced parens parses cleanly"
  else
    echo "self-test FAIL  parse legitimate URL with balanced parens was rejected"
    failures=$((failures + 1))
  fi

  # G1: the forward-forgery repro - a dependency's own <url> closes its coordinate
  # group early and opens a fresh, allowlisted one after it. The line now has TWO
  # coordinate-shaped top-level groups (the real example.synth:evil-c:1.0 and the trailing
  # forged ch.qos.logback:logback-core:1.5.6), which is genuine ambiguity - must fall to
  # UNPARSEABLE (fail closed), never be silently read as the allowlisted one.
  printf 'Lists of 1 third-party dependencies.\n     (GPL-3.0) evil-trailing (example.synth:evil-c:1.0 - http://x) (ch.qos.logback:logback-core:1.5.6 - http://y)\n' \
    > "$work/THIRD-PARTY-NOTICES.txt"
  if check_notices_file "$work/THIRD-PARTY-NOTICES.txt" >/dev/null 2>&1; then
    echo "self-test FAIL  parse coordinate forged by a trailing allowlisted group was NOT denied"
    failures=$((failures + 1))
  else
    echo "self-test OK    parse coordinate forged by a trailing allowlisted group is denied"
  fi

  # G1 regression guard: a legitimate parenthesised project name ("Apache Commons (Core)")
  # must still parse cleanly - the name's own paren is a top-level group but is not
  # coordinate-shaped, so it does not count toward the "exactly one" requirement.
  printf 'Lists of 1 third-party dependencies.\n     (Apache-2.0) Apache Commons (Core) (org.apache.commons:commons-lang3:3.12.0 - https://commons.apache.org/)\n' \
    > "$work/THIRD-PARTY-NOTICES.txt"
  if check_notices_file "$work/THIRD-PARTY-NOTICES.txt" >/dev/null 2>&1; then
    echo "self-test OK    parse legitimate parenthesised project name parses cleanly"
  else
    echo "self-test FAIL  parse legitimate parenthesised project name was rejected"
    failures=$((failures + 1))
  fi

  rm -rf "$work"

  echo
  if [ "$failures" -eq 0 ]; then
    echo "check-third-party-licences --self-test: all cases correct"
    return 0
  else
    echo "check-third-party-licences --self-test: $failures case(s) FAILED" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------------------
# --check-unused: fails if any ALLOWED_COORDINATES entry was not actually needed by this
# tree. A carve-out is "needed" when the coordinate appears in some module's generated
# THIRD-PARTY-NOTICES.txt AND at least one of its declared licence tokens is on the deny
# list - i.e. the entry is the only reason that dependency passed. An entry that is absent
# from the tree, or present but permissive, is dead weight that would silently pre-approve a
# future dependency reusing the same coordinate.
#
# Run from CI after a FULL build, when every module has produced its notices file; per-module
# the question cannot be answered, because an entry needed by the starter is legitimately
# absent from the core. Fails closed when no notices file exists at all (that means the build
# did not run, not that every entry is dead).
# ---------------------------------------------------------------------------------------
check_unused_allowlist_entries() {
  local files needed status=0 c
  files="$(find . -path '*/target/THIRD-PARTY-NOTICES.txt' -not -path './.git/*' | sort)"
  if [ -z "$files" ]; then
    echo "check-third-party-licences --check-unused: no THIRD-PARTY-NOTICES.txt anywhere under $(pwd); run a full build first" >&2
    return 1
  fi
  needed="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f '$needed'" RETURN
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    echo "check-third-party-licences --check-unused: reading $f"
    while IFS=$'\t' read -r kind a b; do
      [ "$kind" = "OK" ] || continue
      local coord="$a" tokens="$b" ga tok
      ga="${coord%:*}"
      tok_list=()
      IFS='|' read -ra tok_list <<<"$tokens" || true
      for tok in "${tok_list[@]:-}"; do
        [ -n "$tok" ] || continue
        if is_denied_token "$tok"; then
          echo "$ga" >> "$needed"
          break
        fi
      done
    done < <(parse_notices <"$f")
  done <<<"$files"

  for c in "${ALLOWED_COORDINATES[@]:-}"; do
    [ -n "$c" ] || continue
    if grep -qxF "$c" "$needed"; then
      echo "check-third-party-licences --check-unused: $c is needed (carves out a denied licence declared in this tree)"
    else
      echo "check-third-party-licences --check-unused: DEAD carve-out '$c' - not needed by any module in this tree, remove it from ALLOWED_COORDINATES" >&2
      status=1
    fi
  done

  if [ "$status" -eq 0 ]; then
    echo "check-third-party-licences --check-unused: every carve-out is needed"
  fi
  return "$status"
}

if [ "${1:-}" = "--check-unused" ]; then
  check_unused_allowlist_entries
  exit $?
fi

if [ "${1:-}" = "--self-test" ]; then
  run_self_test
  exit $?
fi

build_dir="${1:-}"
packaging="${2:-}"

if [ -z "$build_dir" ] || [ -z "$packaging" ]; then
  echo "usage: check-third-party-licences.sh <module-build-dir> <module-packaging>" >&2
  echo "       check-third-party-licences.sh --self-test" >&2
  echo "       check-third-party-licences.sh --check-unused" >&2
  exit 1
fi

notices="$build_dir/THIRD-PARTY-NOTICES.txt"

if [ ! -f "$notices" ]; then
  if [ "$packaging" = "pom" ]; then
    echo "check-third-party-licences: $packaging module, no THIRD-PARTY-NOTICES.txt (declares no shipped dependencies of its own)"
    exit 0
  fi
  echo "check-third-party-licences: no THIRD-PARTY-NOTICES.txt found at $notices (did third-party-notices run first?)" >&2
  exit 1
fi

if check_notices_file "$notices"; then
  echo "check-third-party-licences: clean ($notices)"
  exit 0
else
  echo "check-third-party-licences: FAILED, see DENIED lines above" >&2
  exit 1
fi
