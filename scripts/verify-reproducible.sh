#!/usr/bin/env bash
#
# Proves the build is reproducible: the same source tree, built twice, produces
# byte-identical jars for the two published artifacts.
#
#   scripts/verify-reproducible.sh
#
# How it works. Both builds are run with -Dproject.build.outputTimestamp set to the
# committer date of HEAD, so every zip entry carries that instant instead of "now".
# The jars from the first build are copied aside, the tree is rebuilt from clean, and
# the SHA-256 of each jar is compared.
#
# The two builds are invoked differently ON PURPOSE. Build 1 skips tests: it is the fast
# baseline whose checksums get written to disk and later compared against what actually
# got deployed. Build 2 runs the tests, because `clean deploy -Prelease` (the invocation
# that publishes) runs the tests too, and a surefire report or any other test-only byte
# landing in a jar is exactly the defect this script exists to catch (see run 34419387032:
# a `-DskipTests` vs `-DskipTests`
# comparison agreed the sources jars were reproducible while the real, tests-running release
# build produced a sources jar with surefire-reports/ baked in). A flaky test now fails this
# script before anything is deployed, which is where this pipeline wants that failure.
#
# Checked (must match):
#   gdpr-shredding-core-<v>.jar
#   gdpr-shredding-core-<v>-sources.jar
#   gdpr-shredding-spring-boot-starter-<v>.jar
#   gdpr-shredding-spring-boot-starter-<v>-sources.jar
#   gdpr-shredding-core-<v>.pom
#   gdpr-shredding-spring-boot-starter-<v>.pom
#   gdpr-shredding-parent-<v>.pom
#
# Poms are checked for the same reason the jars are: Central consumes the pom bytes too,
# and the window between this proved build and the upload applies to them identically
# (RP-5). Signatures are correctly left out - they are not reproducible.
#
# The parent pom (RP-6) is recorded too: the bundle carries exactly three published
# coordinates - parent, core, starter - and a record covering only two of them leaves the
# third an unrecorded bundle entry on every release, which is what broke the comparison
# step (see release.yml's own fix, same finding).
#
# Reported but NOT enforced: the javadoc jars. javadoc embeds the JDK build string and,
# in some JDK versions, generation-time detail that -notimestamp does not remove. Maven
# Central requires a javadoc jar; nobody diffs one.
#
# Also writes a checksum file, "<sha256>  <filename>" per jar from build 1 (the two
# builds already matched by the time this is written, or the script has already exited
# non-zero). This is what L1 compares the actually-deployed jars against after
# `clean deploy`, so a reproducible tree is not just proved in the abstract, it is proved
# to be what got published. Written OUTSIDE target/ by default (target/*.jar is what
# `mvn clean deploy` deletes and rebuilds next, a third time, right after this script
# runs) - override with REPRODUCIBLE_SHA_FILE to put it somewhere that survives that
# clean, e.g. $RUNNER_TEMP in CI.
#
set -euo pipefail
cd "$(dirname "$0")/.."
SHA_FILE="${REPRODUCIBLE_SHA_FILE:-reproducible-sha256.txt}"

TS="$(scripts/git-commit-timestamp.sh)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MVN_ARGS_BASE=(-B -q -Dproject.build.outputTimestamp="$TS" -Prelease -Dgpg.skip=true)
MVN_ARGS_BUILD1=("${MVN_ARGS_BASE[@]}" -DskipTests)
MVN_ARGS_BUILD2=("${MVN_ARGS_BASE[@]}")

echo "reproducibility check"
echo "  timestamp: $TS"
echo "  scratch:   $WORK"

collect() { # collect <dir>
  local dest="$1"
  mkdir -p "$dest"
  local module jar name
  for module in gdpr-shredding-core gdpr-shredding-spring-boot-starter; do
    for jar in "$module"/target/*.jar; do
      [ -e "$jar" ] || continue
      cp "$jar" "$dest/"
    done
    # `mvn package` never writes a pom into target/ - the pom Central receives is a bundle
    # entry central-publishing-maven-plugin assembles only at `deploy`, from this module's
    # own pom.xml verbatim (RP-5). Name it to match the bundle's convention
    # (artifactId-version.pom, same as the main jar's basename) by borrowing the main jar's
    # name, never the sources/javadoc jar's.
    name=""
    for jar in "$module"/target/*.jar; do
      [ -e "$jar" ] || continue
      case "$jar" in
        *-sources.jar|*-javadoc.jar) continue ;;
      esac
      name="$(basename "$jar")"
      break
    done
    if [ -n "$name" ] && [ -e "$module/pom.xml" ]; then
      cp "$module/pom.xml" "$dest/${name%.jar}.pom"
    fi
  done
  # The reactor root, gdpr-shredding-parent (packaging pom, no jar of its own to borrow a
  # name from): the bundle listing assertion elsewhere in the pipeline already refuses a
  # release whose bundle lacks com/housedevinci/gdpr-shredding-parent/, so this record must
  # exist for every release the comparison step ever sees (RP-6). Version read from the
  # root pom.xml itself, the same <artifactId>/<version> pair pattern every module's own
  # <parent> block already carries.
  local parent_version
  parent_version="$(awk '
    /<artifactId>gdpr-shredding-parent<\/artifactId>/ { getline; print; exit }
  ' pom.xml | sed -E 's/.*<version>(.*)<\/version>.*/\1/')"
  if [ -n "$parent_version" ] && [ -e pom.xml ]; then
    cp pom.xml "$dest/gdpr-shredding-parent-${parent_version}.pom"
  fi
}

echo "  build 1 (fast baseline, tests skipped) ..."
./mvnw "${MVN_ARGS_BUILD1[@]}" clean package
collect "$WORK/one"

echo "  build 2 (tests run, mirrors clean deploy -Prelease) ..."
./mvnw "${MVN_ARGS_BUILD2[@]}" clean package
collect "$WORK/two"

status=0
mkdir -p "$(dirname "$SHA_FILE")"
sha_file="$SHA_FILE"
: > "$sha_file"
printf '\n%-56s %-8s %s\n' "artifact" "verdict" "sha256 (build 1)"
for f in "$WORK/one"/*.jar "$WORK/one"/*.pom; do
  [ -e "$f" ] || continue
  name="$(basename "$f")"
  other="$WORK/two/$name"
  if [ ! -e "$other" ]; then
    printf '%-56s %-8s %s\n' "$name" "MISSING" "-"
    status=1
    continue
  fi
  a="$(shasum -a 256 "$f" | cut -d' ' -f1)"
  b="$(shasum -a 256 "$other" | cut -d' ' -f1)"
  if [ "$a" = "$b" ]; then
    printf '%-56s %-8s %s\n' "$name" "same" "$a"
    printf '%s  %s\n' "$a" "$name" >> "$sha_file"
  else
    case "$name" in
      *-javadoc.jar)
        printf '%-56s %-8s %s\n' "$name" "differs" "$a  (not enforced: the javadoc jar is not diffed)"
        # Recorded anyway, not-enforced marker and all: L1's post-deploy comparison needs
        # a line to look up, and it applies the same not-enforced rule for *-javadoc.jar.
        printf '%s  %s  # not enforced: the javadoc jar is not diffed\n' "$a" "$name" >> "$sha_file"
        ;;
      *)
        printf '%-56s %-8s %s\n' "$name" "DIFFERS" "$a vs $b"
        status=1
        ;;
    esac
  fi
done

echo
if [ "$status" -eq 0 ]; then
  echo "reproducible: every enforced artifact is byte-identical across two clean builds"
  echo "  wrote: $sha_file"
else
  echo "NOT reproducible: see DIFFERS above" >&2
fi
exit "$status"
