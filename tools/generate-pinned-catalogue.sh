#!/usr/bin/env bash
# Writes the pinned files of the function-grants check (C-PR45-3) for one PostgreSQL major:
#   pg-initdb-withheld-<major>.tsv, pg-extension-manifest-<major>.tsv, pg-extension-versions-<major>.tsv
# into gdpr-shredding-core/src/main/resources/com/housedevinci/shredding/adapter/jdbc/.
#
# The files are never typed by hand. The generator starts the pinned image of that major by digest
# (512 MB, two CPUs), installs every available extension version in a fresh database, and refuses
# to write anything on an unexpected install error, a half-installable extension, a chain install
# that differs from the direct one, a duplicate entry, or an R5 row on a pristine install. Run it
# at every pin bump; the byte-for-byte tests fail until the files match the new image.
#
# Usage: tools/generate-pinned-catalogue.sh 16|17     (Docker must be running)
set -euo pipefail

major="${1:-}"
case "$major" in
  16|17) ;;
  *) echo "usage: $0 16|17" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/gdpr-shredding-core/src/main/resources/com/housedevinci/shredding/adapter/jdbc"
work="$(mktemp -d)"
trap 'rm -f "$work/cp.txt"; rmdir "$work" 2>/dev/null || true' EXIT

cd "$root"
./mvnw -B -q -pl gdpr-shredding-core -am test-compile -Dspotless.check.skip=true
./mvnw -B -q -pl gdpr-shredding-core dependency:build-classpath \
  -Dmdep.includeScope=test -Dmdep.outputFile="$work/cp.txt"

java -cp "gdpr-shredding-core/target/test-classes:gdpr-shredding-core/target/classes:$(cat "$work/cp.txt")" \
  com.housedevinci.shredding.adapter.jdbc.PinnedCatalogueGenerator "$major" "$out"
