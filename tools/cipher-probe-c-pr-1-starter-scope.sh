#!/usr/bin/env bash
# Security review, PR 38 (C-PR-1) pass 1, 2026-10-16.
# probe_a_starter_class_in_a_core_package_mints_a_verified_schema_unseen
#
# The rule only_SchemaVerification_constructs_VerifiedSchema runs in core's test tree and imports
# core's classes only. A class the starter declares in package com.housedevinci.shredding.adapter.jdbc
# can call VerifiedSchema's package-private constructor, and no test of either module notices.
#
# Runs on a scratch copy of the tree (never edits the tree it is given): plants StarterMint in the
# starter's main, runs the core and starter test suites. RED when both suites stay green (the plant
# goes unseen). GREEN when a test fails because of the plant.
# Needs Docker up (the suites use Testcontainers). Exit 2 when the copy does not even compile.
# Usage: cipher-probe-c-pr-1-starter-scope.sh <module root>
set -uo pipefail
ROOT=${1:?module root}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
rsync -a --exclude target --exclude .git "$ROOT/" "$WORK/tree/"
D="$WORK/tree/gdpr-shredding-spring-boot-starter/src/main/java/com/housedevinci/shredding/adapter/jdbc"
mkdir -p "$D"
cat > "$D/StarterMint.java" <<'JAVA'
package com.housedevinci.shredding.adapter.jdbc;

/** Planted by the security review probe. */
public final class StarterMint {
  private StarterMint() {}

  public static VerifiedSchema mint(String n, javax.sql.DataSource d) {
    return new VerifiedSchema(n, d);
  }
}
JAVA
cd "$WORK/tree"
./mvnw -o -B -pl gdpr-shredding-core,gdpr-shredding-spring-boot-starter test -Djacoco.skip=true \
  -Dspotless.check.skip=true > "$WORK/build.log" 2>&1
rc=$?
grep -E "^\[(INFO|ERROR)\] Tests run: [0-9]+, Fail[^,]*, Errors: [0-9]+, Skipped: [0-9]+$" "$WORK/build.log"
if grep -q "COMPILATION ERROR" "$WORK/build.log"; then
  echo "UNVERIFIABLE: the planted copy did not compile"; exit 2
fi
if [ $rc -eq 0 ]; then
  echo "RED: a starter class in a core package minted a VerifiedSchema and every test stayed green"
  exit 1
fi
if grep -E "^\[ERROR\]   " "$WORK/build.log" | grep -q "StarterMint\|core package\|VerifiedSchema"; then
  echo "GREEN: a test refused the planted class"
  grep -E "^\[ERROR\]   " "$WORK/build.log" | head -3
  exit 0
fi
echo "UNVERIFIABLE: the build failed, but not on the planted class"
grep -E "^\[ERROR\]   " "$WORK/build.log" | head -5
exit 2
