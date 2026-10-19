#!/usr/bin/env bash
# Security review, PR 38 (C-PR-1) pass 1, 2026-10-16.
# probe_application_class_in_the_module_package_mints_a_verified_schema
#
# VerifiedSchema is a capability: one package-private constructor, and an architecture rule that
# only SchemaVerification calls it. Both hold for the module's own code only. An application jar
# that declares a class in package com.housedevinci.shredding.adapter.jdbc (a "split package") can
# call the constructor with no reflection, bind the gate's schema name to any DataSource, and build
# a JdbcKeyProvider on a database nobody verified. The module's public test tree shows how
# (TestSchemas.reboundTo). The core jar does not seal the package, so the JVM does not refuse it.
#
# RED while the forging class runs and prints MINTED. GREEN when the JVM refuses to load it
# (SecurityException: sealing violation) because the core jar's manifest seals the package.
#
# Usage: cipher-probe-c-pr-1-split-package.sh <module root, after ./mvnw package>
set -euo pipefail
ROOT=${1:?module root}
JAR=$(find "$ROOT/gdpr-shredding-core/target" -maxdepth 1 -name 'gdpr-shredding-core-*.jar' \
  ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name '*-tests.jar' | head -1)
[ -n "$JAR" ] || { echo "UNVERIFIABLE: no core jar under $ROOT/gdpr-shredding-core/target"; exit 2; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PKG=com/housedevinci/shredding/adapter/jdbc
mkdir -p "$WORK/src/$PKG" "$WORK/out"
cat > "$WORK/src/$PKG/Forge.java" <<'JAVA'
package com.housedevinci.shredding.adapter.jdbc;

import java.io.PrintWriter;
import java.sql.Connection;
import java.util.logging.Logger;
import javax.sql.DataSource;

/** Application code in the module's package. No reflection. */
public final class Forge {
  public static void main(String[] args) {
    DataSource unverified = new DataSource() {
      public Connection getConnection() { throw new UnsupportedOperationException(); }
      public Connection getConnection(String u, String p) { throw new UnsupportedOperationException(); }
      public PrintWriter getLogWriter() { return null; }
      public void setLogWriter(PrintWriter out) {}
      public void setLoginTimeout(int seconds) {}
      public int getLoginTimeout() { return 0; }
      public Logger getParentLogger() { return Logger.getGlobal(); }
      public <T> T unwrap(Class<T> iface) { throw new UnsupportedOperationException(); }
      public boolean isWrapperFor(Class<?> iface) { return false; }
    };
    // C-PR-1b: the one constructor also takes the database identity; forged as well.
    DatabaseIdentity identity = new DatabaseIdentity(0L, 0L, "app", 2200L, "app", "app", 0L, "app");
    VerifiedSchema forged = new VerifiedSchema("public", unverified, identity);
    System.out.println("MINTED " + forged.name() + " bound to "
        + (forged.dataSource() == unverified ? "the unverified DataSource" : "something else"));
  }
}
JAVA
javac -cp "$JAR" -d "$WORK/out" "$WORK/src/$PKG/Forge.java" \
  || { echo "UNVERIFIABLE: the planted class did not compile"; exit 2; }
set +e
OUT=$(java -cp "$JAR:$WORK/out" com.housedevinci.shredding.adapter.jdbc.Forge 2>&1)
set -e
echo "$OUT" | head -5
if echo "$OUT" | grep -q '^MINTED'; then
  echo "RED: application code in the module's package minted a VerifiedSchema on an unverified DataSource"
  exit 1
fi
if echo "$OUT" | grep -q 'sealing violation'; then
  echo "GREEN: the JVM refused the split package (core jar seals $PKG)"
  exit 0
fi
echo "UNVERIFIABLE: neither MINTED nor a sealing violation"
exit 2
