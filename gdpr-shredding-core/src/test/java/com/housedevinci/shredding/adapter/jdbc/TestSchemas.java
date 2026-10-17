package com.housedevinci.shredding.adapter.jdbc;

import java.sql.SQLException;
import javax.sql.DataSource;

/**
 * Test seam for C-PR-1, test tree only. Several tests check a control that sits after verification
 * (mapping admission, the isolation window, statement qualification on a hostile path, an aborted
 * pin). They verify on a clean pool and then hand the store a different pool on purpose: a
 * fault-injecting wrapper, or a fresh pool whose session settings an attacker changed. Since 0.2.1
 * the store takes its pool from the schema, so these tests rebind the capability to that pool here,
 * explicitly, instead of pairing them silently as they did on 0.2.0.
 *
 * <p>The module's own {@code main} cannot do this. {@link VerifiedSchema}'s only constructor is
 * package-private, the ArchUnit rule {@code only_SchemaVerification_constructs_VerifiedSchema}
 * refuses any other caller in the core and the starter, and there is no such helper in {@code
 * main}. Application code can do it only by placing a class in this package. The core jar seals the
 * package, so on a plain classpath the JVM refuses that class ({@code sealing violation}). Spring
 * Boot's executable-jar launcher does not enforce sealing; there it is deliberate application code,
 * like a {@code KeyProvider} of your own.
 */
final class TestSchemas {

  private TestSchemas() {}

  /**
   * The verified schema's name and database identity, bound to {@code dataSource} as if it had been
   * verified there. Since C-PR-1b every store connection is compared with that identity, so a pool
   * rebound here must still reach the verified database as the verified roles, or its calls refuse
   * with {@code SHRED-SCHEMA-012} before the control the test is about.
   */
  static VerifiedSchema reboundTo(VerifiedSchema verified, DataSource dataSource) {
    return new VerifiedSchema(verified.name(), dataSource, verified.identity());
  }

  /**
   * As {@link #reboundTo}, for a test whose pool logs in as another role on purpose (a member of
   * the verified role with its own session defaults, say): the database identity is read again
   * through {@code dataSource}, so the C-PR-1b check sees what that pool reaches and the test
   * reaches the control it is about.
   */
  static VerifiedSchema reboundAs(VerifiedSchema verified, DataSource dataSource) {
    try (var c = dataSource.getConnection()) {
      DatabaseIdentity identity =
          DatabaseIdentity.read(c, verified.name(), false).identity().orElseThrow();
      return new VerifiedSchema(verified.name(), dataSource, identity);
    } catch (SQLException e) {
      throw new IllegalStateException("could not read the database identity", e);
    }
  }
}
