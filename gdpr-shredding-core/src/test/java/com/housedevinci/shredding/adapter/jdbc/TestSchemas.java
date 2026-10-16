package com.housedevinci.shredding.adapter.jdbc;

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

  /** The verified schema's name, bound to {@code dataSource} as if it had been verified there. */
  static VerifiedSchema reboundTo(VerifiedSchema verified, DataSource dataSource) {
    return new VerifiedSchema(verified.name(), dataSource);
  }
}
