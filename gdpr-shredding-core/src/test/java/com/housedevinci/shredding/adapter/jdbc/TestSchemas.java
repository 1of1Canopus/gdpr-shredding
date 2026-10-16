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
 * <p>Production code cannot do this. {@link VerifiedSchema}'s only constructor is package-private,
 * the ArchUnit rule {@code only_SchemaVerification_constructs_VerifiedSchema} refuses any other
 * caller in {@code main}, and there is no such helper in {@code main}.
 */
final class TestSchemas {

  private TestSchemas() {}

  /** The verified schema's name, bound to {@code dataSource} as if it had been verified there. */
  static VerifiedSchema reboundTo(VerifiedSchema verified, DataSource dataSource) {
    return new VerifiedSchema(verified.name(), dataSource);
  }
}
