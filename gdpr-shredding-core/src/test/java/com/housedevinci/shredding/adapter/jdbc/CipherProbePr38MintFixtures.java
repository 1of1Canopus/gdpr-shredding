package com.housedevinci.shredding.adapter.jdbc;

import javax.sql.DataSource;

/**
 * Security review, PR 38 pass 1: fixtures for {@code CipherProbePr38Test}. Test tree only. They are
 * imported by ArchUnit and never run.
 */
public final class CipherProbePr38MintFixtures {

  private CipherProbePr38MintFixtures() {}

  /** A second minting point by direct call. */
  public static final class ByCall {
    private ByCall() {}

    static VerifiedSchema mint(String name, DataSource ds, DatabaseIdentity identity) {
      return new VerifiedSchema(name, ds, identity);
    }
  }

  /** A second minting point by constructor reference. */
  public static final class ByReference {
    private ByReference() {}

    /** The constructor gained the database identity in C-PR-1b; the reference is the same. */
    interface Mint {
      VerifiedSchema mint(String name, DataSource ds, DatabaseIdentity identity);
    }

    static final Mint MINT = VerifiedSchema::new;
  }
}
