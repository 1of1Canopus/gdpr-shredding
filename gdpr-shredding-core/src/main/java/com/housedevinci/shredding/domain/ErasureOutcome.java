package com.housedevinci.shredding.domain;

/**
 * How an erasure ended (control 19).
 *
 * <p>There is no third value that means "probably fine". A proof-of-erasure refuses to render
 * "complete" while any hook is outstanding.
 */
public enum ErasureOutcome {
  /** The key rows are gone, the blind-index columns are null, and every hook succeeded. */
  COMPLETE,
  /**
   * The key rows are gone but at least one {@link
   * com.housedevinci.shredding.application.PostErasureHook} failed. Hooks run after the key
   * destruction commits, so they carry retry state; until every one of them succeeds this erasure
   * is not complete and must not be presented as such.
   */
  PARTIAL
}
