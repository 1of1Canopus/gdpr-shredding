package com.housedevinci.shredding.domain;

import java.util.Optional;

/**
 * The erasure trail's head as the store last wrote it, in a separate row from the trail itself, so
 * trimming the tail or truncating the table leaves a mismatch the verifier reports (control 8,
 * module B verbatim).
 */
public interface ErasureAnchor {

  /**
   * @param headHash hash of the newest row
   * @param rowCount number of rows in the trail
   * @param keyed whether this trail is keyed from row 1 or unkeyed forever; set once, at the first
   *     append, and immutable afterwards (the anchor's trigger refuses a change). It is the
   *     external, attacker-unwritable signal the verifier checks every row's {@code chain_version}
   *     against, because that column is itself part of what a table-owning attacker rewrites.
   */
  record Anchor(String headHash, long rowCount, boolean keyed) {}

  Optional<Anchor> anchor();
}
