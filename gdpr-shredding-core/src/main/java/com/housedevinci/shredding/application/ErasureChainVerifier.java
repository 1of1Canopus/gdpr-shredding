package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.ErasureAnchor;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ShreddingException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Walks the erasure trail in sequence order, recomputes every hash and compares the head with the
 * anchor. Module B's verifier, adapted (control 8).
 *
 * <p>Holds a keyring ({@code keyId -> secret}), because the key id is inside the hashed material
 * from row 1, so a rotation window has rows signed by different ids in the same, still-keyed trail.
 * An id the keyring does not hold is {@code BROKEN}, never skipped.
 */
public final class ErasureChainVerifier {

  private static final int PAGE = 500;
  private static final Logger log = LoggerFactory.getLogger(ErasureChainVerifier.class);

  private final ErasureReader reader;
  private final ErasureAnchor anchor;
  private final Map<String, ErasureChain> keyring;

  public ErasureChainVerifier(
      ErasureReader reader, ErasureAnchor anchor, Map<String, byte[]> keyring) {
    this.reader = Objects.requireNonNull(reader, "reader");
    this.anchor = Objects.requireNonNull(anchor, "anchor");
    Objects.requireNonNull(keyring, "keyring");
    var chains = new LinkedHashMap<String, ErasureChain>();
    keyring.forEach((id, secret) -> chains.put(id, ErasureChain.keyed(secret, id)));
    this.keyring = Map.copyOf(chains);
  }

  public enum Status {
    /** No rows and no anchor. */
    EMPTY,
    /** Every hash recomputes, the head matches the anchor, and the trail is keyed. */
    INTACT,
    /**
     * Every hash recomputes and the head matches, but the trail is unkeyed: its integrity rests
     * only on database privilege separation, not on a secret. Deliberately a different word from
     * {@link #INTACT}, so a clean unkeyed result never reads like a clean keyed one.
     */
    INTACT_UNKEYED,
    /** A row does not recompute, claims the wrong chain version, or claims an unknown key id. */
    BROKEN,
    /** The rows recompute but the head hash or the row count differs from the anchor. */
    ANCHOR_MISMATCH,
    /**
     * There is no anchor row and the trail is not empty. Reported unconditionally, keyed or not:
     * without the anchor there is no attacker-unwritable record of what the rows ought to claim,
     * and the verifier refuses to guess.
     */
    NO_ANCHOR
  }

  /**
   * @param status outcome
   * @param verified rows that recomputed
   * @param brokenAtSequence sequence of the first failing row, or -1
   * @param headHash hash of the newest verified row, or GENESIS
   * @param anchored whether an anchor row was available
   * @param keyed the trail's recorded mode, or false when not anchored
   * @param keyIds every distinct key id seen on a row that recomputed
   */
  public record Report(
      Status status,
      long verified,
      long brokenAtSequence,
      String headHash,
      boolean anchored,
      boolean keyed,
      Set<String> keyIds) {

    public boolean intact() {
      return status == Status.INTACT || status == Status.INTACT_UNKEYED || status == Status.EMPTY;
    }
  }

  public Report verify() {
    Optional<ErasureAnchor.Anchor> anchored = anchor.anchor();
    if (anchored.isEmpty()) {
      List<ErasureRecord> probe = reader.readAfter(0, 1);
      if (probe.isEmpty()) {
        return new Report(Status.EMPTY, 0, -1, ErasureChain.GENESIS, false, false, Set.of());
      }
      log.warn(
          "shredding: verifying a non-empty erasure trail with no anchor row; refusing to report"
              + " INTACT. Reporting NO_ANCHOR.");
      return new Report(Status.NO_ANCHOR, 0, -1, ErasureChain.GENESIS, false, false, Set.of());
    }
    boolean expectKeyed = anchored.get().keyed();
    String expectedVersion =
        expectKeyed ? ErasureChain.KEYED_VERSION : ErasureChain.CANONICAL_VERSION;

    String prev = ErasureChain.GENESIS;
    long after = 0;
    long count = 0;
    var keyIdsSeen = new LinkedHashSet<String>();
    while (true) {
      List<ErasureRecord> page;
      try {
        page = reader.readAfter(after, PAGE);
      } catch (ShreddingException e) {
        // L10: a row that cannot even be decoded - a malformed hook_outcomes column, most likely -
        // is written by exactly the attacker this trail exists to detect. The read path reports
        // BROKEN rather than letting a typed decode error escape as an unhandled exception, which
        // would make the verifier itself fail instead of reporting the tamper it found.
        log.warn(
            "shredding: erasure trail did not decode while verifying after seq={}: {}",
            after,
            e.getMessage());
        return new Report(Status.BROKEN, count, after, prev, true, expectKeyed, keyIdsSeen);
      }
      if (page.isEmpty()) {
        break;
      }
      for (ErasureRecord r : page) {
        ErasureChain rowChain = chainForRow(expectKeyed, r.keyId());
        if (!expectedVersion.equals(r.chainVersion())
            || rowChain == null
            || !rowChain.verify(r, prev)) {
          return new Report(
              Status.BROKEN, count, r.sequence(), prev, true, expectKeyed, keyIdsSeen);
        }
        keyIdsSeen.add(r.keyId());
        prev = r.hash();
        after = r.sequence();
        count++;
      }
    }
    if (anchored.get().rowCount() != count || !anchored.get().headHash().equals(prev)) {
      return new Report(Status.ANCHOR_MISMATCH, count, -1, prev, true, expectKeyed, keyIdsSeen);
    }
    if (count == 0) {
      return new Report(Status.EMPTY, 0, -1, prev, true, expectKeyed, keyIdsSeen);
    }
    return new Report(
        expectKeyed ? Status.INTACT : Status.INTACT_UNKEYED,
        count,
        -1,
        prev,
        true,
        expectKeyed,
        keyIdsSeen);
  }

  private ErasureChain chainForRow(boolean expectKeyed, String rowKeyId) {
    if (!expectKeyed) {
      return ErasureChain.UNKEYED_KEY_ID.equals(rowKeyId) ? ErasureChain.unkeyed() : null;
    }
    if (ErasureChain.UNKEYED_KEY_ID.equals(rowKeyId)) {
      return null;
    }
    return keyring.get(rowKeyId);
  }
}
