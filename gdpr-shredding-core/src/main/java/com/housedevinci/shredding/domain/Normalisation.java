package com.housedevinci.shredding.domain;

import java.math.BigDecimal;
import java.text.Normalizer;
import java.time.LocalDate;
import java.util.Locale;

/**
 * The one normalisation used by both the write path and the query path of the blind index (control
 * 10). Its version is part of the indexed material, so changing a rule produces a different index
 * rather than a silently wrong match.
 *
 * <p>NFKC, trim, casefold, then a per-type rule. Two values that a human would call equal must
 * normalise to the same string, or an equality lookup on an encrypted column misses rows.
 */
public final class Normalisation {

  /** Bumped whenever any rule below changes. Part of the indexed material. */
  public static final String VERSION = "n1";

  private Normalisation() {}

  public static String forText(String value) {
    String nfkc = Normalizer.normalize(value, Normalizer.Form.NFKC);
    return nfkc.strip().toLowerCase(Locale.ROOT);
  }

  /** ISO-8601, so 2026-01-02 and 2026-1-2 index alike. */
  public static String forDate(LocalDate value) {
    return value.toString();
  }

  /** Scale-insensitive: 1.50 and 1.5 are the same number and must index alike. */
  public static String forDecimal(BigDecimal value) {
    return value.stripTrailingZeros().toPlainString();
  }

  /** Bytes have no locale; hex keeps the index a text-shaped value like every other type. */
  public static String forBytes(byte[] value) {
    return java.util.HexFormat.of().formatHex(value);
  }
}
