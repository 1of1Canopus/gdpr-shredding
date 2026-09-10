package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;
import java.util.TreeSet;

/**
 * PostgreSQL's fully reserved key words (design addendum 4, revision correction E-2): the words
 * that cannot appear as a bare {@code ColId}, which is exactly the grammar position an unqualified
 * column reference occupies in this module's {@code WHERE} and {@code SET}. An unquoted column
 * mapped to one of these can be written by no application - Hibernate's own {@code INSERT} is a
 * syntax error against it - but if the physical column already exists (a legacy table, written by
 * something other than this application), the round trip in {@link ColumnRefs} still holds and
 * startup would otherwise accept the mapping. This module's own SQL is not alias-qualified the way
 * Hibernate's is, so the bare word would then be parsed as the keyword - {@code user} as {@code
 * CURRENT_USER} - and match nothing, for ever.
 *
 * <p><b>Not {@code Dialect.getKeywords()}.</b> That list carries every key word Hibernate knows
 * about for this dialect, reserved and non-reserved together; refusing on it would refuse a column
 * named {@code value} or {@code name}, which is not reserved and works unquoted today. The list
 * here is PostgreSQL's own two reserved categories only - {@code pg_get_keywords()} catcode {@code
 * R} ("reserved") and catcode {@code T} ("reserved, can be function or type name") - vendored from
 * a running PostgreSQL 16.14, the version this module's tests pin. See the resource file for the
 * generating query and a checksum, verified below at class-init so a corrupted or hand-edited list
 * fails loudly rather than under-refusing silently.
 */
final class PostgreSqlReservedKeywords {

  private static final String RESOURCE = "postgresql-16-reserved-keywords.txt";

  static final String EXPECTED_SHA256 =
      "3a9027604ec759856e3f9fdbaadaccc4588c00b213328ab5ca0018231448e0d6";

  private static final Set<String> WORDS = load();

  private PostgreSqlReservedKeywords() {}

  /**
   * Case-insensitive: an unquoted identifier is folded to lower case by PostgreSQL regardless of
   * how it was typed in the mapping.
   */
  static boolean isReserved(String unquotedText) {
    return WORDS.contains(unquotedText.toLowerCase(java.util.Locale.ROOT));
  }

  private static Set<String> load() {
    var words = new TreeSet<String>();
    try (InputStream in = PostgreSqlReservedKeywords.class.getResourceAsStream(RESOURCE)) {
      if (in == null) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "the vendored PostgreSQL reserved key word list "
                + RESOURCE
                + " is missing from the"
                + " classpath; this module cannot tell an unquoted reserved-word column mapping"
                + " from an ordinary one without it");
      }
      try (var reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
        String line;
        while ((line = reader.readLine()) != null) {
          String trimmed = line.strip();
          if (trimmed.isEmpty() || trimmed.startsWith("#")) {
            continue;
          }
          words.add(trimmed);
        }
      }
    } catch (IOException e) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "could not read the vendored PostgreSQL reserved key word list " + RESOURCE,
          e);
    }
    String actual = sha256(words);
    if (!EXPECTED_SHA256.equals(actual)) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "the vendored PostgreSQL reserved key word list "
              + RESOURCE
              + " does not match its recorded checksum (expected "
              + EXPECTED_SHA256
              + ", got "
              + actual
              + "). A tampered or hand-edited list would silently under- or over-refuse reserved"
              + " column mappings, so it is refused rather than trusted.");
    }
    return Set.copyOf(words);
  }

  private static String sha256(Set<String> sortedWords) {
    var joined = new StringBuilder();
    for (String word : sortedWords) {
      joined.append(word).append('\n');
    }
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(joined.toString().getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is a JDK-mandated algorithm", e);
    }
  }
}
