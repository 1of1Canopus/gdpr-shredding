package com.housedevinci.shredding.domain;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * One column, addressed exactly as Hibernate's mapping addresses it (design addendum 4, §4.1).
 *
 * <p><b>Why this type exists (S-22).</b> Every column identifier this module interpolated into SQL
 * used to be a {@code String} taken from an annotation's text or lowercased by a hand-written
 * {@code unquote} helper, and then either quoted by a hand-written {@code quote} helper or not
 * quoted at all, depending on which statement was building it. A column the mapping quotes -
 * {@code @Column(name = "\"Owner\"")}, or a reserved word like {@code "user"} - was therefore
 * addressed as a <em>different</em> column, or as a scalar expression that parses and matches
 * nothing. The erasure cleared no row, its own read-back was built from the same text and agreed
 * with it, and the record said {@code COMPLETE} with the HMAC of the erased plaintext still in the
 * table.
 *
 * <p><b>The rule.</b> This record does not decide quoting, it <em>reproduces</em> Hibernate's. It
 * is built in one place only - from the persister's own selection expression, parsed by Hibernate's
 * own {@code Identifier.toIdentifier} - and {@link #sql()} renders exactly what Hibernate renders:
 * bare when the mapping is unquoted, {@code "}-wrapped when the mapping quotes. That is why, unlike
 * {@link TableRef#sql()}, this never blanket-quotes: {@code @Column(name = "OWNER_ID")} is an
 * unquoted, upper-case, entirely ordinary mapping whose physical column PostgreSQL folded to
 * {@code owner_id}, and rendering {@code "OWNER_ID"} would address a column that does not exist.
 *
 * <p><b>Dialect.</b> PostgreSQL only, as {@link TableRef} is. {@code "} is the only quote character
 * this renders, and the starter refuses at startup any dialect that is not a PostgreSQL dialect
 * rather than rendering an identifier the database would read as something else.
 *
 * @param text the column name as the mapping holds it, quote characters already removed - {@code
 *     Owner}, not {@code "Owner"}
 * @param quoted whether the mapping quotes it, which is what decides whether PostgreSQL folds the
 *     case
 */
public record ColumnRef(String text, boolean quoted) {

  /**
   * PostgreSQL truncates an identifier at 63 bytes (NAMEDATALEN - 1) <em>silently</em>. A longer
   * one would address a different column than the one named, so it is refused rather than
   * truncated.
   */
  private static final int MAX_BYTES = 63;

  /**
   * An unquoted identifier is by construction a bare SQL identifier; anything else in it means the
   * expression was not a column name at all. Case is <em>not</em> constrained: an unquoted
   * upper-case name is legal and PostgreSQL folds it, which is the whole point of not quoting it
   * here.
   */
  private static final Pattern UNQUOTED = Pattern.compile("[A-Za-z_][A-Za-z0-9_$]*");

  public ColumnRef {
    Objects.requireNonNull(text, "text");
    if (text.isEmpty()) {
      throw new ShreddingException(ErrorCodes.CONFIG, "a column name is empty");
    }
    if (text.indexOf('"') >= 0) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "the column name "
              + text
              + " contains a double-quote character. This module renders a quoted identifier by"
              + " wrapping it in double quotes, and a name that carries one of its own cannot be"
              + " rendered that way without changing which column it addresses. It is refused"
              + " rather than escaped: a column no mapping can have is a parse this module got"
              + " wrong.");
    }
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (c < 0x20 || c == 0x7f) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "the column name \""
                + text
                + "\" contains a control character (0x"
                + Integer.toHexString(c)
                + "), which no mapping this module can address holds");
      }
    }
    int bytes = text.getBytes(StandardCharsets.UTF_8).length;
    if (bytes > MAX_BYTES) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "the column name \""
              + text
              + "\" is "
              + bytes
              + " bytes long; PostgreSQL truncates an identifier at "
              + MAX_BYTES
              + " bytes without saying so, which would address a different column than the one the"
              + " mapping names");
    }
    if (!quoted && !UNQUOTED.matcher(text).matches()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "the unquoted column expression \""
              + text
              + "\" is not a SQL identifier ("
              + UNQUOTED.pattern()
              + "). An unquoted expression that is not an identifier is not a column name: it is a"
              + " formula, a Column.assignmentExpression, or an expression this module has not been"
              + " shown to address, and it is refused rather than interpolated.");
    }
  }

  /** An unquoted column, which PostgreSQL folds to lower case. */
  public static ColumnRef unquoted(String text) {
    return new ColumnRef(text, false);
  }

  /** A column the mapping quotes, whose case is significant. */
  public static ColumnRef quoted(String text) {
    return new ColumnRef(text, true);
  }

  /** The identifier to interpolate into a statement: bare when unquoted, {@code "}-wrapped when not. */
  public String sql() {
    return quoted ? "\"" + text + "\"" : text;
  }

  /**
   * For messages: verbatim, with its quoting, because a developer comparing a lookup key against a
   * list of mapped columns has to be able to see which of them are quoted.
   */
  @Override
  public String toString() {
    return sql();
  }
}
