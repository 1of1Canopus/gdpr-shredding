package com.housedevinci.shredding.application;

/**
 * The one escape for an operator-chosen identifier printed in a log line or an exception message
 * (audit-table coverage design, section 3c.7, rev 5 item 3).
 *
 * <p>PostgreSQL accepts any UTF-8 in a quoted identifier, and a hook name is any string the
 * application picks, so either can hold a line break. Printed raw, one WARN becomes two lines and
 * the second can read like a line this module wrote. Escaped here: C0 controls (U+0000 to U+001F),
 * DEL (U+007F), C1 controls (U+0080 to U+009F), U+2028 and U+2029, every format character (Unicode
 * category Cf: U+200B to U+200F, U+202A to U+202E, U+2060 to U+2064, U+FEFF, U+00AD and the tag
 * characters, among others) and every lone surrogate, as {@code \}{@code uXXXX} per UTF-16 unit,
 * and the backslash itself as {@code \\}, so an escaped text cannot be mistaken for an escape. A
 * format character is invisible: a schema named {@code public} followed by U+200B would print as
 * {@code public} (C-PR47-5). The erasure record never goes through this: it keeps the exact text,
 * which is hashed material.
 */
public final class LogText {

  private LogText() {}

  /**
   * {@code text} with every control, separator, format character, lone surrogate and backslash
   * escaped.
   */
  public static String escape(String text) {
    var out = new StringBuilder(text.length() + 8);
    int i = 0;
    while (i < text.length()) {
      int cp = text.codePointAt(i);
      int units = Character.charCount(cp);
      if (cp == '\\') {
        out.append("\\\\");
      } else if (hidden(cp)) {
        for (int u = i; u < i + units; u++) {
          out.append(String.format("\\u%04X", (int) text.charAt(u)));
        }
      } else {
        out.appendCodePoint(cp);
      }
      i += units;
    }
    return out.toString();
  }

  /**
   * A code point that would break or disguise the line: a control, a separator, a format character
   * or a lone surrogate ({@code codePointAt} returns a lone surrogate as itself).
   */
  private static boolean hidden(int cp) {
    return cp < 0x20
        || (cp >= 0x7F && cp <= 0x9F)
        || cp == 0x2028
        || cp == 0x2029
        || Character.getType(cp) == Character.FORMAT
        || Character.getType(cp) == Character.SURROGATE;
  }
}
