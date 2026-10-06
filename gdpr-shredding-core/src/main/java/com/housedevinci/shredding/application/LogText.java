package com.housedevinci.shredding.application;

/**
 * The one escape for an operator-chosen identifier printed in a log line or an exception message
 * (audit-table coverage design, section 3c.7, rev 5 item 3).
 *
 * <p>PostgreSQL accepts any UTF-8 in a quoted identifier, and a hook name is any string the
 * application picks, so either can hold a line break. Printed raw, one WARN becomes two lines and
 * the second can read like a line this module wrote. Escaped here: C0 controls (U+0000 to U+001F),
 * DEL (U+007F), C1 controls (U+0080 to U+009F), U+2028 and U+2029 as {@code \}{@code uXXXX}, and
 * the backslash itself as {@code \\}, so an escaped text cannot be mistaken for an escape. The
 * erasure record never goes through this: it keeps the exact text, which is hashed material.
 */
public final class LogText {

  private LogText() {}

  /**
   * {@code text} with every control character, line or paragraph separator and backslash escaped.
   */
  public static String escape(String text) {
    var out = new StringBuilder(text.length() + 8);
    for (int i = 0; i < text.length(); i++) {
      char ch = text.charAt(i);
      if (ch == '\\') {
        out.append("\\\\");
      } else if (ch < 0x20 || (ch >= 0x7F && ch <= 0x9F) || ch == ' ' || ch == ' ') {
        out.append(String.format("\\u%04X", (int) ch));
      } else {
        out.append(ch);
      }
    }
    return out.toString();
  }
}
