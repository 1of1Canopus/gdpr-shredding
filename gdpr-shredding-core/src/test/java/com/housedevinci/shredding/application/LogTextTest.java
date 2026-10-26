package com.housedevinci.shredding.application;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * {@link LogText#escape}: what an operator-chosen name may not hide in a message (C-PR47-5). The
 * characters are built from code points: invisible or bidi characters never sit in this source.
 */
class LogTextTest {

  private static String cp(int... codePoints) {
    var out = new StringBuilder();
    for (int c : codePoints) {
      out.appendCodePoint(c);
    }
    return out.toString();
  }

  @Test
  void escapes_controls_separators_and_the_backslash() {
    assertThat(LogText.escape("a" + cp(0x0A) + "b" + cp(0x85) + "c" + cp(0x2028) + "d\\e"))
        .isEqualTo("a\\u000Ab\\u0085c\\u2028d\\\\e");
  }

  @Test
  void escapes_format_characters() {
    // A schema "public" + U+200B (zero width space) printed raw reads as "public".
    assertThat(LogText.escape("public" + cp(0x200B) + ".w")).isEqualTo("public\\u200B.w");
    // U+202E right-to-left override.
    assertThat(LogText.escape("a" + cp(0x202E) + "b")).isEqualTo("a\\u202Eb");
    // U+FEFF byte order mark, U+2060 word joiner, U+00AD soft hyphen.
    assertThat(LogText.escape(cp(0xFEFF) + "x")).isEqualTo("\\uFEFFx");
    assertThat(LogText.escape("x" + cp(0x2060, 0xAD) + "y")).isEqualTo("x\\u2060\\u00ADy");
  }

  @Test
  void escapes_a_format_character_outside_the_basic_plane_as_its_two_units() {
    // U+E0041 TAG LATIN CAPITAL LETTER A is format (Cf) and invisible.
    assertThat(LogText.escape("a" + cp(0xE0041) + "b")).isEqualTo("a\\uDB40\\uDC41b");
  }

  @Test
  void escapes_lone_surrogates_and_keeps_a_valid_pair() {
    assertThat(LogText.escape("a" + (char) 0xD800 + "b")).isEqualTo("a\\uD800b");
    assertThat(LogText.escape("a" + (char) 0xDC00)).isEqualTo("a\\uDC00");
    String emoji = cp(0x1F600);
    assertThat(LogText.escape("x" + emoji)).isEqualTo("x" + emoji);
  }

  @Test
  void keeps_plain_text() {
    String text = "public.w(text, boolean) caf" + cp(0xE9);
    assertThat(LogText.escape(text)).isEqualTo(text);
  }
}
