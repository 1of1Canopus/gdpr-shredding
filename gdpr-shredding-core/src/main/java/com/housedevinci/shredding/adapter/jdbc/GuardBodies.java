package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reads the three guard-function bodies out of the bundled {@code schema-postgresql.sql}, through
 * the same {@code getResourceAsStream} call {@link JdbcSupport#initializeSchema} uses.
 *
 * <p>Design §4.3, finding D-2. Version 1 of the design declared {@code prosrc} out of scope because
 * a replaced body "is caught by the trigger identity check". That was wrong and it was the hole:
 * {@code CREATE OR REPLACE FUNCTION} keeps the oid, so the oid, {@code prolang}, {@code
 * prorettype}, {@code tgfoid}, {@code tgtype} and {@code tgenabled} are byte-identical before and
 * after a body swap. The behavioural alternative is closed too - a role with {@code SELECT}/{@code
 * INSERT} only can never observe a guard firing, because the privilege check runs before the
 * trigger. So the bodies are verified material.
 *
 * <p>Extracted at run time rather than shipped as a digest, so the expectation and the script it is
 * about cannot drift. A resource that does not yield exactly the three expected names is {@code
 * SHRED-SCHEMA-005}: a broken jar is unverifiable, not clean.
 */
final class GuardBodies {

  private GuardBodies() {}

  private static final String CREATE = "CREATE OR REPLACE FUNCTION";
  private static final String DOLLARS = "$$";

  /** Keyed by function name, values normalised by {@link #normalise}. */
  static Map<String, String> fromBundledScript() {
    return extract(readResource());
  }

  static String readResource() {
    try (InputStream in = JdbcSupport.class.getResourceAsStream(JdbcSupport.SCHEMA_RESOURCE)) {
      if (in == null) {
        throw new ShreddingException(
            ErrorCodes.SCHEMA_UNVERIFIABLE,
            "the bundled schema resource "
                + JdbcSupport.SCHEMA_RESOURCE
                + " is missing from the classpath, so the guard-function bodies this module"
                + " verifies against cannot be read. The schema cannot be verified, which is not"
                + " the same as verifying it clean. Check that the gdpr-shredding-core jar is"
                + " intact and not repackaged with its resources stripped.");
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "the bundled schema resource " + JdbcSupport.SCHEMA_RESOURCE + " could not be read.",
          e);
    }
  }

  static Map<String, String> extract(String script) {
    var found = new LinkedHashMap<String, String>();
    int at = 0;
    while ((at = script.indexOf(CREATE, at)) >= 0) {
      int nameStart = at + CREATE.length();
      int paren = script.indexOf('(', nameStart);
      int open = script.indexOf(DOLLARS, nameStart);
      if (paren < 0 || open < 0 || paren > open) {
        throw unreadable("a CREATE OR REPLACE FUNCTION block has no name or no $$ body");
      }
      String name = script.substring(nameStart, paren).trim();
      int close = script.indexOf(DOLLARS, open + DOLLARS.length());
      if (close < 0) {
        throw unreadable("the $$ body of " + name + " is not closed");
      }
      if (found.put(name, normalise(script.substring(open + DOLLARS.length(), close))) != null) {
        throw unreadable("the guard function " + name + " is defined twice");
      }
      at = close + DOLLARS.length();
    }
    if (!found.keySet().equals(new java.util.LinkedHashSet<>(SchemaExpectations.GUARD_FUNCTIONS))) {
      throw unreadable(
          "expected exactly the guard functions "
              + SchemaExpectations.GUARD_FUNCTIONS
              + " and found "
              + found.keySet());
    }
    for (var entry : found.entrySet()) {
      if (entry.getValue().indexOf('\r') >= 0) {
        throw unreadable(
            "the body of "
                + entry.getKey()
                + " in the bundled resource contains a carriage return that is not part of a CRLF"
                + " line ending. PostgreSQL ends a -- comment at a lone CR, so that body does not"
                + " mean what it looks like it means and it is not a body this module will accept"
                + " as its own expectation.");
      }
    }
    return Map.copyOf(found);
  }

  /**
   * Exactly two steps, and then one refusal elsewhere (design §4.3 as amended for C-D2-2). CRLF is
   * folded to LF, and the result is stripped at both ends. Nothing else: no comment stripping, no
   * whitespace collapsing, no lower-casing. Stripping SQL comments needs a lexer, and a lexer that
   * mishandles a {@code --} inside a string literal fails open.
   *
   * <p>Version 2 dropped <em>every</em> {@code \r}, which made six variants of {@code
   * shredding_erasure_anchor_monotonic} hash to the expected value while PostgreSQL's own lexer saw
   * different code, because a {@code --} comment ends at a lone {@code \r} too. A lone {@code \r}
   * that survives this fold is therefore refused by the caller rather than normalised away; a body
   * applied from a CRLF checkout has none and still passes.
   */
  static String normalise(String body) {
    return body.replace("\r\n", "\n").strip();
  }

  private static ShreddingException unreadable(String what) {
    return new ShreddingException(
        ErrorCodes.SCHEMA_UNVERIFIABLE,
        "the bundled schema resource "
            + JdbcSupport.SCHEMA_RESOURCE
            + " could not be read as the expectation for this module's guard functions: "
            + what
            + ". The schema cannot be verified, which is not the same as verifying it clean.");
  }
}
