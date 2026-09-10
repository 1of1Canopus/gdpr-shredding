package com.housedevinci.shredding.domain;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The table one statement names, schema and all (design addendum 3, change 9, applied §3.9a).
 *
 * <p><b>Why this type exists (S-21).</b> Every statement this module builds for a user table - the
 * blind-index {@code UPDATE}, the two read-backs that verify it, the post-hoc header check, the
 * {@code IDENTITY} rebind and the subject-immutability {@code SELECT} - used to interpolate a bare
 * name derived from {@code @Table(name = ...)}, which ignores {@code schema}. Which table those
 * statements actually hit was then decided by the runtime connection's {@code search_path} rather
 * than by the mapping Hibernate uses: a same-named table earlier on the path takes every one of
 * them, and an erasure clears a stranger's column while reporting success. The table is now taken
 * from the persister, parsed here, and rendered qualified.
 *
 * <p><b>Residual, stated because it is not closed.</b> When the mapping names no schema - no
 * {@code @Table(schema)}, no {@code hibernate.default_schema} - Hibernate's own table expression is
 * unqualified, and so is what this renders. {@code search_path} decides, exactly as it does for
 * Hibernate's own statements. That is the intended property: this module addresses the table
 * Hibernate addresses, whatever that is.
 *
 * @param schema the schema, empty when the mapping names none
 * @param name the table
 */
public record TableRef(Optional<String> schema, String name) {

  /**
   * Deliberately narrow: this table's schema and name become SQL identifiers, which no bind
   * parameter can carry. {@link BlindIndexColumn}'s {@code subjectColumn}/{@code tenantColumn} are
   * not validated against this or any pattern any more (design addendum 4, §4.3) - they are lookup
   * keys, matched case-sensitively against Hibernate's own mapping and then thrown away.
   */
  private static final Pattern IDENTIFIER = Pattern.compile("[a-z_][a-z0-9_]{0,62}");

  public TableRef {
    Objects.requireNonNull(schema, "schema");
    schema = schema.map(s -> part("schema", s));
    name = part("table", name);
  }

  /** An unqualified table. */
  public static TableRef of(String name) {
    return new TableRef(Optional.empty(), name);
  }

  /**
   * Parses a table expression as Hibernate renders it: {@code table}, {@code schema.table} or
   * {@code catalog.schema.table}, each part optionally quoted.
   *
   * <p>A catalog is refused rather than dropped. PostgreSQL has no cross-database references, so a
   * three-part expression here means the mapping is doing something this module has not been shown
   * to address, and silently addressing the last two parts would be a guess.
   */
  public static TableRef parse(String expression) {
    if (expression == null || expression.isBlank()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG, "a @Shredded entity's table expression is null or blank");
    }
    List<String> parts = split(expression);
    return switch (parts.size()) {
      case 1 -> new TableRef(Optional.empty(), parts.get(0));
      case 2 -> new TableRef(Optional.of(parts.get(0)), parts.get(1));
      default ->
          throw new ShreddingException(
              ErrorCodes.CONFIG,
              "the table expression \""
                  + expression
                  + "\" has "
                  + parts.size()
                  + " parts. This module addresses a table as an optional schema and a name; a"
                  + " catalog-qualified table is refused rather than silently reduced to its last"
                  + " two parts, which would address a table nobody named.");
    };
  }

  /** The quoted, qualified expression to interpolate into a statement. */
  public String sql() {
    return schema.map(s -> quote(s) + "." + quote(name)).orElseGet(() -> quote(name));
  }

  /** For messages: what a developer wrote, not what the driver reads. */
  @Override
  public String toString() {
    return schema.map(s -> s + "." + name).orElse(name);
  }

  private static String quote(String identifier) {
    return "\"" + identifier + "\"";
  }

  /** Splits on dots outside quotes, so a quoted identifier containing one stays whole. */
  private static List<String> split(String expression) {
    var parts = new ArrayList<String>();
    var current = new StringBuilder();
    boolean quoted = false;
    for (int i = 0; i < expression.length(); i++) {
      char c = expression.charAt(i);
      if (c == '"' || c == '`') {
        quoted = !quoted;
        current.append(c);
      } else if (c == '.' && !quoted) {
        parts.add(current.toString());
        current.setLength(0);
      } else {
        current.append(c);
      }
    }
    parts.add(current.toString());
    return parts;
  }

  private static String part(String what, String value) {
    Objects.requireNonNull(value, what);
    String trimmed = value.trim();
    boolean wasQuoted = false;
    if (trimmed.length() > 1) {
      char first = trimmed.charAt(0);
      char last = trimmed.charAt(trimmed.length() - 1);
      if ((first == '"' && last == '"') || (first == '`' && last == '`')) {
        trimmed = trimmed.substring(1, trimmed.length() - 1);
        wasQuoted = true;
      }
    }
    if (IDENTIFIER.matcher(trimmed).matches()) {
      return trimmed;
    }
    if (IDENTIFIER.matcher(trimmed.toLowerCase(Locale.ROOT)).matches()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "the "
              + what
              + " \""
              + trimmed
              + "\" is not folded lowercase. This module renders every identifier quoted, so"
              + " lowercasing it here would address \""
              + trimmed.toLowerCase(Locale.ROOT)
              + "\" - a different table in PostgreSQL"
              + (wasQuoted ? ", and the mapping quotes it, which makes the case significant" : "")
              + ". Map the "
              + what
              + " with a lowercase name.");
    }
    throw new ShreddingException(
        ErrorCodes.CONFIG,
        "the "
            + what
            + " \""
            + trimmed
            + "\" must match "
            + IDENTIFIER.pattern()
            + " (it becomes a SQL identifier, which cannot be a bind parameter)");
  }
}
