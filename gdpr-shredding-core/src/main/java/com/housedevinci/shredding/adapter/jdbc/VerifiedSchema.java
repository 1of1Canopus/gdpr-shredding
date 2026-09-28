package com.housedevinci.shredding.adapter.jdbc;

import java.util.Objects;

/**
 * The schema {@link JdbcSupport#verifySchema} resolved with {@code current_schema()} and then
 * verified, object by object, on that same connection.
 *
 * <p>Design §16 (finding C-D2-1). Every statement this module issues is qualified with this name,
 * so none of them depends on {@code search_path} at parse time. Three attacks close together as a
 * result, and all three were reproduced against the unqualified form: a second schema the runtime
 * role owns holding same-named unguarded copies and placed first on the path; a {@code
 * pg_temp.shredding_erasure} created by the runtime role itself while it holds {@code TEMPORARY};
 * and a plain {@code SET search_path} issued between two adapter calls on a pooled connection. In
 * every one of them {@code current_schema()} still answered {@code public} and boot verification
 * still answered clean, while the appends went somewhere else.
 *
 * <p>The name is never caller input: it comes from the server's own {@code current_schema()} on the
 * connection verification ran on. It is quoted anyway, with {@code "} doubled, so an operator whose
 * schema is {@code Public}, {@code my schema} or {@code s"q} gets the relation they verified rather
 * than a parse error or, worse, a different relation.
 */
public record VerifiedSchema(String name) {

  public VerifiedSchema {
    Objects.requireNonNull(name, "name");
    if (name.isBlank()) {
      throw new IllegalArgumentException("verified schema name is blank");
    }
  }

  /** {@code "myschema"."shredding_erasure"} - both parts quoted, never interpolated bare. */
  public String qualify(String relation) {
    Objects.requireNonNull(relation, "relation");
    return quote(name) + "." + quote(relation);
  }

  private static String quote(String identifier) {
    return "\"" + identifier.replace("\"", "\"\"") + "\"";
  }

  @Override
  public String toString() {
    return name;
  }
}
