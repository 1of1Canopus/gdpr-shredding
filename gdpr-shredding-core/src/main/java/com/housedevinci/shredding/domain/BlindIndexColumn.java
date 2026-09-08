package com.housedevinci.shredding.domain;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Where one blind index lives, so an erasure can null it in the same transaction that destroys the
 * key (control 10).
 *
 * <p>These names are interpolated into SQL identifiers, which no bind parameter can carry, so they
 * are validated here against a deliberately narrow pattern and rejected at startup otherwise. The
 * <em>values</em> compared against {@code subjectColumn} and {@code tenantColumn} are always bind
 * parameters.
 *
 * @param table the entity's table
 * @param column the blind-index column to null
 * @param subjectColumn the column holding the data subject id
 * @param tenantColumn the column holding the tenant id
 */
public record BlindIndexColumn(
    String table, String column, String subjectColumn, String tenantColumn) {

  private static final Pattern IDENTIFIER = Pattern.compile("[a-z_][a-z0-9_]{0,62}");

  public BlindIndexColumn {
    table = identifier("table", table);
    column = identifier("column", column);
    subjectColumn = identifier("subjectColumn", subjectColumn);
    tenantColumn = identifier("tenantColumn", tenantColumn);
  }

  private static String identifier(String what, String value) {
    Objects.requireNonNull(value, what);
    String lower = value.toLowerCase(java.util.Locale.ROOT);
    if (!IDENTIFIER.matcher(lower).matches()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "@BlindIndex "
              + what
              + " must match "
              + IDENTIFIER.pattern()
              + " (it becomes a SQL identifier, which cannot be a bind parameter)");
    }
    return lower;
  }
}
