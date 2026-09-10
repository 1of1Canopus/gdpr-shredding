package com.housedevinci.shredding.domain;

import java.util.Objects;
import java.util.Optional;
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
 * <p><b>Design addendum 3, change 2 (applied §3.2).</b> {@code tenantColumn} is a <em>column</em>
 * name - what the erasure's {@code WHERE} matches on - while the write path reads its value out of
 * Hibernate's state array, which is keyed by <em>property</em> name. S-7 and S-13 both exist
 * because the tenant the write derived under and the tenant the erasure matched on were computed in
 * two places from two different inputs; a third input resolved somewhere else again would only move
 * the seam. So the column-to-property resolution happens once, at startup, through the entity's own
 * column mapping, and its result lives here beside the column it resolved from: one object, one
 * resolution, read by {@code writeBlindIndexes} (the property) and by {@code
 * JdbcErasureStore.clearBlindIndexes} (the column).
 *
 * <p><b>Design addendum 3, change 8 (applied §3.8b).</b> S-20 was S-13 one column over: the same
 * resolution was owed to {@code subjectColumn}, which the erasure's {@code WHERE} matches on just
 * as it matches on {@code tenantColumn}, and which nothing resolved, read or compared. Both axes
 * now carry their resolved property on this one record, so a row's index, its data key and the
 * values the erasure matches on cannot be computed from three different inputs.
 *
 * @param table the entity's table, schema and all (change 9, §3.9a)
 * @param column the blind-index column to null
 * @param subjectColumn the column holding the data subject id
 * @param tenantColumn the column holding the tenant id
 * @param tenantProperty the entity property mapped to {@code tenantColumn}, resolved from the
 *     Hibernate metamodel at startup. Empty only for a model scanned without an {@code
 *     EntityManagerFactory} (this module's own unit tests); the startup check refuses an empty one,
 *     and the write path refuses to derive an index without it rather than guessing.
 * @param subjectProperty the entity property mapped to {@code subjectColumn}, resolved the same way
 *     and empty under the same one condition
 */
public record BlindIndexColumn(
    TableRef table,
    String column,
    String subjectColumn,
    String tenantColumn,
    Optional<String> tenantProperty,
    Optional<String> subjectProperty) {

  private static final Pattern IDENTIFIER = Pattern.compile("[a-z_][a-z0-9_]{0,62}");
  private static final Pattern PROPERTY = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]{0,127}");

  public BlindIndexColumn {
    Objects.requireNonNull(table, "table");
    column = identifier("column", column);
    subjectColumn = identifier("subjectColumn", subjectColumn);
    tenantColumn = identifier("tenantColumn", tenantColumn);
    Objects.requireNonNull(tenantProperty, "tenantProperty");
    Objects.requireNonNull(subjectProperty, "subjectProperty");
    tenantProperty.ifPresent(p -> property("tenantProperty", p));
    subjectProperty.ifPresent(p -> property("subjectProperty", p));
  }

  /** A column whose tenant and subject columns have not been resolved to properties yet. */
  public static BlindIndexColumn unresolved(
      TableRef table, String column, String subjectColumn, String tenantColumn) {
    return new BlindIndexColumn(
        table, column, subjectColumn, tenantColumn, Optional.empty(), Optional.empty());
  }

  /** The same column, addressed at the table the persister maps (change 9, §3.9b). */
  public BlindIndexColumn at(TableRef resolvedTable) {
    return new BlindIndexColumn(
        resolvedTable, column, subjectColumn, tenantColumn, tenantProperty, subjectProperty);
  }

  /** The same column, with the properties the startup scan resolved both columns to. */
  public BlindIndexColumn resolvedTo(String tenant, String subject) {
    return new BlindIndexColumn(
        table, column, subjectColumn, tenantColumn, Optional.of(tenant), Optional.of(subject));
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

  private static String property(String what, String value) {
    if (!PROPERTY.matcher(value).matches()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "@BlindIndex " + what + " must match " + PROPERTY.pattern() + ", was \"" + value + "\"");
    }
    return value;
  }
}
