package com.housedevinci.shredding.api;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a column that holds the blind index of a {@link Shredded} field, so equality lookups still
 * work on an encrypted column.
 *
 * <p>Put it on a separate {@code byte[]} field of the same entity. The write path fills it in; the
 * query path must treat it as a <em>prefilter</em> and re-verify the candidates by decrypting,
 * because the index is truncated ({@code shredding.blind-index.bits}, default 64).
 *
 * <p>An erasure nulls this column for the erased subject. That is not configurable: an index that
 * survives an erasure keeps the erased subject searchable and linkable forever.
 *
 * <p>{@link #subjectColumn()} and {@link #tenantColumn()} name the columns the erasure matches on;
 * they become SQL identifiers, so they are validated at startup against a narrow pattern. The value
 * in {@link #tenantColumn()} must be the tenant the index was derived under, or the erasure cannot
 * find it: the {@link #of()} field may not declare its own {@code @Shredded(tenant=...)}, because
 * that would key the index under a tenant the erasure - which matches on the row's own {@code
 * tenantColumn} value, not on any one field's declared tenant expression - can never prove
 * reachable. Refused at startup rather than written.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface BlindIndex {

  /** The {@link Shredded} field this indexes. */
  String of();

  /** The column holding the data subject id. */
  String subjectColumn();

  /** The column holding the tenant id. */
  String tenantColumn();
}
