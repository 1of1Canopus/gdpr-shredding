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
 * <p>{@link #subjectColumn()} and {@link #tenantColumn()} name <em>columns</em>, not properties;
 * they become SQL identifiers, so they are validated at startup against a narrow pattern. {@link
 * #tenantColumn()} is resolved at startup, through the entity's own column mapping, to the single
 * basic {@code String} property of this entity that maps to it - startup is refused if the
 * resolution finds none, finds more than one, finds a non-{@code String} one, or finds it only
 * inside an {@code @Embeddable}, because the write path has to read that value out of the row it is
 * writing.
 *
 * <p>The index is derived under <em>that row's own tenant column value</em>, which is the one value
 * the erasure's {@code WHERE} can match. The write is refused when it disagrees with the tenant the
 * indexed field's data key is derived under ({@code @Shredded(tenant = ...)}, else the ambient
 * {@code TenantSupplier}): one erasure request names one tenant and one subject, so key, ciphertext
 * and index are only reachable together when all three are under the same tenant. An application
 * whose acting organisation differs from the owning one declares the {@code @Shredded} tenant as
 * the owning one - the value its tenant column holds - and the shape works.
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
