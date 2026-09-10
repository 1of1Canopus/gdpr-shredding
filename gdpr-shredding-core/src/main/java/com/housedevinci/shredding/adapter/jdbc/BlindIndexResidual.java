package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.sql.Connection;

/**
 * An answer to "does this subject still have a populated blind index?" that is <em>not</em> built
 * from the text the erasure's own statements were built from (design addendum 4, §4.5).
 *
 * <p><b>Why this is a port and not a method.</b> {@code JdbcErasureStore}'s {@code UPDATE} and its
 * same-text read-back share one weakness: if the column identifier is wrong, both are wrong
 * together and agree with each other. That is S-22. The check that catches a mis-addressed erasure
 * therefore has to come from somewhere else - in the auto-configured module, from Hibernate, which
 * renders the column from its own mapping. Core does not know Hibernate, so the starter supplies
 * this.
 *
 * <p><b>The contract, and it is strict.</b> The implementation is handed the erasure's <em>own</em>
 * {@link Connection}, inside the erasure's own transaction, which already holds a {@code
 * pg_advisory_xact_lock} and {@code SELECT ... FOR UPDATE} rows. It must:
 *
 * <ul>
 *   <li>never take a second connection - a pool of one would deadlock, a second connection sees a
 *       different snapshot and may carry a different {@code search_path};
 *   <li>never begin or commit a transaction on it - that would commit a half-done erasure, with the
 *       index cleared and the key destroyed but no record appended;
 *   <li>never be able to flush pending entity state - a flush here writes a blind index back
 *       <em>after</em> the clear.
 * </ul>
 *
 * <p>This interface lives beside the JDBC adapter rather than in {@code application} for one
 * reason: its contract is about a {@code java.sql.Connection}, and {@code application} is not
 * allowed to import {@code java.sql} (ArchUnit enforces that). It is the JDBC adapter's own SPI.
 */
@FunctionalInterface
public interface BlindIndexResidual {

  /**
   * How many rows of {@code column}'s table still hold a value in the blind-index column for this
   * subject and tenant, counted independently of the identifiers {@code column} carries.
   *
   * @param connection the erasure's own connection; see the class contract
   * @return zero when nothing is left, which is the only answer that lets the erasure complete
   */
  long count(Connection connection, BlindIndexColumn column, TenantId tenant, SubjectId subject);
}
