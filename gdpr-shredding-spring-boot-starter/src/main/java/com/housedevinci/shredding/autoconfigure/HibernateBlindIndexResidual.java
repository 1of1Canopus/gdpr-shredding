package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.adapter.jdbc.BlindIndexResidual;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TableRef;
import com.housedevinci.shredding.domain.TenantId;
import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.Map;
import org.hibernate.engine.spi.SessionFactoryImplementor;

/**
 * The independent read-back (design addendum 4, §4.5): after the erasure's {@code UPDATE}, a count
 * <em>Hibernate</em> renders from the entity mapping, on the erasure's own connection.
 *
 * <p><b>Why it is not more SQL.</b> The erasure's {@code UPDATE} and its same-text read-back are
 * built from the same three identifiers. If those identifiers address the wrong column - S-22 -
 * both are wrong together and agree with each other, the erasure clears nothing and the record says
 * {@code COMPLETE}. This query shares no identifier with them: the subject and the tenant are HQL
 * parameters, the index column is reached through the persister's own property, and the table and
 * every column are rendered by Hibernate from the mapping. The only way the two can disagree is if
 * the erasure addressed something the mapping does not.
 *
 * <p><b>How it stays on the erasure's transaction.</b> {@code
 * withStatelessOptions().connection(c).openStatelessSession()} gives Hibernate a caller-owned
 * connection: one physical connection, therefore one PostgreSQL transaction and one snapshot, and
 * {@code close()} hands the connection back without closing it. A {@code StatelessSession} also
 * cannot flush - {@code flush()} is empty and the auto-flush hooks return false - so it can never
 * write a blind index back after the clear.
 *
 * <p><b>Two hazards, written down because nothing in the API stops them.</b>
 *
 * <ul>
 *   <li>{@code beginTransaction()} and {@code getTransaction().commit()} are never called here.
 *       With a provided connection {@code isTransactionInProgress()} already returns {@code true},
 *       so there is nothing to stop a one-line "fix" that adds them - and a {@code commit()} here
 *       would commit the erasure's own connection half-done: index cleared, key destroyed, no
 *       record appended, no residual verified.
 *   <li>Closing the session runs {@code LogicalConnectionProvidedImpl.afterCompletion()}, which
 *       calls {@code resetConnection(initiallyAutoCommit)}. That is a no-op <em>only because</em>
 *       {@code JdbcSupport.inTransaction} set {@code autoCommit=false} on this connection before
 *       the erasure began. If that ever changes, this reset turns auto-commit back on
 *       mid-transaction.
 * </ul>
 */
final class HibernateBlindIndexResidual implements BlindIndexResidual {

  /**
   * A blind index is identified here by its table and its own column, never by the subject or
   * tenant columns the erasure matches on - those are exactly what a mis-addressed erasure gets
   * wrong, and a lookup keyed on them would find nothing precisely when it matters most.
   */
  private record Key(TableRef table, ColumnRef column) {}

  private record Residual(String hql, String entityName) {}

  private final SessionFactoryImplementor sessionFactory;
  private final Map<Key, Residual> residuals;

  HibernateBlindIndexResidual(SessionFactoryImplementor sessionFactory, ShreddedModel model) {
    this.sessionFactory = sessionFactory;
    var built = new LinkedHashMap<Key, Residual>();
    for (var index : model.blindIndexFields()) {
      var column = index.column();
      built.put(
          new Key(column.table(), column.column()),
          new Residual(
              "select count(*) from "
                  + index.entityName()
                  + " e where e."
                  + column.subjectProperty().orElseThrow()
                  + " = :subject and e."
                  + column.tenantProperty().orElseThrow()
                  + " = :tenant and e."
                  + index.fieldName()
                  + " is not null",
              index.entityName()));
    }
    this.residuals = Map.copyOf(built);
  }

  @Override
  public long count(
      Connection connection, BlindIndexColumn column, TenantId tenant, SubjectId subject) {
    Residual residual = residuals.get(new Key(column.table(), column.column()));
    if (residual == null) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "no entity mapping is registered for the blind-index column "
              + column.column().sql()
              + " of "
              + column.table()
              + ", so the erasure's independent read-back cannot be rendered. An erasure whose only"
              + " check is the statement it just ran is refused rather than recorded as complete.");
    }
    try (var session =
        sessionFactory.withStatelessOptions().connection(connection).openStatelessSession()) {
      // No beginTransaction, no commit: this connection's transaction belongs to the erasure.
      return session
          .createSelectionQuery(residual.hql(), Long.class)
          .setParameter("subject", subject.value())
          .setParameter("tenant", tenant.value())
          .getSingleResult();
    }
  }
}
