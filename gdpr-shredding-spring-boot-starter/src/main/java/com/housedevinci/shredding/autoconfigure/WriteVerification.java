package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.domain.EncryptedValue;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.ShreddingContext;
import java.math.BigDecimal;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.engine.spi.TransactionCompletionCallbacks;

/**
 * Design addendum "insert-side binding under batching" (2026-09-10), Cipher S-1.
 *
 * <p>The property this class exists for: <em>no row of a {@code @Shredded} entity commits whose
 * stored header is not bound to that row's own id, subject and tenant - at any {@code
 * hibernate.jdbc.batch_size}.</em> With the corollary the per-row post-hoc check in {@link
 * ShreddingEventListener} lacked: <strong>a check that could not run is a refusal, never a
 * pass.</strong>
 *
 * <p>S-1 was not "the {@code SELECT} sits in the wrong place". With {@code jdbc.batch_size} set the
 * {@code INSERT} is still in the JDBC batch when {@code onPostInsert} fires, so the read-back found
 * no row - and {@code refuseIfStoredHeadersDisagree} read "I saw nothing" as "nothing is wrong" and
 * returned. Every row of every batch went unchecked, on an ordinary performance property, with no
 * warning.
 *
 * <p>So a bind no longer <em>performs</em> a check, it <strong>incurs a debt</strong>: {@code
 * (entity, table, id column, id, expected tenant/subject/rowId)}, recorded on this session's ledger
 * the moment the row's identifier is known. Debts are settled - one {@code SELECT} with an {@code
 * IN} list per entity, not one statement per row - at every point where the JDBC batch has
 * demonstrably executed and the transaction has not yet committed:
 *
 * <ul>
 *   <li>the end of every flush and auto-flush, after {@code ActionQueue.executeActions} has called
 *       {@code JdbcCoordinator.executeBatch()} for each action queue;
 *   <li>{@code beforeCompletion}, which runs after Hibernate's own commit-time flush and covers
 *       {@code StatelessSession}, which fires no flush event at all.
 * </ul>
 *
 * <p><strong>Settlement is total or the transaction aborts.</strong> A debt whose row is absent, a
 * stored header that disagrees, or any debt still outstanding when the transaction completes is a
 * {@code SHRED-UNVERIFIED-WRITE} thrown before the commit. A configuration knob can no longer
 * remove this control; it can only make it refuse.
 *
 * <p>A row deleted in the same transaction discharges its own debt ({@code onPostDelete}): inside a
 * single flush Hibernate executes insertions before deletions, so an insert-then-delete of one row
 * would otherwise settle against a row that legitimately no longer exists.
 */
final class WriteVerification {

  /** Ids per settlement statement. Keeps the {@code IN} list off any driver's parameter limit. */
  private static final int CHUNK = 500;

  /**
   * QUESTIONS #26 (Cipher seventh pass): {@code shredding.write-verification.max-outstanding},
   * configured once by {@link ShreddingStartupCheck} at boot. A ledger this session's debts would
   * exceed is refused rather than left to grow without bound - a {@code StatelessSession} import of
   * millions of rows in one transaction is the only realistic way to reach it, and the remedy is a
   * transaction per chunk, not a bigger heap.
   */
  private static volatile int maxOutstanding = 50_000;

  static void configureMaxOutstanding(int max) {
    maxOutstanding = max;
  }

  /**
   * Keyed by session identity - Hibernate's session implementations do not override {@code equals}.
   * An entry is created only when a transaction is in progress, so the after-completion callback
   * that removes it is always registered and always runs.
   */
  private static final Map<SharedSessionContractImplementor, WriteVerification> LEDGERS =
      new ConcurrentHashMap<>();

  private final Map<Key, Debt> debts = new LinkedHashMap<>();

  private WriteVerification() {}

  /** One written row, identified the way the settlement query will identify it. */
  private record Key(String entityName, Object id) {}

  private record Debt(
      String entityName,
      String tableName,
      String idColumn,
      Object id,
      List<ShreddedModel.ShreddedField> fields,
      // S-2, carried into this ledger: a Scope, not a single TenantId - a debt covers every
      // @Shredded field of the row, and two fields of one entity may declare different tenants
      // (ShreddingContext.Scope#tenantFor). Comparing every field's stored header against one
      // scope-wide tenant would reintroduce the exact defect S-2 closed on the per-row post-hoc
      // check, just inside the settlement path instead.
      ShreddingContext.Scope scope,
      RowId rowId,
      String what) {}

  /**
   * Records what one flushed row must be found to hold. Called from {@code onPostInsert} and {@code
   * onPostUpdate}, where the identifier exists; the {@code IDENTITY} rebind has already run, so the
   * {@code rowId} recorded is the real one and never the {@code 0x7f} intermediate.
   */
  static void owe(
      SharedSessionContractImplementor session,
      String entityName,
      String tableName,
      String idColumn,
      Object id,
      List<ShreddedModel.ShreddedField> fields,
      ShreddingContext.Scope scope,
      RowId rowId,
      String what) {
    WriteVerification ledger = ledgerFor(session);
    Key key = new Key(entityName, normalise(id));
    // #26: the cap is on distinct debts, not on this call - a row already owed and rebound (an
    // update after an insert in the same flush) replaces its own entry rather than growing the
    // ledger, so only a genuinely new row can push it over.
    if (!ledger.debts.containsKey(key) && ledger.debts.size() >= maxOutstanding) {
      throw new ShreddingException(
          ErrorCodes.UNVERIFIED_WRITE,
          "this session's write-verification ledger already holds "
              + ledger.debts.size()
              + " unsettled row(s), at shredding.write-verification.max-outstanding ("
              + maxOutstanding
              + "). Settlement discharges the ledger at the end of every flush, so an ordinary"
              + " @Transactional write never grows past one flush worth of debt; a StatelessSession"
              + " import that stays under one transaction for its whole run does not flush at all"
              + " and keeps accumulating debts, each holding a subject and a tenant, until"
              + " beforeCompletion. Refused rather than left to grow without bound: commit in"
              + " chunks, one transaction per chunk, instead of one transaction for the whole"
              + " import.");
    }
    ledger.debts.put(
        key, new Debt(entityName, tableName, idColumn, id, fields, scope, rowId, what));
  }

  /** A row deleted in this transaction owes nothing: there is no stored header left to verify. */
  static void forgive(SharedSessionContractImplementor session, String entityName, Object id) {
    WriteVerification ledger = LEDGERS.get(session);
    if (ledger != null) {
      ledger.debts.remove(new Key(entityName, normalise(id)));
    }
  }

  /**
   * Settles every outstanding debt of this session, or throws. Called at the end of every flush and
   * auto-flush, and again from the before-completion callback.
   *
   * <p><strong>#27 (Cipher seventh pass).</strong> A debt is removed from the ledger only after the
   * check that discharges it has actually passed - not before, on the assumption that it is about
   * to. The old shape cleared the whole ledger up front, on the reasoning that a refusal below
   * throws out of the flush and aborts the transaction anyway, so nothing downstream would ever see
   * the difference. That reasoning is sound only as long as nothing ever catches the refusal and
   * carries on - which is exactly the shape S-1 itself was - and it made {@code beforeCompletion}'s
   * own "still outstanding at completion" refusal permanently unreachable: {@code settle} always
   * left the ledger empty, whether it threw or not. Now a chunk's debts are removed one at a time,
   * each immediately after its own row is found to agree, so a chunk that throws partway through
   * leaves every debt it had not yet reached - correctly - still outstanding.
   */
  static void settle(SharedSessionContractImplementor session) {
    WriteVerification ledger = LEDGERS.get(session);
    if (ledger == null || ledger.debts.isEmpty()) {
      return;
    }
    var outstanding = new ArrayList<>(ledger.debts.keySet());
    for (var group : groupByTable(ledger, outstanding).values()) {
      for (int from = 0; from < group.size(); from += CHUNK) {
        verifyChunk(session, ledger, group.subList(from, Math.min(from + CHUNK, group.size())));
      }
    }
  }

  private static Map<String, List<Key>> groupByTable(
      WriteVerification ledger, List<Key> outstanding) {
    var groups = new LinkedHashMap<String, List<Key>>();
    for (var key : outstanding) {
      Debt debt = ledger.debts.get(key);
      if (debt == null) {
        continue; // forgiven (onPostDelete) since the snapshot was taken
      }
      groups
          .computeIfAbsent(debt.entityName() + " " + debt.tableName(), k -> new ArrayList<>())
          .add(key);
    }
    return groups;
  }

  private static void verifyChunk(
      SharedSessionContractImplementor session, WriteVerification ledger, List<Key> chunkKeys) {
    var chunk = chunkKeys.stream().map(ledger.debts::get).toList();
    Debt first = chunk.get(0);
    var fields = first.fields();
    StringBuilder sql = new StringBuilder("SELECT ").append(quote(first.idColumn()));
    for (var field : fields) {
      sql.append(", ").append(quote(field.columnName()));
    }
    sql.append(" FROM ")
        .append(quote(first.tableName()))
        .append(" WHERE ")
        .append(quote(first.idColumn()))
        .append(" IN (");
    for (int i = 0; i < chunk.size(); i++) {
      sql.append(i == 0 ? "?" : ", ?");
    }
    sql.append(")");

    Map<Object, byte[][]> stored =
        session.doReturningWork(
            connection -> {
              var rows = new HashMap<Object, byte[][]>();
              try (PreparedStatement ps = connection.prepareStatement(sql.toString())) {
                for (int i = 0; i < chunk.size(); i++) {
                  ps.setObject(i + 1, chunk.get(i).id());
                }
                try (ResultSet rs = ps.executeQuery()) {
                  while (rs.next()) {
                    byte[][] columns = new byte[fields.size()][];
                    for (int i = 0; i < fields.size(); i++) {
                      columns[i] = rs.getBytes(i + 2);
                    }
                    rows.put(normalise(rs.getObject(1)), columns);
                  }
                }
              }
              return rows;
            });

    for (int idx = 0; idx < chunk.size(); idx++) {
      Debt debt = chunk.get(idx);
      byte[][] columns = stored.get(normalise(debt.id()));
      if (columns == null) {
        throw new ShreddingException(
            ErrorCodes.UNVERIFIED_WRITE,
            "the "
                + debt.what()
                + " "
                + debt.entityName()
                + " row "
                + debt.id()
                + " could not be read back before commit, so what it actually stores was never"
                + " compared against the scope it was written under. The transaction is refused"
                + " rather than committed unverified.");
      }
      for (int i = 0; i < fields.size(); i++) {
        if (columns[i] == null) {
          continue;
        }
        var header = EncryptedValue.decode(columns[i]);
        // S-2: this field's own tenant, not the row's primary one.
        if (!header.subject().equals(debt.scope().subject())
            || !header.tenant().equals(debt.scope().tenantFor(fields.get(i).fieldName()))
            || !header.rowId().equals(debt.rowId())) {
          throw new ShreddingException(
              ErrorCodes.SUBJECT_IMMUTABLE,
              "the "
                  + debt.what()
                  + " "
                  + debt.entityName()
                  + " row's stored "
                  + fields.get(i).fieldName()
                  + " is not bound to the subject and row it was written for. A write scope is"
                  + " consumable only by the bind it was pushed for; this row is refused before"
                  + " commit rather than left in another subject's erasure scope.");
        }
      }
      // #27: discharged only now, after this row's own check has actually passed.
      ledger.debts.remove(chunkKeys.get(idx));
    }
  }

  /**
   * A ledger for this session, and with it the two callbacks that make settlement unavoidable.
   *
   * <p>The transaction is the settlement anchor, so a bind with no transaction in progress has
   * nowhere to settle and is refused by {@link #requireSettlementAnchor} before it ever gets here.
   */
  private static WriteVerification ledgerFor(SharedSessionContractImplementor session) {
    WriteVerification existing = LEDGERS.get(session);
    if (existing != null) {
      return existing;
    }
    var created = new WriteVerification();
    LEDGERS.put(session, created);
    var callbacks = session.getTransactionCompletionCallbacks();
    callbacks.registerCallback(
        (TransactionCompletionCallbacks.BeforeCompletionCallback)
            s -> {
              settle(s);
              WriteVerification ledger = LEDGERS.get(s);
              if (ledger != null && !ledger.debts.isEmpty()) {
                int owed = ledger.debts.size();
                ledger.debts.clear();
                throw new ShreddingException(
                    ErrorCodes.UNVERIFIED_WRITE,
                    owed
                        + " written @Shredded row(s) were still unverified when this transaction"
                        + " tried to commit. The commit is refused: a row whose stored header was"
                        + " never compared against the scope it was written under may be sitting in"
                        + " another subject's erasure scope.");
              }
            });
    callbacks.registerCallback(
        (TransactionCompletionCallbacks.AfterCompletionCallback) (success, s) -> LEDGERS.remove(s));
    return created;
  }

  /**
   * Design addendum, part 3: a bind with no settlement anchor is refused at bind time rather than
   * written and never verified. Every JPA write runs inside a transaction; a {@code
   * StatelessSession} write outside one does not, and that is the path this closes.
   */
  static void requireSettlementAnchor(SharedSessionContractImplementor session, String entityName) {
    if (!session.isTransactionInProgress()) {
      throw new ShreddingException(
          ErrorCodes.UNVERIFIED_WRITE,
          "refusing to write a @Shredded "
              + entityName
              + " with no transaction in progress. What actually reached the database is verified"
              + " before the transaction commits; with no transaction there is no point at which"
              + " that check can run, and an unverifiable write is refused rather than performed.");
    }
  }

  /** How many rows this session still owes. Used by the settlement assertions in the tests. */
  static int outstanding(SharedSessionContractImplementor session) {
    WriteVerification ledger = LEDGERS.get(session);
    return ledger == null ? 0 : ledger.debts.size();
  }

  /**
   * Identifier values come back from JDBC in whatever type the driver chose, which is not always
   * the type Hibernate bound: a {@code bigint} id bound as {@code Long} can return as {@code Long}
   * or as {@code BigInteger}, an {@code int} column as {@code Integer}. Both sides of the
   * comparison go through here so settlement matches rows rather than boxes.
   *
   * <p><strong>S-9 (Cipher seventh pass).</strong> Must be injective over every identifier type JPA
   * allows. It used to map every {@link Number} through {@code longValue()}, which truncates a
   * {@link BigDecimal}, {@code Double} or {@code Float} id: {@code 1} and {@code 1.5} normalised to
   * the same key, so the second row's debt silently replaced the first's in {@code owe}'s {@code
   * Map.put}, and that row committed with its stored header never compared against anything - S-1's
   * property, reopened by an identifier type. Every {@link Number} now goes through the exact same
   * {@link BigDecimal} canonicalisation - never a truncation - so it matches regardless of which
   * concrete {@code Number} subtype the bind side and the JDBC read-back side each happen to use
   * for the same value (a {@code bigint} column, for example, can come back as {@code Long} or as
   * {@code BigInteger} depending on the driver).
   */
  private static Object normalise(Object id) {
    return switch (id) {
      case null -> null;
      case Byte n -> canonicalDecimal(BigDecimal.valueOf(n.longValue()));
      case Short n -> canonicalDecimal(BigDecimal.valueOf(n.longValue()));
      case Integer n -> canonicalDecimal(BigDecimal.valueOf(n.longValue()));
      case Long n -> canonicalDecimal(BigDecimal.valueOf(n));
      case java.math.BigInteger n -> canonicalDecimal(new BigDecimal(n));
      case BigDecimal n -> canonicalDecimal(n);
      case Float n -> canonicalDecimal(BigDecimal.valueOf(n.doubleValue()));
      case Double n -> canonicalDecimal(BigDecimal.valueOf(n));
      case Number n -> canonicalDecimal(BigDecimal.valueOf(n.longValue()));
      case UUID u -> u;
      case byte[] b -> java.util.Arrays.toString(b);
      default -> id.toString();
    };
  }

  /** The exact string form of a numeric id: never lossy, and the same string for equal values. */
  private static String canonicalDecimal(BigDecimal value) {
    return value.stripTrailingZeros().toPlainString();
  }

  private static String quote(String identifier) {
    return "\"" + identifier.replace("\"", "\"\"") + "\"";
  }
}
