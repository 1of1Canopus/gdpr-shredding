package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.JdbcSupport.instant;
import static com.housedevinci.shredding.adapter.jdbc.JdbcSupport.ts;

import com.housedevinci.shredding.application.ErasureReader;
import com.housedevinci.shredding.application.ErasureStore;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ErasureAnchor;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.HookOutcome;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TableRef;
import com.housedevinci.shredding.domain.TenantId;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The erasure half in PostgreSQL: key destruction, blind-index clearing and the chained erasure
 * record, in one transaction (control 6, 8, 10).
 *
 * <p>A trail is keyed from row 1 or unkeyed forever (module B's keyed-from-birth decision): the
 * anchor's {@code keyed} column records which, once, and every later append must agree with it or
 * is refused with {@link ErrorCodes#ERASURE_KEY_MISMATCH}. A trail with rows and no anchor is never
 * re-derived by guessing; it is refused with {@link ErrorCodes#ERASURE_ANCHOR_MISSING}, both at
 * construction and on every append.
 */
public final class JdbcErasureStore implements ErasureStore, ErasureReader, ErasureAnchor {

  private static final Logger log = LoggerFactory.getLogger(JdbcErasureStore.class);

  private static final long LOCK_KEY = 0x5348455241L; // "SHERA"

  private static final String COLUMNS =
      "seq, ts, tenant, subject_pseudonym, requested_by, reason, keys_destroyed, entity_count,"
          + " field_count, blind_index_cleared, outcome, hook_outcomes, backup_clear_at,"
          + " chain_version, key_id, prev_hash, hash";

  private final DataSource dataSource;
  private final ErasureChain chain;
  private final List<BlindIndexColumn> blindIndexColumns;
  private final List<MappingAdmission.Target> admissionTargets;
  private final BlindIndexResidual residual;
  private final String dataKeyTable;
  private final String erasedSubjectTable;
  private final String erasureTable;
  private final String anchorTable;

  /**
   * @param residual the independent read-back (design addendum 4, §4.5). It is not optional and has
   *     no default: an erasure whose own statements are the only thing that ever checks them is the
   *     shape S-22 shipped. See {@link BlindIndexResidual} for what an implementation must not do.
   */
  public JdbcErasureStore(
      DataSource dataSource,
      VerifiedSchema schema,
      ErasureChain chain,
      List<BlindIndexColumn> blindIndexColumns,
      BlindIndexResidual residual) {
    this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    Objects.requireNonNull(schema, "schema");
    // Design §16: the four relation names are built once, from the schema that was verified at
    // boot, and no statement below names a relation any other way. The blind-index statements are
    // deliberately not qualified here - they address the application's own tables through the
    // persister's TableRef, which carries the schema the mapping names (section 3.2) and whose
    // relation is checked against the catalogue before every erasure (MappingAdmission).
    this.dataKeyTable = schema.qualify(SchemaExpectations.DATA_KEY);
    this.erasedSubjectTable = schema.qualify(SchemaExpectations.ERASED_SUBJECT);
    this.erasureTable = schema.qualify(SchemaExpectations.ERASURE);
    this.anchorTable = schema.qualify(SchemaExpectations.ANCHOR);
    this.chain = Objects.requireNonNull(chain, "chain");
    this.blindIndexColumns = List.copyOf(blindIndexColumns);
    this.admissionTargets = MappingAdmission.Target.forErasure(this.blindIndexColumns);
    this.residual = Objects.requireNonNull(residual, "residual");
    // Fail closed at startup, not on the first erasure: a rolling restart must not serve traffic
    // for a while before it discovers it disagrees with the trail.
    JdbcSupport.withConnection(
        dataSource,
        c -> {
          refuseIfMismatched(trailState(c));
          return null;
        });
  }

  @Override
  public Outcome erase(TenantId tenant, SubjectId subject, RecordFactory factory) {
    return JdbcSupport.inTransaction(
        dataSource,
        c -> {
          // CIPHER-03: the (tenant, subject) advisory lock first, ahead of the FOR UPDATE. It is
          // what makes a write racing the *first* mint for a subject line up behind (or in front
          // of) this erasure instead of both observing "no row, no tombstone" at once.
          step("the subject's advisory lock", () -> JdbcSupport.lockSubject(c, tenant, subject));
          // FOR UPDATE next: a concurrent write that is about to encrypt under this key blocks
          // here and then finds the row gone (control 6, probe on the erasure/write race).
          List<Integer> versions =
              step("the subject's key rows", () -> lockKeyRows(c, tenant, subject));
          if (versions.isEmpty()
              && step("the erasure tombstone", () -> alreadyErased(c, tenant, subject))) {
            // Idempotent: a repeat erasure writes no second record and claims nothing new.
            return new Outcome(true, 0, 0, null);
          }
          int cleared = step("the blind-index update", () -> clearBlindIndexes(c, tenant, subject));
          int destroyed = step("the key-row delete", () -> deleteKeyRows(c, tenant, subject));
          step("the erasure tombstone", () -> tombstone(c, tenant, subject));
          ErasureRecord record =
              step(
                  "the erasure-log append",
                  () -> appendInTransaction(c, factory.create(destroyed, cleared)));
          return new Outcome(false, destroyed, cleared, record);
        });
  }

  @Override
  public ErasureRecord append(ErasureRecord record) {
    return JdbcSupport.inTransaction(
        dataSource, c -> step("the erasure-log append", () -> appendInTransaction(c, record)));
  }

  private ErasureRecord appendInTransaction(Connection c, ErasureRecord record)
      throws SQLException {
    try (PreparedStatement lock =
        c.prepareStatement("SELECT pg_catalog.pg_advisory_xact_lock(?)")) {
      lock.setLong(1, LOCK_KEY);
      lock.execute();
    }
    String prev = ErasureChain.GENESIS;
    long count = 0;
    boolean anchored = false;
    try (PreparedStatement ps =
            c.prepareStatement(
                "SELECT head_hash, row_count, keyed FROM "
                    + anchorTable
                    + " WHERE (id OPERATOR(pg_catalog.=) 1)");
        ResultSet rs = ps.executeQuery()) {
      if (rs.next()) {
        prev = rs.getString(1);
        count = rs.getLong(2);
        refuseIfMismatched(new TrailState(true, rs.getBoolean(3), true));
        anchored = true;
      }
    }
    if (!anchored) {
      refuseIfMismatched(trailState(c));
    }
    ErasureRecord linked = chain.link(record, prev);
    try (PreparedStatement ps =
        c.prepareStatement(
            "INSERT INTO "
                + anchorTable
                + " (id, head_hash, row_count, updated_at, keyed)"
                + " VALUES (1, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET"
                + " head_hash = EXCLUDED.head_hash, row_count = EXCLUDED.row_count,"
                + " updated_at = EXCLUDED.updated_at")) {
      ps.setString(1, linked.hash());
      ps.setLong(2, count + 1);
      ps.setObject(3, ts(linked.timestamp()));
      ps.setBoolean(4, chain.isKeyed());
      ps.executeUpdate();
    }
    try (PreparedStatement ps =
        c.prepareStatement(
            "INSERT INTO "
                + erasureTable
                + " (ts, tenant, subject_pseudonym, requested_by, reason,"
                + " keys_destroyed, entity_count, field_count, blind_index_cleared, outcome,"
                + " hook_outcomes, backup_clear_at, chain_version, key_id, prev_hash, hash)"
                + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq")) {
      int i = 1;
      ps.setObject(i++, ts(linked.timestamp()));
      ps.setString(i++, linked.tenant().value());
      ps.setString(i++, linked.subjectPseudonym());
      ps.setString(i++, linked.requestedBy());
      ps.setString(i++, linked.reason());
      ps.setInt(i++, linked.keysDestroyed());
      ps.setInt(i++, linked.entityCount());
      ps.setInt(i++, linked.fieldCount());
      ps.setInt(i++, linked.blindIndexColumnsCleared());
      ps.setString(i++, linked.outcome().name());
      ps.setString(i++, ErasureChain.hookMaterial(linked));
      ps.setObject(i++, ts(linked.backupRetentionUntil()));
      ps.setString(i++, linked.chainVersion());
      ps.setString(i++, linked.keyId());
      ps.setString(i++, linked.prevHash());
      ps.setString(i, linked.hash());
      try (ResultSet rs = ps.executeQuery()) {
        rs.next();
        return linked.withSequence(rs.getLong(1));
      }
    }
  }

  private List<Integer> lockKeyRows(Connection c, TenantId tenant, SubjectId subject)
      throws SQLException {
    var versions = new ArrayList<Integer>();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT version FROM "
                + dataKeyTable
                + " WHERE (tenant OPERATOR(pg_catalog.=) ?)"
                + " AND (subject OPERATOR(pg_catalog.=) ?)"
                + " ORDER BY version FOR UPDATE")) {
      ps.setString(1, tenant.value());
      ps.setString(2, subject.value());
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          versions.add(rs.getInt(1));
        }
      }
    }
    return versions;
  }

  /**
   * Records that this subject is erased. The key rows are gone; this row holds no key material and
   * exists so a later write cannot mint a fresh key and quietly undo the erasure (control 11).
   */
  private void tombstone(Connection c, TenantId tenant, SubjectId subject) throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement(
            "INSERT INTO "
                + erasedSubjectTable
                + " (tenant, subject, erased_at)"
                + " VALUES (?,?,pg_catalog.now()) ON CONFLICT (tenant, subject) DO NOTHING")) {
      ps.setString(1, tenant.value());
      ps.setString(2, subject.value());
      ps.executeUpdate();
    }
  }

  private boolean alreadyErased(Connection c, TenantId tenant, SubjectId subject)
      throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT 1 FROM "
                + erasedSubjectTable
                + " WHERE (tenant OPERATOR(pg_catalog.=) ?)"
                + " AND (subject OPERATOR(pg_catalog.=) ?)")) {
      ps.setString(1, tenant.value());
      ps.setString(2, subject.value());
      try (ResultSet rs = ps.executeQuery()) {
        return rs.next();
      }
    }
  }

  private int deleteKeyRows(Connection c, TenantId tenant, SubjectId subject) throws SQLException {
    // A DELETE, not an overwrite followed by a delete: under MVCC an overwrite only writes a
    // second heap tuple that still holds the same key, so the assurance it implies is false.
    try (PreparedStatement ps =
        c.prepareStatement(
            "DELETE FROM "
                + dataKeyTable
                + " WHERE (tenant OPERATOR(pg_catalog.=) ?)"
                + " AND (subject OPERATOR(pg_catalog.=) ?)")) {
      ps.setString(1, tenant.value());
      ps.setString(2, subject.value());
      return ps.executeUpdate();
    }
  }

  private int clearBlindIndexes(Connection c, TenantId tenant, SubjectId subject)
      throws SQLException {
    // Mapping admission, the erasure leg (name-resolution design, addendum section A.5): every
    // table this erasure will clear is locked and then checked against the catalogue, before the
    // first statement that touches it. All tables first, in the model's order, which is the lock
    // order for every erasure, so two erasures cannot take the same pair of locks the other way
    // round.
    for (MappingAdmission.Target target : admissionTargets) {
      admit(c, target);
    }
    int cleared = 0;
    for (BlindIndexColumn column : blindIndexColumns) {
      // Addendum 4, S4.4: every identifier here is a TableRef or a ColumnRef, built from the
      // persister's own mapping and rendered exactly as Hibernate renders it - quoted when the
      // mapping quotes, bare when it does not. No String identifier survives in any signature on
      // this path. The values are always bind parameters. The table is the one the persister maps,
      // schema and all (change 9, S-21): an unqualified name here would leave it to the
      // connection's search_path which table this UPDATE clears.
      String sql =
          "UPDATE "
              + column.table().sql()
              + " SET "
              + column.column().sql()
              + " = NULL WHERE ("
              + column.tenantColumn().sql()
              + " OPERATOR(pg_catalog.=) ?) AND ("
              + column.subjectColumn().sql()
              + " OPERATOR(pg_catalog.=) ?) AND "
              + column.column().sql()
              + " IS NOT NULL";
      try (PreparedStatement ps = c.prepareStatement(sql)) {
        ps.setString(1, tenant.value());
        ps.setString(2, subject.value());
        cleared += ps.executeUpdate();
      }
    }
    verifyCleared(c, tenant, subject);
    return cleared;
  }

  /**
   * Locks one table and checks its mapping, in that order (addendum section A.5, steps 1, 1b, 2 and
   * 3). Never cached: a verdict taken at startup is undone by one rename and one {@code CREATE
   * VIEW} the role is allowed to perform (D16), so the verdict that counts is the one taken here,
   * under a lock that keeps it true until this transaction ends.
   *
   * <p><b>Step 1</b>, {@code ROW EXCLUSIVE}, is the lock the {@code UPDATE} takes anyway, taken
   * before the verdict instead of after it: it conflicts with the {@code ACCESS EXCLUSIVE} that
   * {@code DROP TABLE}, {@code ALTER TABLE ... RENAME} and every other way of swapping the relation
   * need. <b>Step 1b</b>, {@code SHARE UPDATE EXCLUSIVE}, pins the descendant set: {@code ATTACH
   * PARTITION}, {@code DETACH PARTITION CONCURRENTLY}, {@code CREATE TABLE ... INHERITS} and {@code
   * ALTER TABLE ... INHERIT} all take {@code SHARE UPDATE EXCLUSIVE} on the parent, which does not
   * conflict with step 1, so without step 1b a relation could be routed to after the verdict
   * described the set. The design took step 1b on a partitioned table only; the build measured the
   * two inheritance statements succeeding on an ordinary table under step 1 alone, so it is taken
   * on every table. It does not conflict with {@code ROW EXCLUSIVE}, so the application's own
   * writes are not blocked; it does serialise two erasures of the same table, and waits behind a
   * manual {@code VACUUM}, {@code ANALYZE} or {@code CREATE INDEX CONCURRENTLY} on it.
   *
   * <p>A lock that fails because the relation does not exist, cannot be locked (a foreign table) or
   * may not be locked by this role is the same refusal the verdict would give, reached one
   * statement earlier (A26).
   */
  private static void admit(Connection c, MappingAdmission.Target target) throws SQLException {
    TableRef table = target.table();
    lock(c, target, "LOCK TABLE " + table.sql() + " IN ROW EXCLUSIVE MODE");
    lock(c, target, "LOCK TABLE " + table.sql() + " IN SHARE UPDATE EXCLUSIVE MODE");
    MappingAdmission.Verdict verdict = MappingAdmission.verdict(c, target);
    switch (verdict) {
      case MappingAdmission.Admitted admitted -> {
        // Postures the erasure is sound under; startup has already warned about each of them.
      }
      case MappingAdmission.Absent absent -> throw refusedBeforeFirstStatement(absent.message());
      case MappingAdmission.Refused refused -> throw refusedBeforeFirstStatement(refused.message());
    }
  }

  private static void lock(Connection c, MappingAdmission.Target target, String sql)
      throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(sql)) {
      ps.execute();
    } catch (SQLException e) {
      String state = String.valueOf(e.getSQLState());
      if (isLockWait(e)) {
        throw lockWait(
            "the table lock on "
                + target.table()
                + " (wanted: "
                + sql.substring(sql.indexOf(" IN ") + 4)
                + ")",
            e);
      }
      String why =
          switch (state) {
            case "42P01" -> "does not exist";
            case "42809" -> "is not a relation this module can lock (a foreign table is one)";
            case "42501" -> "may not be locked by this role, which an erasure needs";
            default -> null;
          };
      if (why == null) {
        throw e;
      }
      throw refusedBeforeFirstStatement(
          "shredding: the blind-indexed table "
              + target.table()
              + " "
              + why
              + " (SQLState "
              + state
              + "). Create the table, map the entity to an ordinary table, or grant the runtime"
              + " role SELECT and UPDATE on it (SECURITY-NOTES.md, \"Database roles\").");
    }
  }

  /** One statement of the erasure transaction, so a lock wait inside it can be named (RC-10). */
  @FunctionalInterface
  private interface Step<T> {
    T run() throws SQLException;
  }

  @FunctionalInterface
  private interface VoidStep {
    void run() throws SQLException;
  }

  private static <T> T step(String what, Step<T> step) throws SQLException {
    try {
      return step.run();
    } catch (SQLException e) {
      if (isLockWait(e)) {
        throw lockWait(what, e);
      }
      throw e;
    }
  }

  private static void step(String what, VoidStep step) throws SQLException {
    step(
        what,
        () -> {
          step.run();
          return null;
        });
  }

  private static boolean isLockWait(SQLException e) {
    return "55P03".equals(e.getSQLState()) || "40P01".equals(e.getSQLState());
  }

  /**
   * RC-7, RC-10: a {@code lock_timeout} that fired (55P03) or a deadlock this transaction lost
   * (40P01) at any wait of the erasure. The transaction rolls back whole, so nothing is destroyed,
   * cleared or recorded, and the caller is not sent to the key store.
   */
  private static ShreddingException lockWait(String what, SQLException e) {
    String state = e.getSQLState();
    return new ShreddingException(
        ErrorCodes.ERASURE_LOCK_WAIT,
        "shredding: the erasure waited on "
            + what
            + " ("
            + ("55P03".equals(state)
                ? "lock wait exceeded the connection's lock_timeout"
                : "deadlock detected, this transaction was chosen as the victim")
            + ", SQLState "
            + state
            + "). The erasure was not performed: no key is destroyed, no blind index is touched"
            + " and no record is appended. Another session holds a conflicting lock (another"
            + " erasure, an application transaction open on the subject's row, a manual VACUUM,"
            + " ANALYZE or CREATE INDEX CONCURRENTLY, or an autovacuum to prevent wraparound)."
            + " This is not a key-store outage. Retry the erasure later.",
        e);
  }

  private static ShreddingException refusedBeforeFirstStatement(String message) {
    return new ShreddingException(
        ErrorCodes.MAPPING_INADMISSIBLE,
        message
            + " This erasure is refused before its first statement: no key is destroyed, no blind"
            + " index is touched and no record is appended.");
  }

  /**
   * Design addendum 4, §4.5, on top of addendum 3 change 5 (§3.5). Two read-backs, for two
   * different failures, both run unconditionally - never only when {@code cleared == 0}, because a
   * mis-addressed <em>tenant</em> column clears a subset rather than nothing, and a check that runs
   * only on the failure path is never exercised and rots.
   *
   * <ol>
   *   <li><b>The independent one, first.</b> A residual Hibernate renders from its own mapping, on
   *       this very {@link Connection}: it does not share one character of text with the statements
   *       above, so an erasure that addressed the wrong column - S-22 - is caught here even though
   *       the {@code UPDATE} and the same-text query below agree with each other perfectly. Above
   *       zero refuses. Row counts are never a refusal predicate: {@code AND <col> IS NOT NULL}
   *       makes {@code cleared} a subset of the subject's rows, so a nullable index, a row written
   *       before the column existed, or a retry all give {@code cleared &lt; rows} with nothing
   *       wrong.
   *   <li><b>The same-text one, after it.</b> The {@code UPDATE}s report a row count; a row count
   *       is what this module asked for, not evidence of what the table now holds. Between the
   *       startup scan and this transaction the column may have gained a trigger, a rule, a view
   *       that repopulates it or a new default, any of which leaves an HMAC of the erased plaintext
   *       behind while the erasure record claims the index was cleared. Also refuses with {@link
   *       ErrorCodes#ERASURE_INDEX_RESIDUAL}. It does <em>not</em> cover a view, a policy or a
   *       foreign table that <em>hides</em> the subject's row: this read-back asks the same
   *       relation the same way as the {@code UPDATE} and agrees with it (A6). That shape is
   *       refused before the first statement, by {@link MappingAdmission}.
   *   <li><b>The cross-tenant one is a WARN, never a refusal.</b> An index under a
   *       <em>different</em> tenant value for the same subject id may legitimately belong to
   *       another tenant that happens to use the same subject identifier, and refusing would let
   *       one tenant's data block another tenant's erasure. It is also the only place a row moved
   *       between tenants by a bulk update outside Hibernate (change 7) is ever visible.
   * </ol>
   *
   * <p>Either refusal rolls back the whole transaction - key destruction, tombstone and record
   * included - so nothing claims a completion that did not happen.
   *
   * <p><b>Concurrency, stated as intent rather than tolerated as a race (addendum 4, change
   * 10).</b> The independent count runs on this connection, so it shares this transaction and its
   * snapshot. The one divergence left is a row committed for the subject <em>after</em> the {@code
   * UPDATE}'s snapshot: a new row carrying a populated index for a subject whose key is about to be
   * destroyed. That refuses the erasure, under READ COMMITTED, REPEATABLE READ and SERIALIZABLE
   * alike. It is the intended answer, not a race to retry away.
   *
   * <p><b>Cost.</b> One indexed {@code COUNT} per (erasure, blind-index column) for each of the two
   * read-backs, on a connection that already holds the row locks, inside a transaction that already
   * does an advisory lock, a {@code SELECT ... FOR UPDATE}, a {@code DELETE}, a tombstone insert
   * and a hash-chain append. Measured on the probe suite's PostgreSQL container: <b>214 ms</b> for
   * the very first erasure in a JVM - that is Hibernate compiling the HQL, once, not the query -
   * and <b>1.3-4.2 ms</b> (median 1.8 ms) for every one after it. Erasure is rare and
   * human-initiated; if it is ever too slow the answer is an index on (tenant, subject), not a
   * control that switches itself off.
   */
  private void verifyCleared(Connection c, TenantId tenant, SubjectId subject) throws SQLException {
    for (BlindIndexColumn column : blindIndexColumns) {
      // C-13-14: the one statement of this erasure whose text this module did not write. It is
      // rendered by Hibernate from the entity mapping, so there is no name in it to qualify, and
      // the only mechanism left is the session's own candidate set. One statement, its own window.
      long independent =
          JdbcSupport.inOneStatementWindow(c, () -> residual.count(c, column, tenant, subject));
      if (independent > 0) {
        throw new ShreddingException(
            ErrorCodes.ERASURE_INDEX_RESIDUAL,
            "erasure refused: read back through the entity's own mapping, "
                + independent
                + " row(s) of "
                + column.table()
                + " still hold a value in the blind-index column "
                + column.column().sql()
                + " for this subject. This read-back shares no identifier with the statements this"
                + " erasure built, so it also fires when those statements addressed the wrong"
                + " column and cleared nothing while reporting success. The whole transaction is"
                + " rolled back: no key is destroyed and no record is appended.");
      }
      // Identifiers validated at startup (BlindIndexColumn); values are bind parameters.
      String sameText =
          "SELECT pg_catalog.count(*) FROM "
              + column.table().sql()
              + " WHERE ("
              + column.tenantColumn().sql()
              + " OPERATOR(pg_catalog.=) ?) AND ("
              + column.subjectColumn().sql()
              + " OPERATOR(pg_catalog.=) ?) AND "
              + column.column().sql()
              + " IS NOT NULL";
      try (PreparedStatement ps = c.prepareStatement(sameText)) {
        ps.setString(1, tenant.value());
        ps.setString(2, subject.value());
        try (ResultSet rs = ps.executeQuery()) {
          long left = rs.next() ? rs.getLong(1) : 0L;
          if (left > 0) {
            throw new ShreddingException(
                ErrorCodes.ERASURE_INDEX_RESIDUAL,
                "erasure refused: "
                    + left
                    + " row(s) of "
                    + column.table()
                    + " still hold a value in the blind-index column "
                    + column.column().sql()
                    + " for this subject after the erasure cleared it. Something outside this"
                    + " module - a trigger, a rule, a rewriting view - is repopulating the column,"
                    + " and an erasure that leaves an HMAC of the erased plaintext behind is"
                    + " refused rather than recorded as complete.");
          }
        }
      }
      // The tenant leg is spelled out rather than written IS DISTINCT FROM (finding C-A-6). The
      // keyword form reaches the type's own `=` along search_path and has no
      // OPERATOR(pg_catalog....) spelling at all, so it was the one name in this module that
      // qualification could not reach. A bare OPERATOR(pg_catalog.<>) is not equivalent here: the
      // tenant column is nullable and `NULL <> ?` is NULL, which drops exactly the rows this WARN
      // exists to find. `(<tenant> IS NULL OR NOT (<tenant> = ?))` is equivalent for the non-null
      // bound value this always passes, and every name in it is pg_catalog's.
      String elsewhere =
          "SELECT pg_catalog.count(*) FROM "
              + column.table().sql()
              + " WHERE ("
              + column.subjectColumn().sql()
              + " OPERATOR(pg_catalog.=) ?) AND ("
              + column.tenantColumn().sql()
              + " IS NULL OR NOT ("
              + column.tenantColumn().sql()
              + " OPERATOR(pg_catalog.=) ?)) AND "
              + column.column().sql()
              + " IS NOT NULL";
      // No window around this statement (finding C-18-6).
      // Every name in it is pg_catalog's and its relation is two-part (section 3.2), so the
      // session's path decides nothing here and a window could change no answer any test can
      // observe. The window is for text this module cannot qualify, which is the framework-rendered
      // read-back above and nothing else; the name gate asserts that no window holds a statement
      // this module wrote.
      long other;
      try (PreparedStatement ps = c.prepareStatement(elsewhere)) {
        ps.setString(1, subject.value());
        ps.setString(2, tenant.value());
        try (ResultSet rs = ps.executeQuery()) {
          other = rs.next() ? rs.getLong(1) : 0L;
        }
      }
      if (other > 0) {
        log.warn(
            "shredding: this subject also has {} blind index value(s) in {}.{} under other"
                + " tenant values, which this erasure does not destroy. That is legitimate when"
                + " another tenant uses the same subject identifier for a different person, and"
                + " is a leftover when it is the same person - a row whose tenant column was"
                + " changed by a bulk update outside Hibernate keeps an index derived under its"
                + " former tenant. Erase that tenant too, or re-derive the index.",
            other,
            column.table(),
            column.column().sql());
      }
    }
  }

  @Override
  public Optional<ErasureRecord> latestForSubject(TenantId tenant, String subjectPseudonym) {
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "SELECT "
                      + COLUMNS
                      + " FROM "
                      + erasureTable
                      + " WHERE (tenant OPERATOR(pg_catalog.=) ?)"
                      + " AND (subject_pseudonym OPERATOR(pg_catalog.=) ?)"
                      // CIPHER-15: the log is append-only and seq is its own monotonic bigserial;
                      // ts is clock.instant() from the application and a backwards clock step
                      // (NTP, a container resume, two nodes disagreeing) between two appends could
                      // otherwise return an older COMPLETE ahead of a later PARTIAL and hide an
                      // outstanding erasure from the DPO who asked. Order by the column that
                      // actually orders the chain.
                      + " ORDER BY seq DESC LIMIT 1")) {
            ps.setString(1, tenant.value());
            ps.setString(2, subjectPseudonym);
            try (ResultSet rs = ps.executeQuery()) {
              return rs.next() ? Optional.of(map(rs)) : Optional.<ErasureRecord>empty();
            }
          }
        });
  }

  @Override
  public Optional<Anchor> anchor() {
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
                  c.prepareStatement(
                      "SELECT head_hash, row_count, keyed FROM "
                          + anchorTable
                          + " WHERE (id OPERATOR(pg_catalog.=) 1)");
              ResultSet rs = ps.executeQuery()) {
            return rs.next()
                ? Optional.of(new Anchor(rs.getString(1), rs.getLong(2), rs.getBoolean(3)))
                : Optional.empty();
          }
        });
  }

  @Override
  public List<ErasureRecord> readAfter(long afterSequence, int limit) {
    int capped = Math.max(1, Math.min(limit, 1000));
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "SELECT "
                      + COLUMNS
                      + " FROM "
                      + erasureTable
                      + " WHERE (seq OPERATOR(pg_catalog.>) ?) ORDER BY seq ASC LIMIT ?")) {
            ps.setLong(1, afterSequence);
            ps.setInt(2, capped);
            try (ResultSet rs = ps.executeQuery()) {
              var out = new ArrayList<ErasureRecord>();
              while (rs.next()) {
                out.add(map(rs));
              }
              return out;
            }
          }
        });
  }

  private record TrailState(boolean anchored, boolean keyed, boolean nonEmpty) {}

  private TrailState trailState(Connection c) throws SQLException {
    try (PreparedStatement ps =
            c.prepareStatement(
                "SELECT keyed FROM " + anchorTable + " WHERE (id OPERATOR(pg_catalog.=) 1)");
        ResultSet rs = ps.executeQuery()) {
      if (rs.next()) {
        return new TrailState(true, rs.getBoolean(1), true);
      }
    }
    try (PreparedStatement ps = c.prepareStatement("SELECT 1 FROM " + erasureTable + " LIMIT 1");
        ResultSet rs = ps.executeQuery()) {
      return new TrailState(false, false, rs.next());
    }
  }

  private void refuseIfMismatched(TrailState state) {
    if (!state.anchored() && state.nonEmpty()) {
      throw new ShreddingException(
          ErrorCodes.ERASURE_ANCHOR_MISSING,
          "shredding_erasure_anchor has no row but shredding_erasure is not empty. The schema step"
              + " never invents a keyed value for rows it did not write, so this is refused rather"
              + " than guessed: either a restore lost the anchor row, or a role that can disable"
              + " triggers removed it. Remedy: archive shredding_erasure and"
              + " shredding_erasure_anchor and re-run the schema step so it re-seeds an empty pair.");
    }
    if (state.anchored() && state.keyed() != chain.isKeyed()) {
      throw new ShreddingException(
          ErrorCodes.ERASURE_KEY_MISMATCH,
          "shredding_erasure is "
              + (state.keyed() ? "keyed" : "unkeyed")
              + " but this instance is "
              + (chain.isKeyed() ? "keyed" : "unkeyed")
              + " (shredding.erasure-log.hmac-secret "
              + (chain.isKeyed() ? "is set" : "is not set, or shredding.erasure-log.unkeyed=true")
              + "). A trail is keyed from row 1 or unkeyed forever; it cannot switch. To change the"
              + " mode for real, archive the trail and its anchor and start a new one.");
    }
  }

  private static ErasureRecord map(ResultSet rs) throws SQLException {
    long seq = rs.getLong("seq");
    List<HookOutcome> hooks;
    try {
      hooks = decodeHooks(rs.getString("hook_outcomes"));
    } catch (ShreddingException e) {
      // L10: the sequence is already in hand, so the verifier's caller can say exactly which row
      // would not decode, not just that something did.
      throw new ShreddingException(
          ErrorCodes.INVALID, "erasure record seq=" + seq + ": " + e.getMessage(), e);
    }
    return new ErasureRecord(
        seq,
        instant(rs.getObject("ts", OffsetDateTime.class)),
        TenantId.of(rs.getString("tenant")),
        rs.getString("subject_pseudonym"),
        rs.getString("requested_by"),
        rs.getString("reason"),
        rs.getInt("keys_destroyed"),
        rs.getInt("entity_count"),
        rs.getInt("field_count"),
        rs.getInt("blind_index_cleared"),
        ErasureOutcome.valueOf(rs.getString("outcome")),
        hooks,
        instant(rs.getObject("backup_clear_at", OffsetDateTime.class)),
        rs.getString("chain_version"),
        rs.getString("key_id"),
        rs.getString("prev_hash"),
        rs.getString("hash"));
  }

  /** Reverses {@link ErasureChain#hookMaterial}: triples of length-prefixed fields. */
  static List<HookOutcome> decodeHooks(String material) {
    var out = new ArrayList<HookOutcome>();
    if (material == null || material.isEmpty()) {
      return out;
    }
    var fields = new ArrayList<String>();
    int i = 0;
    while (i < material.length()) {
      if (material.charAt(i) != '|') {
        throw new ShreddingException(ErrorCodes.INVALID, "hook_outcomes is not in canonical form");
      }
      int colon = material.indexOf(':', i + 1);
      if (colon < 0) {
        throw new ShreddingException(ErrorCodes.INVALID, "hook_outcomes is not in canonical form");
      }
      int byteLength;
      try {
        String digits = material.substring(i + 1, colon);
        // P-2: only the digits the encoder writes (no sign, no leading zero).
        if (!digits.matches("0|[1-9][0-9]*")) {
          throw new NumberFormatException(digits);
        }
        byteLength = Integer.parseInt(digits);
      } catch (NumberFormatException e) {
        // L10: this column is writable by exactly the attacker the chain exists to detect, so a
        // malformed length must be a typed, catchable error - never a raw NumberFormatException
        // the verifier's read path cannot distinguish from a real bug and has no chance to turn
        // into BROKEN.
        throw new ShreddingException(ErrorCodes.INVALID, "hook_outcomes is not in canonical form");
      }
      int start = colon + 1;
      int end = start;
      int seen = 0;
      while (end < material.length() && seen < byteLength) {
        // P-1: advance by code point, not by UTF-16 char. A character outside the BMP is a
        // surrogate pair whose UTF-8 form (4 bytes) only exists for the pair; counting each half
        // alone (1 byte each, as '?') loses the field boundary. Encoding side
        // (ErasureChain.field) encodes the whole string, so this is the symmetric count.
        int next = end + Character.charCount(material.codePointAt(end));
        seen +=
            material.substring(end, next).getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        end = next;
      }
      if (seen != byteLength) {
        // P-2: the length ended inside a character or ran past the material; the encoder never
        // writes either.
        throw new ShreddingException(ErrorCodes.INVALID, "hook_outcomes is not in canonical form");
      }
      fields.add(material.substring(start, end));
      i = end;
    }
    if (fields.size() % 3 != 0) {
      throw new ShreddingException(ErrorCodes.INVALID, "hook_outcomes is not in canonical form");
    }
    for (int f = 0; f < fields.size(); f += 3) {
      out.add(
          new HookOutcome(
              fields.get(f), Boolean.parseBoolean(fields.get(f + 1)), fields.get(f + 2)));
    }
    return out;
  }
}
