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
 * <p>A trail is keyed from row 1 or unkeyed forever (module B's keyed-from-birth ruling): the
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

  public JdbcErasureStore(
      DataSource dataSource, ErasureChain chain, List<BlindIndexColumn> blindIndexColumns) {
    this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    this.chain = Objects.requireNonNull(chain, "chain");
    this.blindIndexColumns = List.copyOf(blindIndexColumns);
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
          JdbcSupport.lockSubject(c, tenant, subject);
          // FOR UPDATE next: a concurrent write that is about to encrypt under this key blocks
          // here and then finds the row gone (control 6, probe on the erasure/write race).
          List<Integer> versions = lockKeyRows(c, tenant, subject);
          if (versions.isEmpty() && alreadyErased(c, tenant, subject)) {
            // Idempotent: a repeat erasure writes no second record and claims nothing new.
            return new Outcome(true, 0, 0, null);
          }
          int cleared = clearBlindIndexes(c, tenant, subject);
          int destroyed = deleteKeyRows(c, tenant, subject);
          tombstone(c, tenant, subject);
          ErasureRecord record = appendInTransaction(c, factory.create(destroyed, cleared));
          return new Outcome(false, destroyed, cleared, record);
        });
  }

  @Override
  public ErasureRecord append(ErasureRecord record) {
    return JdbcSupport.inTransaction(dataSource, c -> appendInTransaction(c, record));
  }

  private ErasureRecord appendInTransaction(Connection c, ErasureRecord record)
      throws SQLException {
    try (PreparedStatement lock = c.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
      lock.setLong(1, LOCK_KEY);
      lock.execute();
    }
    String prev = ErasureChain.GENESIS;
    long count = 0;
    boolean anchored = false;
    try (PreparedStatement ps =
            c.prepareStatement(
                "SELECT head_hash, row_count, keyed FROM shredding_erasure_anchor WHERE id = 1");
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
            "INSERT INTO shredding_erasure_anchor (id, head_hash, row_count, updated_at, keyed)"
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
            "INSERT INTO shredding_erasure (ts, tenant, subject_pseudonym, requested_by, reason,"
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

  private static List<Integer> lockKeyRows(Connection c, TenantId tenant, SubjectId subject)
      throws SQLException {
    var versions = new ArrayList<Integer>();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT version FROM shredding_data_key WHERE tenant = ? AND subject = ?"
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
  private static void tombstone(Connection c, TenantId tenant, SubjectId subject)
      throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement(
            "INSERT INTO shredding_erased_subject (tenant, subject, erased_at)"
                + " VALUES (?,?,now()) ON CONFLICT (tenant, subject) DO NOTHING")) {
      ps.setString(1, tenant.value());
      ps.setString(2, subject.value());
      ps.executeUpdate();
    }
  }

  private static boolean alreadyErased(Connection c, TenantId tenant, SubjectId subject)
      throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT 1 FROM shredding_erased_subject WHERE tenant = ? AND subject = ?")) {
      ps.setString(1, tenant.value());
      ps.setString(2, subject.value());
      try (ResultSet rs = ps.executeQuery()) {
        return rs.next();
      }
    }
  }

  private static int deleteKeyRows(Connection c, TenantId tenant, SubjectId subject)
      throws SQLException {
    // A DELETE, not an overwrite followed by a delete: under MVCC an overwrite only writes a
    // second heap tuple that still holds the same key, so the assurance it implies is false.
    try (PreparedStatement ps =
        c.prepareStatement("DELETE FROM shredding_data_key WHERE tenant = ? AND subject = ?")) {
      ps.setString(1, tenant.value());
      ps.setString(2, subject.value());
      return ps.executeUpdate();
    }
  }

  private int clearBlindIndexes(Connection c, TenantId tenant, SubjectId subject)
      throws SQLException {
    int cleared = 0;
    for (BlindIndexColumn column : blindIndexColumns) {
      // The identifiers were validated against a narrow pattern when the column was registered
      // (BlindIndexColumn, TableRef); the values are always bind parameters. The table is the one
      // the persister maps, schema and all (change 9, S-21): an unqualified name here would leave
      // it to the connection's search_path which table this UPDATE clears.
      String sql =
          "UPDATE "
              + column.table().sql()
              + " SET "
              + column.column()
              + " = NULL WHERE "
              + column.tenantColumn()
              + " = ? AND "
              + column.subjectColumn()
              + " = ? AND "
              + column.column()
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
   * Design addendum 3, change 5 (applied §3.5). The {@code UPDATE}s above report a row count; a row
   * count is what this module asked for, not evidence of what the table now holds. Between the
   * startup scan and this transaction the column may have gained a trigger, a rule, a rewriting
   * view or a new default, any of which leaves an HMAC of the erased plaintext behind while the
   * erasure record claims the index was cleared. So it is read back, inside the same transaction,
   * before the record is appended:
   *
   * <ul>
   *   <li>an index still populated for this (tenant, subject) <b>refuses</b> the erasure - {@link
   *       ErrorCodes#ERASURE_INDEX_RESIDUAL}, rolling back the whole transaction, key destruction
   *       and record included, so nothing claims a completion that did not happen;
   *   <li>an index under a <em>different</em> tenant value for the same subject id is a
   *       <b>WARN</b>, never a refusal: those rows may legitimately belong to another tenant that
   *       happens to use the same subject identifier, and refusing would let one tenant's data
   *       block another tenant's erasure. It is also the only place a row moved between tenants by
   *       a bulk update outside Hibernate (change 7) is ever visible.
   * </ul>
   */
  private void verifyCleared(Connection c, TenantId tenant, SubjectId subject) throws SQLException {
    for (BlindIndexColumn column : blindIndexColumns) {
      // Identifiers validated at startup (BlindIndexColumn); values are bind parameters.
      String residual =
          "SELECT count(*) FROM "
              + column.table().sql()
              + " WHERE "
              + column.tenantColumn()
              + " = ? AND "
              + column.subjectColumn()
              + " = ? AND "
              + column.column()
              + " IS NOT NULL";
      try (PreparedStatement ps = c.prepareStatement(residual)) {
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
                    + column.column()
                    + " for this subject after the erasure cleared it. Something outside this"
                    + " module - a trigger, a rule, a rewriting view - is repopulating the column,"
                    + " and an erasure that leaves an HMAC of the erased plaintext behind is"
                    + " refused rather than recorded as complete.");
          }
        }
      }
      String elsewhere =
          "SELECT count(*) FROM "
              + column.table().sql()
              + " WHERE "
              + column.subjectColumn()
              + " = ? AND "
              + column.tenantColumn()
              + " IS DISTINCT FROM ? AND "
              + column.column()
              + " IS NOT NULL";
      try (PreparedStatement ps = c.prepareStatement(elsewhere)) {
        ps.setString(1, subject.value());
        ps.setString(2, tenant.value());
        try (ResultSet rs = ps.executeQuery()) {
          long other = rs.next() ? rs.getLong(1) : 0L;
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
                column.column());
          }
        }
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
                      + " FROM shredding_erasure WHERE tenant = ? AND subject_pseudonym = ?"
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
                      "SELECT head_hash, row_count, keyed FROM shredding_erasure_anchor WHERE id = 1");
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
                      + " FROM shredding_erasure WHERE seq > ? ORDER BY seq ASC LIMIT ?")) {
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
            c.prepareStatement("SELECT keyed FROM shredding_erasure_anchor WHERE id = 1");
        ResultSet rs = ps.executeQuery()) {
      if (rs.next()) {
        return new TrailState(true, rs.getBoolean(1), true);
      }
    }
    try (PreparedStatement ps = c.prepareStatement("SELECT 1 FROM shredding_erasure LIMIT 1");
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
        byteLength = Integer.parseInt(material.substring(i + 1, colon));
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
        seen +=
            String.valueOf(material.charAt(end))
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)
                .length;
        end++;
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
