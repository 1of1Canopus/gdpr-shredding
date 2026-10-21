package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Runs the three statements of the function-grants leg (C-PR45-3) and returns their rows as facts.
 * It judges nothing: {@link FunctionGrants} applies every rule in Java.
 *
 * <p>The statements are the resource files {@value #STATEMENT_ONE}, {@value #STATEMENT_TWO} and
 * {@value #STATEMENT_THREE}, beside the pinned files, in the house dialect, so the
 * name-qualification gate lexes them whole. Java binds parameters only; it never puts text into
 * them. A missing or unreadable file is {@code SHRED-SCHEMA-005}. Both run on the caller's
 * connection, inside its pinned window.
 */
final class FunctionGrantsSql {

  private FunctionGrantsSql() {}

  static final String STATEMENT_ONE = "function-grants-1.sql";
  static final String STATEMENT_TWO = "function-grants-2.sql";
  static final String STATEMENT_THREE = "function-grants-3.sql";

  /** The first oid PostgreSQL assigns after initdb (FirstNormalObjectId). */
  static final long FIRST_NORMAL_OID = 16_384;

  /**
   * One row of statement 1: a function with a shipped record or a baseline oid, or an extension.
   */
  record RecordFact(
      String kind,
      long oid,
      String privtype,
      String acl,
      boolean namesPublic,
      boolean namesLate,
      boolean nativeCode,
      String signature,
      String key,
      String symbol,
      boolean securityDefiner,
      String extension,
      String version,
      String targets) {}

  /** One row of statement 2: one (function, grantee) pair, the grantee empty when none. */
  record ExecuteFact(
      long oid,
      String label,
      OptionalLong grantee,
      String privtype,
      boolean shippedPublic,
      boolean nativeCode,
      String language,
      String symbol,
      boolean securityDefiner,
      String extension,
      String version,
      String key,
      long owner,
      String ownerName,
      String kind,
      String library) {}

  /**
   * One row of statement 3: one (caller object, slot, support function). {@code slot} is the
   * 1-based position in the branch's slot list ({@link FunctionGrants#SLOTS}). {@code fnLabel} is
   * the slot function's schema-qualified name: {@code fnKey} has no schema, as the manifest's
   * support column has none. {@code fnDefiner} is its rights mode; {@code fnReach} is true when
   * reach may run it as itself (C-PR47-2): PUBLIC holds EXECUTE on it, or a role whose rights the
   * login may use (inherited, or reachable by {@code SET ROLE}) holds EXECUTE on it or owns it.
   * Membership alone does not count (C-PR47-4): a grant {@code WITH INHERIT FALSE, SET FALSE} gives
   * the login none of the role's rights.
   */
  record CallerFact(
      String kind,
      long oid,
      String label,
      long owner,
      String ownerName,
      boolean usable,
      int slot,
      long fn,
      String fnKey,
      String fnLabel,
      boolean fnDefiner,
      boolean fnReach) {}

  static int major(Connection c) throws SQLException {
    try (PreparedStatement ps =
            c.prepareStatement(
                "SELECT pg_catalog.current_setting('server_version_num')::pg_catalog.int4");
        ResultSet rs = ps.executeQuery()) {
      if (!rs.next()) {
        throw new SQLException("server_version_num gave no row");
      }
      return rs.getInt(1) / 10_000;
    }
  }

  /** The text of statement 1, read from the jar. */
  static String statementOne() {
    return resource(STATEMENT_ONE);
  }

  /** The text of statement 2, read from the jar. */
  static String statementTwo() {
    return resource(STATEMENT_TWO);
  }

  /** The text of statement 3, read from the jar. */
  static String statementThree() {
    return resource(STATEMENT_THREE);
  }

  static List<RecordFact> records(
      Connection c, long[] baselineOids, List<String> okExtensions, List<String> okPairs)
      throws SQLException {
    var out = new ArrayList<RecordFact>();
    try (PreparedStatement ps = c.prepareStatement(statementOne())) {
      ps.setArray(1, c.createArrayOf("oid", boxed(baselineOids)));
      ps.setArray(2, c.createArrayOf("text", okExtensions.toArray()));
      ps.setArray(3, c.createArrayOf("text", okPairs.toArray()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          out.add(
              new RecordFact(
                  rs.getString(1),
                  rs.getLong(2),
                  text(rs, 3),
                  text(rs, 4),
                  rs.getBoolean(5),
                  rs.getBoolean(6),
                  rs.getBoolean(7),
                  text(rs, 8),
                  text(rs, 9),
                  text(rs, 10),
                  rs.getBoolean(11),
                  text(rs, 12),
                  text(rs, 13),
                  text(rs, 14)));
        }
      }
    }
    return out;
  }

  static List<ExecuteFact> executes(Connection c, long[] reachOids, long[] baselineOids)
      throws SQLException {
    var out = new ArrayList<ExecuteFact>();
    try (PreparedStatement ps = c.prepareStatement(statementTwo())) {
      ps.setArray(1, c.createArrayOf("oid", boxed(reachOids)));
      ps.setArray(2, c.createArrayOf("oid", boxed(baselineOids)));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          long g = rs.getLong(3);
          OptionalLong grantee = rs.wasNull() ? OptionalLong.empty() : OptionalLong.of(g);
          out.add(
              new ExecuteFact(
                  rs.getLong(1),
                  text(rs, 2),
                  grantee,
                  text(rs, 4),
                  rs.getBoolean(5),
                  rs.getBoolean(6),
                  text(rs, 7),
                  text(rs, 8),
                  rs.getBoolean(9),
                  text(rs, 10),
                  text(rs, 11),
                  text(rs, 12),
                  rs.getLong(13),
                  text(rs, 14),
                  text(rs, 15),
                  text(rs, 16)));
        }
      }
    }
    return out;
  }

  /** The number of binds of statement 3. */
  static final int STATEMENT_THREE_BINDS = 14;

  /**
   * The binds of statement 3 that take the login oid, one per branch (C-PR47-4); every other bind
   * takes the reach oids.
   */
  static final Set<Integer> STATEMENT_THREE_LOGIN_BINDS = Set.of(4, 7, 11, 14);

  /**
   * Statement 3: the caller objects (design revision 5, rule R6).
   *
   * @param loginOid the login role, whose usable rights decide {@code fnReach} (C-PR47-4)
   */
  static List<CallerFact> callers(Connection c, long[] reachOids, long loginOid)
      throws SQLException {
    var out = new ArrayList<CallerFact>();
    try (PreparedStatement ps = c.prepareStatement(statementThree())) {
      for (int i = 1; i <= STATEMENT_THREE_BINDS; i++) {
        if (STATEMENT_THREE_LOGIN_BINDS.contains(i)) {
          ps.setLong(i, loginOid);
        } else {
          ps.setArray(i, c.createArrayOf("oid", boxed(reachOids)));
        }
      }
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          out.add(
              new CallerFact(
                  text(rs, 1),
                  rs.getLong(2),
                  text(rs, 3),
                  rs.getLong(4),
                  text(rs, 5),
                  rs.getBoolean(6),
                  rs.getInt(7),
                  rs.getLong(8),
                  text(rs, 9),
                  text(rs, 10),
                  rs.getBoolean(11),
                  rs.getBoolean(12)));
        }
      }
    }
    return out;
  }

  /** A statement file, or {@code 005}: unverifiable is not clean. */
  static String resource(String name) {
    try (InputStream in = SchemaVerification.class.getResourceAsStream(name)) {
      if (in == null) {
        throw missing(name, null);
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw missing(name, e);
    }
  }

  private static ShreddingException missing(String name, IOException cause) {
    return new ShreddingException(
        ErrorCodes.SCHEMA_UNVERIFIABLE,
        "shredding: the statement file "
            + name
            + " of the function-grants check could not be read from this jar, so function grants"
            + " cannot be judged. Unverifiable is not clean.",
        cause);
  }

  private static String text(ResultSet rs, int column) throws SQLException {
    String value = rs.getString(column);
    return value == null ? "" : value;
  }

  private static Long[] boxed(long[] values) {
    var out = new Long[values.length];
    for (int i = 0; i < values.length; i++) {
      out[i] = values[i];
    }
    return out;
  }
}
