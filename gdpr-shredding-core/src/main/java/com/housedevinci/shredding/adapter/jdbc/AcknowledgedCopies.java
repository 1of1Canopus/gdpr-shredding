package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.application.AcknowledgedCopy;
import com.housedevinci.shredding.application.LogText;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The acknowledgement list as a whole (audit-table coverage design, sections 2, 3c.5 and C8): each
 * entry must admit something now, at startup and at every erasure, or it refuses with {@code
 * SHRED-CONFIG-001}. An entry that grants nothing today is a silent grant tomorrow.
 *
 * <p>{@link MappingAdmission#verdict} decides per target which entries admitted a finding; an entry
 * that admitted none on any target is classified here, so the message says why: the object does not
 * exist (compared exactly as {@code pg_catalog} stores it), it is a trigger on a table this module
 * does not erase (an ancestor included: an ancestor is refused as a mapping before this runs, rule
 * R-i, and is never a family member), it is disabled, it is a partition clone, a publication that
 * does not publish {@code UPDATE} or carries no blind-index column, or a slot that is physical, in
 * another database, or uses {@code pgoutput}.
 */
public final class AcknowledgedCopies {

  private AcknowledgedCopies() {}

  /** The trigger an entry names, whatever table it is on. */
  static final String TRIGGER_SQL =
      "SELECT t.tgenabled,"
          + " (t.tgparentid OPERATOR(pg_catalog.<>) CAST(0 AS pg_catalog.oid)) AS clone"
          + " FROM pg_catalog.pg_trigger t"
          + " JOIN pg_catalog.pg_class c ON (c.oid OPERATOR(pg_catalog.=) t.tgrelid)"
          + " JOIN pg_catalog.pg_namespace n ON (n.oid OPERATOR(pg_catalog.=) c.relnamespace)"
          + " WHERE (NOT t.tgisinternal)"
          + " AND (CAST(n.nspname AS pg_catalog.text) OPERATOR(pg_catalog.=)"
          + " CAST(? AS pg_catalog.text))"
          + " AND (CAST(c.relname AS pg_catalog.text) OPERATOR(pg_catalog.=)"
          + " CAST(? AS pg_catalog.text))"
          + " AND (CAST(t.tgname AS pg_catalog.text) OPERATOR(pg_catalog.=)"
          + " CAST(? AS pg_catalog.text))";

  /** The publication an entry names. */
  static final String PUBLICATION_SQL =
      "SELECT p.pubupdate FROM pg_catalog.pg_publication p"
          + " WHERE (CAST(p.pubname AS pg_catalog.text) OPERATOR(pg_catalog.=)"
          + " CAST(? AS pg_catalog.text))";

  /** The slot an entry names. */
  static final String SLOT_SQL =
      "SELECT s.slot_type, s.plugin, pg_catalog.quote_ident(s.database) AS db,"
          + " (s.database OPERATOR(pg_catalog.=) pg_catalog.current_database()) AS here"
          + " FROM pg_catalog.pg_replication_slots s"
          + " WHERE (CAST(s.slot_name AS pg_catalog.text) OPERATOR(pg_catalog.=)"
          + " CAST(? AS pg_catalog.text))";

  /**
   * Refuses a list that names one object twice: two entries for one trigger would bind it to two
   * hooks, or bind it once and grant nothing with the other.
   *
   * @throws ShreddingException {@code SHRED-CONFIG-001}
   */
  public static void requireDistinct(List<AcknowledgedCopy> entries) {
    for (int i = 0; i < entries.size(); i++) {
      for (int j = 0; j < i; j++) {
        if (entries.get(i).object().equals(entries.get(j).object())) {
          throw new ShreddingException(
              ErrorCodes.CONFIG,
              "shredding: "
                  + AcknowledgedCopy.entry(i)
                  + " names "
                  + entries.get(i).printable()
                  + ", as "
                  + AcknowledgedCopy.entry(j)
                  + " does. Name each object once, with the one hook that clears it.");
        }
      }
    }
  }

  /**
   * One {@code SHRED-CONFIG-001} sentence per entry that is not in {@code used}, saying why it
   * admits nothing. Empty when every entry admitted a finding.
   *
   * @param used the positions of the entries some target's verdict admitted
   */
  public static List<String> unused(Connection c, List<AcknowledgedCopy> entries, Set<Integer> used)
      throws SQLException {
    var out = new ArrayList<String>();
    for (int i = 0; i < entries.size(); i++) {
      if (!used.contains(i)) {
        AcknowledgedCopy e = entries.get(i);
        out.add(
            "shredding: "
                + AcknowledgedCopy.entry(i)
                + " names "
                + e.printable()
                + ", which "
                + why(c, e));
      }
    }
    return out;
  }

  private static final String MISSING =
      "does not exist. Names are compared exactly as pg_catalog stores them (unquoted SQL names are"
          + " stored in lower case). Remove the entry or correct it.";

  private static final String GRANTS_NOTHING =
      " An entry that grants nothing now would grant silently later; remove it.";

  private static String why(Connection c, AcknowledgedCopy e) throws SQLException {
    return switch (e.kind()) {
      case TRIGGER -> {
        try (PreparedStatement ps = c.prepareStatement(TRIGGER_SQL)) {
          ps.setString(1, e.schema().orElseThrow());
          ps.setString(2, e.table().orElseThrow());
          ps.setString(3, e.name());
          try (ResultSet rs = ps.executeQuery()) {
            if (!rs.next()) {
              yield MISSING;
            }
            if ("D".equals(rs.getString("tgenabled"))) {
              yield "is disabled, so it grants nothing now." + GRANTS_NOTHING;
            }
            if (rs.getBoolean("clone")) {
              yield "is a partition's clone of a trigger on its parent table; this module reports"
                  + " the parent's trigger, so acknowledge that one instead.";
            }
            yield "is on "
                + LogText.escape(e.schema().orElseThrow())
                + "."
                + LogText.escape(e.table().orElseThrow())
                + ", which is not a table this module erases or a descendant of one."
                + GRANTS_NOTHING;
          }
        }
      }
      case PUBLICATION -> {
        try (PreparedStatement ps = c.prepareStatement(PUBLICATION_SQL)) {
          ps.setString(1, e.name());
          try (ResultSet rs = ps.executeQuery()) {
            if (!rs.next()) {
              yield MISSING;
            }
            yield rs.getBoolean("pubupdate")
                ? "does not publish any blind-index column." + GRANTS_NOTHING
                : "does not publish UPDATE, which cannot be acknowledged: a subscriber keeps every"
                    + " index value it received after every erasure. Publish UPDATE, or leave the"
                    + " index out of the publication's column list.";
          }
        }
      }
      case REPLICATION_SLOT -> {
        try (PreparedStatement ps = c.prepareStatement(SLOT_SQL)) {
          ps.setString(1, e.name());
          try (ResultSet rs = ps.executeQuery()) {
            if (!rs.next()) {
              yield MISSING;
            }
            if (!"logical".equals(rs.getString("slot_type"))) {
              yield "is a physical slot: a standby applies the erasure, so there is nothing to"
                  + " acknowledge."
                  + GRANTS_NOTHING;
            }
            if (!rs.getBoolean("here")) {
              yield "belongs to database "
                  + LogText.escape(String.valueOf(rs.getString("db")))
                  + ", not this one."
                  + GRANTS_NOTHING;
            }
            if ("pgoutput".equals(rs.getString("plugin"))) {
              yield "uses pgoutput, which decodes only what a publication carries; acknowledge the"
                  + " publication instead.";
            }
            yield "decodes no table this module erases with a blind-index column." + GRANTS_NOTHING;
          }
        }
      }
    };
  }
}
