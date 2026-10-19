package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.application.LogText;

/**
 * The text of each function-grants finding (C-PR45-3, design section 5, "Messages"). Function
 * signatures, symbols, extension names and role names only: no secret is in any line.
 */
final class FunctionGrantMessages {

  private FunctionGrantMessages() {}

  static final String PROPERTY = "shredding.jdbc.accepted-third-party-extensions";

  /** A statement 2 row, for the grantee already named ("PUBLIC", "role R, reachable from ..."). */
  static String held(
      FunctionGrants.ExecuteRow row, String who, String grantee, PinnedCatalogue catalogue) {
    String fn = text(row.label());
    String head = who + " holds EXECUTE on function " + fn;
    return switch (row.leg()) {
      case 1 ->
          row.granteeOwns()
              ? who
                  + " owns function "
                  + fn
                  + ", which the server ships without EXECUTE for PUBLIC; an owner may always"
                  + " execute it. Give it back with ALTER FUNCTION "
                  + fn
                  + " OWNER TO the bootstrap superuser"
              : head
                  + ", which the server ships without EXECUTE for PUBLIC; revoke it with REVOKE"
                  + " EXECUTE ON FUNCTION "
                  + fn
                  + " FROM "
                  + text(grantee);
      case 2 ->
          head
              + ", which runs the same server code (symbol "
              + text(row.ref())
              + ") as "
              + text(row.sameAs())
              + ", which the server ships without EXECUTE for PUBLIC";
      case 3 -> head + ", native code that runs with the rights of its owner " + text(row.owner());
      case 4 ->
          head
              + ", native code created outside any extension. Revoke EXECUTE on it from PUBLIC and"
              + " from every role in reach; never ALTER EXTENSION ... ADD it (R5 refuses that too)";
      case 5 -> pinnedWithheld(row, head);
      default -> notAsShipped(row, head, catalogue);
    };
  }

  private static String pinnedWithheld(FunctionGrants.ExecuteRow row, String head) {
    if (row.sub() == 3) {
      return head
          + ", which has the name or runs the code (symbol "
          + text(row.ref())
          + ") of "
          + text(row.sameAs())
          + ", which PostgreSQL ships without EXECUTE for PUBLIC; the live record no longer says"
          + " so";
    }
    String[] m = row.ref().split("\t", -1);
    String line = m.length == 4 ? m[0] + " " + m[1] + " " + m[2] : text(row.ref());
    String symbol = m.length == 4 ? m[3] : "";
    if (row.sub() == 4) {
      return head
          + ", a member of extension "
          + text(row.extension())
          + " that the manifest has no record of, whose code (symbol "
          + text(symbol)
          + ") is what "
          + text(line)
          + " ships without EXECUTE for PUBLIC. Accepting the extension does not relax this:"
          + " revoke EXECUTE on it from PUBLIC and from every role in reach";
    }
    return head
        + ", which runs code that "
        + text(m.length == 4 ? m[0] + " " + m[1] : row.ref())
        + " ships without EXECUTE for PUBLIC (symbol "
        + text(symbol)
        + ", as "
        + text(m.length == 4 ? m[2] : "")
        + "); the live record no longer says so";
  }

  private static String notAsShipped(
      FunctionGrants.ExecuteRow row, String head, PinnedCatalogue catalogue) {
    String ext = text(row.extension());
    if (row.sub() == 1) {
      return head
          + ", a member of extension "
          + ext
          + " "
          + text(row.version())
          + " that the PostgreSQL "
          + catalogue.major()
          + " manifest does not list for that version (key, symbol or rights mode differ)";
    }
    if (catalogue.listedButNotInstallable(row.extension())) {
      return head
          + ", native code of extension "
          + ext
          + ", which the PostgreSQL "
          + catalogue.major()
          + " image lists but cannot install, so the manifest has no record of it; accept it with "
          + PROPERTY
          + " (limit L20)";
    }
    return head
        + ", native code of third-party extension "
        + ext
        + "; accept it with "
        + PROPERTY
        + " (limit L20)";
  }

  /** R1, R2, R4: the record DDL rewrote. {@code baseAcl} is the pinned ACL, or empty. */
  static String record(FunctionGrants.RecordRow row, int major, String baseAcl) {
    String fn = text(row.label().isEmpty() ? "oid " + row.oid() : row.label());
    return switch (row.rule()) {
      case "R1-missing" ->
          "the shipped record of function "
              + fn
              + " is missing; PostgreSQL "
              + major
              + " ships it without EXECUTE for PUBLIC ("
              + text(baseAcl)
              + ")";
      case "R1-changed" ->
          "the shipped record of function "
              + fn
              + " was changed after initdb (it reads "
              + text(row.detail())
              + "; PostgreSQL "
              + major
              + " ships "
              + text(baseAcl)
              + ")";
      case "R1-unknown" ->
          "function "
              + fn
              + " has an initdb record that PostgreSQL "
              + major
              + " does not ship ("
              + text(row.detail())
              + ")";
      case "R2" ->
          "the shipped record of function "
              + fn
              + " names PUBLIC or a role created after initdb ("
              + text(row.detail())
              + "); PostgreSQL ships no such record";
      default ->
          "the extension record of function "
              + fn
              + " grants EXECUTE to PUBLIC explicitly ("
              + text(row.detail())
              + "); a script that leaves the default records nothing, so this came from a GRANT"
              + " made before ALTER EXTENSION ... ADD";
    };
  }

  /** R0, a 005 line. */
  static String signature(FunctionGrants.RecordRow row, int major) {
    return "oid "
        + row.oid()
        + " is "
        + (row.label().isEmpty() ? "no function" : text(row.label()))
        + " on this server, the PostgreSQL "
        + major
        + " baseline expects "
        + text(row.detail())
        + ": this is not a build the module verified";
  }

  /** R5v, a 005 line, with the remedy that fits (C-PR45-3-14). */
  static String version(FunctionGrants.RecordRow row, PinnedCatalogue catalogue) {
    String[] ev = row.detail().split("\t", -1);
    String ext = text(ev[0]);
    String ver = text(ev.length > 1 ? ev[1] : "");
    String head =
        "extension "
            + ext
            + " is installed at version "
            + ver
            + ", which the PostgreSQL "
            + catalogue.major()
            + " manifest does not list (it lists "
            + String.join(", ", catalogue.installableVersions(ev[0]))
            + "); ";
    return row.updateSource()
        ? head
            + "update it with ALTER EXTENSION "
            + ext
            + " UPDATE ("
            + ver
            + " is an update source of a listed version, which this image cannot install"
            + " directly)"
        : head
            + "this release cannot tell which of its functions that version withholds. A module"
            + " release with that version in its manifest fixes it";
  }

  private static String text(String value) {
    return LogText.escape(value);
  }
}
