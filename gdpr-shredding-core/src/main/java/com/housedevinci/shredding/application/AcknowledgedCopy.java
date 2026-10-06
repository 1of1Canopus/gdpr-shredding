package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * One acknowledged copy of a blind-index column (audit-table coverage design, sections 2 and 3c): a
 * trigger, a publication that publishes {@code UPDATE}, or a logical replication slot, which the
 * catalogue leg would otherwise refuse with {@code SHRED-SCHEMA-010}, admitted because the
 * application names the {@link PostErasureHook} that clears what it keeps.
 *
 * <p><b>Identifiers, not patterns.</b> {@code schema}, {@code table} and {@code name} are compared
 * with the values {@code pg_catalog} stores ({@code nspname}, {@code relname}, {@code tgname},
 * {@code pubname}, {@code slot_name}) by exact string equality: no case folding, no splitting on
 * dots, no wildcard. An unquoted SQL name is stored in lower case, so that is how it is written
 * here.
 *
 * <p><b>What an acknowledgement means.</b> The module keeps assuming the object copies the index.
 * It never inspects a trigger body, a subscriber or a CDC consumer, and it does not check what the
 * hook does. What it guarantees is the record: every erasure names every acknowledged object in a
 * pending outcome of its clearing hook, and is {@code COMPLETE} only once that hook has reported
 * success.
 *
 * @param kind what the object is
 * @param schema the trigger's table's schema; present for a trigger only
 * @param table the trigger's table; present for a trigger only
 * @param name the trigger, publication or slot name
 * @param clearedBy the {@link PostErasureHook#name()} of the hook that clears the copy
 */
public record AcknowledgedCopy(
    Kind kind, Optional<String> schema, Optional<String> table, String name, String clearedBy) {

  /** The objects an acknowledgement can name. Rules, views, keys and statistics only refuse. */
  public enum Kind {
    TRIGGER("trigger"),
    PUBLICATION("publication"),
    REPLICATION_SLOT("replication-slot");

    private final String label;

    Kind(String label) {
      this.label = label;
    }

    /** The configuration spelling, which is also how a record names the kind. */
    public String label() {
      return label;
    }

    /** The kind spelled exactly {@code label}, never case-folded. */
    public static Optional<Kind> of(String label) {
      for (Kind kind : values()) {
        if (kind.label.equals(label)) {
          return Optional.of(kind);
        }
      }
      return Optional.empty();
    }
  }

  /** The property every entry is configured under; a core user's list is indexed the same way. */
  public static final String PROPERTY = "shredding.jdbc.acknowledged-copies";

  public AcknowledgedCopy {
    Objects.requireNonNull(kind, "kind");
    Objects.requireNonNull(schema, "schema");
    Objects.requireNonNull(table, "table");
    validate("an acknowledged copy", kind, schema, table, name, clearedBy);
  }

  public static AcknowledgedCopy trigger(
      String schema, String table, String name, String clearedBy) {
    return new AcknowledgedCopy(
        Kind.TRIGGER, Optional.ofNullable(schema), Optional.ofNullable(table), name, clearedBy);
  }

  public static AcknowledgedCopy publication(String name, String clearedBy) {
    return new AcknowledgedCopy(
        Kind.PUBLICATION, Optional.empty(), Optional.empty(), name, clearedBy);
  }

  public static AcknowledgedCopy replicationSlot(String name, String clearedBy) {
    return new AcknowledgedCopy(
        Kind.REPLICATION_SLOT, Optional.empty(), Optional.empty(), name, clearedBy);
  }

  /**
   * Builds entry {@code index} of {@link #PROPERTY} from its configured strings, refusing with
   * {@code SHRED-CONFIG-001} and a message that names the entry.
   */
  public static AcknowledgedCopy of(
      int index, String kind, String schema, String table, String name, String clearedBy) {
    String entry = entry(index);
    Kind parsed =
        Kind.of(kind)
            .orElseThrow(
                () ->
                    refuse(
                        entry
                            + (kind == null || kind.isEmpty()
                                ? " has no kind"
                                : " has kind=" + LogText.escape(kind))
                            + "; kind is one of trigger, publication, replication-slot, written"
                            + " exactly so."));
    Optional<String> s = Optional.ofNullable(schema);
    Optional<String> t = Optional.ofNullable(table);
    validate(entry, parsed, s, t, name, clearedBy);
    return new AcknowledgedCopy(parsed, s, t, name, clearedBy);
  }

  /** {@code shredding.jdbc.acknowledged-copies[index]}, as every message names an entry. */
  public static String entry(int index) {
    return PROPERTY + "[" + index + "]";
  }

  private static void validate(
      String entry,
      Kind kind,
      Optional<String> schema,
      Optional<String> table,
      String name,
      String clearedBy) {
    if (kind == Kind.TRIGGER) {
      if (schema.isEmpty() || schema.get().isEmpty()) {
        throw refuse(
            entry
                + " has kind=trigger and no schema; a trigger is named by its table's"
                + " schema, its table and its own name.");
      }
      if (table.isEmpty() || table.get().isEmpty()) {
        throw refuse(
            entry
                + " has kind=trigger and no table; a trigger is named by its table's"
                + " schema, its table and its own name.");
      }
    } else if (schema.isPresent() || table.isPresent()) {
      String sets =
          schema.isPresent() && table.isPresent()
              ? "schema and table"
              : schema.isPresent() ? "schema" : "table";
      throw refuse(
          entry
              + " has kind="
              + kind.label()
              + " and sets "
              + sets
              + "; schema and table belong to kind=trigger only.");
    }
    if (name == null || name.isEmpty()) {
      throw refuse(entry + " has no name; it names the " + kind.label() + " it acknowledges.");
    }
    if (clearedBy == null || clearedBy.isBlank()) {
      throw refuse(
          entry
              + " has no cleared-by. An acknowledged copy needs the PostErasureHook that clears"
              + " it, or every erasure would be recorded COMPLETE over it.");
    }
  }

  private static ShreddingException refuse(String message) {
    return new ShreddingException(ErrorCodes.CONFIG, "shredding: " + message);
  }

  /**
   * The object as a record names it: the kind, then each identifier double-quoted with {@code "}
   * doubled, joined by dots, for example {@code trigger "public"."note"."note_audit"}. The exact
   * identifiers, never escaped: this text is hashed material.
   */
  public String object() {
    var parts = new ArrayList<String>();
    schema.ifPresent(parts::add);
    table.ifPresent(parts::add);
    parts.add(name);
    var quoted = new ArrayList<String>();
    for (String part : parts) {
      quoted.add('"' + part.replace("\"", "\"\"") + '"');
    }
    return kind.label() + " " + String.join(".", quoted);
  }

  /** {@link #object()} escaped for a log line or an exception message ({@link LogText}). */
  public String printable() {
    return LogText.escape(object());
  }

  /**
   * The objects of {@code copies} as a record names them, joined by {@code "; "}. Sorted here, by
   * kind in declaration order and then by schema, table and name compared code point by code point,
   * so two callers that reach the same set by different routes (the service from its store's list,
   * the store from what the catalogue leg admitted) render byte-identical text. The caller's order
   * is irrelevant and nothing is removed.
   */
  public static String describe(List<AcknowledgedCopy> copies) {
    var sorted = new ArrayList<>(copies);
    sorted.sort(ORDER);
    var out = new ArrayList<String>(sorted.size());
    for (AcknowledgedCopy copy : sorted) {
      out.add(copy.object());
    }
    return String.join("; ", out);
  }

  private static final Comparator<String> BY_CODE_POINT =
      (a, b) -> {
        int i = 0;
        int j = 0;
        while (i < a.length() && j < b.length()) {
          int ca = a.codePointAt(i);
          int cb = b.codePointAt(j);
          if (ca != cb) {
            return Integer.compare(ca, cb);
          }
          i += Character.charCount(ca);
          j += Character.charCount(cb);
        }
        return Integer.compare(a.length() - i, b.length() - j);
      };

  private static final Comparator<AcknowledgedCopy> ORDER =
      Comparator.comparing(AcknowledgedCopy::kind)
          .thenComparing(c -> c.schema().orElse(""), BY_CODE_POINT)
          .thenComparing(c -> c.table().orElse(""), BY_CODE_POINT)
          .thenComparing(AcknowledgedCopy::name, BY_CODE_POINT)
          .thenComparing(AcknowledgedCopy::clearedBy, BY_CODE_POINT);
}
