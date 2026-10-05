package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TableRef;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * What the catalogue leg of mapping admission needs to know about the application's mapping to
 * recognise a relation that holds a copy of a blind-index column (audit-table coverage design,
 * section 3, rows 10, 11 and 45): the audit and history tables the mapping itself names, and the
 * pairs of revision columns that mark a relation as one.
 *
 * <p>A relation outside the admitted table and its descendants that holds a column named as a
 * blind-index column is a copy when it is one of {@link #named()}, when it is named as Hibernate
 * Envers or Hibernate names the audit or history table of the admitted table by default ({@code
 * <table>_aud}, {@code <table>_AUD}, {@code <table>_history}, in the table's own schema), or when it
 * also holds both columns of one of {@link #signatures()}. Shape only, never contents.
 *
 * <p>The starter builds this from the persistence unit's own metamodel (Envers' and Hibernate's
 * configured names); a core-only user who maps no audit or history table passes {@link
 * #defaults()}. The same value is used at startup and inside every erasure, so both positions read
 * the same inputs.
 *
 * @param named audit or history tables the mapping names for an admitted table
 * @param signatures revision column pairs, as stored in {@code pg_attribute}
 */
public record CopySignatures(List<NamedCopy> named, List<RevisionSignature> signatures) {

  public CopySignatures {
    named = List.copyOf(named);
    signatures = List.copyOf(signatures);
  }

  /**
   * One audit or history table the mapping names.
   *
   * @param source the admitted table it copies
   * @param copy the audit or history table, exactly as the mapping renders it
   * @param writer who writes it, for messages ({@code Hibernate Envers}, {@code Hibernate})
   * @param kind {@code audit} or {@code history}
   */
  public record NamedCopy(TableRef source, TableRef copy, String writer, String kind) {
    public NamedCopy {
      Objects.requireNonNull(source, "source");
      Objects.requireNonNull(copy, "copy");
      requireText(writer, "writer");
      requireKind(kind);
    }
  }

  /**
   * Two columns that, together with a blind-index column, mark a relation as an audit or history
   * table.
   *
   * @param writer who writes such a table, for messages
   * @param kind {@code audit} or {@code history}
   * @param first a column name exactly as {@code pg_attribute} stores it
   * @param second the other column name, likewise
   */
  public record RevisionSignature(String writer, String kind, String first, String second) {
    public RevisionSignature {
      requireText(writer, "writer");
      requireKind(kind);
      requireText(first, "first");
      requireText(second, "second");
    }
  }

  /**
   * Hibernate Envers' and Hibernate's own default revision columns: {@code rev} and {@code revtype}
   * (Envers, and {@code @org.hibernate.annotations.Audited}'s {@code REV}/{@code REVTYPE}, which an
   * unquoted mapping stores in lower case), and {@code effective} and {@code superseded} ({@code
   * @org.hibernate.annotations.Temporal}). Each in both stored forms.
   */
  public static CopySignatures defaults() {
    return new CopySignatures(
        List.of(),
        List.of(
            new RevisionSignature("Hibernate Envers", "audit", "rev", "revtype"),
            new RevisionSignature("Hibernate Envers", "audit", "REV", "REVTYPE"),
            new RevisionSignature("Hibernate", "history", "effective", "superseded")));
  }

  /** These and {@code other}'s, without duplicates. */
  public CopySignatures plus(CopySignatures other) {
    var n = new ArrayList<>(named);
    other.named.stream().filter(x -> !n.contains(x)).forEach(n::add);
    var s = new ArrayList<>(signatures);
    other.signatures.stream().filter(x -> !s.contains(x)).forEach(s::add);
    return new CopySignatures(n, s);
  }

  private static void requireText(String value, String what) {
    if (value == null || value.isBlank()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG, "a copy signature's " + what + " must not be blank");
    }
  }

  private static void requireKind(String kind) {
    if (!"audit".equals(kind) && !"history".equals(kind)) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "a copy signature's kind must be \"audit\" or \"history\", was \"" + kind + "\"");
    }
  }
}
