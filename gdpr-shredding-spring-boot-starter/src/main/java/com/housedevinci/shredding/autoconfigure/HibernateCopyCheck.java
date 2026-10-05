package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.adapter.jdbc.CopySignatures;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TableRef;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.metamodel.mapping.AttributeMapping;
import org.hibernate.metamodel.mapping.AuditMapping;
import org.hibernate.metamodel.mapping.ForeignKeyDescriptor;
import org.hibernate.metamodel.mapping.PluralAttributeMapping;
import org.hibernate.metamodel.mapping.SelectableMapping;
import org.hibernate.metamodel.mapping.TemporalMapping;
import org.hibernate.metamodel.mapping.internal.ToOneAttributeMapping;
import org.hibernate.persister.entity.EntityPersister;

/**
 * The mapping leg of audit-table coverage (design section 3, rows 1-8, 13, 33-36, 43, 44): a copy
 * of a blind-index column that Hibernate itself writes, read from the runtime metamodel and never
 * from annotations, so {@code orm.xml}, package-level and meta-annotations are covered by the same
 * read. Keyed on the column, not on the {@code @BlindIndex} attribute (C6): the set of admitted
 * (table, column) pairs is built first, then every persister is walked.
 *
 * <p>Refused with {@code SHRED-SCHEMA-010}, at startup only (the metamodel cannot change after
 * boot; what it left on disk is the catalogue leg's, at every erasure):
 *
 * <ol>
 *   <li>an Envers audit entity writing an attribute whose source column is admitted ({@link
 *       EnversCopyCheck}, loaded only when Envers is on the classpath);
 *   <li>{@code @org.hibernate.annotations.Audited} writing an admitted column that is not {@code
 *       Audited.Excluded};
 *   <li>{@code @org.hibernate.annotations.Temporal} keeping history of an admitted table, in a
 *       history table without {@code Temporal.Excluded} on the column, or in the table itself;
 *   <li>a to-one or collection key whose target is an admitted column and whose key is in another
 *       table: that table holds index values with or without a database foreign key.
 * </ol>
 *
 * <p>It also returns what the catalogue leg must look for by name: the audit and history tables the
 * mapping names for each admitted table, and the revision columns the mapping configures, so a
 * table left behind by an earlier configuration is found at every erasure. An excluded column is
 * admitted here and the catalogue leg still refuses if the named table holds a column of its name.
 *
 * <p>Unverifiable is not clean: a call into Hibernate's incubating audit API, or into Envers, that
 * throws refuses with {@code SHRED-SCHEMA-005} (rows 13, 44).
 */
final class HibernateCopyCheck {

  private static final String ENVERS_SERVICE = "org.hibernate.envers.boot.internal.EnversService";

  private HibernateCopyCheck() {}

  /** One admitted blind-index column, and the attribute that maps it, for messages. */
  record Admitted(String entityName, String fieldName, TableRef table, String column) {
    String label() {
      return "@BlindIndex " + entityName + "." + fieldName;
    }

    String qualified() {
      return table + "." + column;
    }
  }

  /**
   * Refuses every mapped copy and returns what the catalogue leg must recognise by name.
   *
   * @param indexes the model's blind-index fields, already resolved against the metamodel
   */
  static CopySignatures check(
      SessionFactoryImplementor sessionFactory, List<ShreddedModel.BlindIndexField> indexes) {
    var admitted = new LinkedHashMap<String, Admitted>();
    for (ShreddedModel.BlindIndexField field : indexes) {
      BlindIndexColumn column = field.column();
      admitted.put(
          key(column.table().toString(), column.column().sql()),
          new Admitted(
              field.entityName(), field.fieldName(), column.table(), column.column().sql()));
    }
    if (admitted.isEmpty()) {
      return CopySignatures.defaults();
    }
    var findings = new LinkedHashSet<String>();
    var named = new ArrayList<CopySignatures.NamedCopy>();
    var signatures = new ArrayList<CopySignatures.RevisionSignature>();
    if (enversPresent()) {
      EnversCopyCheck.check(sessionFactory, admitted, findings, named, signatures);
    }
    try {
      sessionFactory
          .getMappingMetamodel()
          .forEachEntityDescriptor(
              persister -> {
                if (EnversCopyCheck.isAuditPersister(sessionFactory, persister, enversPresent())) {
                  return;
                }
                nativeAudit(persister, admitted, findings, named, signatures);
                temporal(persister, admitted, findings, named);
                associations(persister, admitted, findings);
              });
    } catch (ShreddingException e) {
      throw e;
    } catch (RuntimeException | LinkageError e) {
      throw unverifiable("Hibernate's audit and history metamodel", e);
    }
    if (!findings.isEmpty()) {
      throw new ShreddingException(ErrorCodes.BLIND_INDEX_COPIED, String.join(" ", findings));
    }
    return CopySignatures.defaults().plus(new CopySignatures(named, signatures));
  }

  static boolean enversPresent() {
    try {
      Class.forName(ENVERS_SERVICE, false, HibernateCopyCheck.class.getClassLoader());
      return true;
    } catch (ClassNotFoundException | LinkageError e) {
      return false;
    }
  }

  // ----------------------------------------------------------------------------- native audit

  private static void nativeAudit(
      EntityPersister persister,
      Map<String, Admitted> admitted,
      Set<String> findings,
      List<CopySignatures.NamedCopy> named,
      List<CopySignatures.RevisionSignature> signatures) {
    AuditMapping audit = persister.getAuditMapping();
    if (audit == null) {
      return;
    }
    String entity = ShreddedModel.simpleEntityName(persister.getEntityName());
    String primary = persister.getMappedTableDetails().getTableName();
    for (Admitted a : admitted.values()) {
      if (key(a.table().toString(), "").equals(key(primary, ""))) {
        named.add(
            new CopySignatures.NamedCopy(
                a.table(), table(audit.resolveTableName(primary)), "Hibernate", "audit"));
      }
    }
    signature(audit.getChangesetIdMapping(primary), audit.getModificationTypeMapping(primary))
        .ifPresent(signatures::add);
    persister.forEachAttributeMapping(
        attribute ->
            attribute.forEachSelectable(
                (i, selectable) -> {
                  Admitted a = admitted.get(key(selectable));
                  if (a == null
                      || persister.isPropertyAuditedExcluded(attribute.getStateArrayPosition())) {
                    return;
                  }
                  String copy = audit.resolveTableName(selectable.getContainingTableExpression());
                  String column = selectable.getSelectionExpression();
                  findings.add(
                      "shredding: Hibernate audits the blind-index column "
                          + a.qualified()
                          + " ("
                          + a.label()
                          + "): @org.hibernate.annotations.Audited on "
                          + entity
                          + " writes it into "
                          + copy
                          + " on every insert and update. An erasure clears "
                          + a.table()
                          + " only. Mark the field @Audited.Excluded, then clear the copies already"
                          + " written: "
                          + clear(copy, column));
                }));
  }

  private static Optional<CopySignatures.RevisionSignature> signature(
      SelectableMapping changeset, SelectableMapping type) {
    if (changeset == null || type == null) {
      return Optional.empty();
    }
    return Optional.of(
        new CopySignatures.RevisionSignature(
            "Hibernate",
            "audit",
            stored(changeset.getSelectionExpression()),
            stored(type.getSelectionExpression())));
  }

  // --------------------------------------------------------------------------------- temporal

  private static void temporal(
      EntityPersister persister,
      Map<String, Admitted> admitted,
      Set<String> findings,
      List<CopySignatures.NamedCopy> named) {
    TemporalMapping temporal = persister.getTemporalMapping();
    if (temporal == null) {
      return;
    }
    String entity = ShreddedModel.simpleEntityName(persister.getEntityName());
    String history = temporal.getTableName();
    String primary = persister.getMappedTableDetails().getTableName();
    persister.forEachAttributeMapping(
        attribute ->
            attribute.forEachSelectable(
                (i, selectable) -> {
                  Admitted a = admitted.get(key(selectable));
                  if (a == null) {
                    return;
                  }
                  if (history == null || history.equals(primary)) {
                    findings.add(
                        "shredding: Hibernate keeps history of "
                            + entity
                            + " inside "
                            + a.table()
                            + " itself (@Temporal, single-table strategy). Old versions of a row"
                            + " keep the blind-index column "
                            + a.column()
                            + " ("
                            + a.label()
                            + ") where this module's independent read-back cannot count them. Use"
                            + " the history-table strategy with the field @Temporal.Excluded, or"
                            + " remove @Temporal from "
                            + entity
                            + ".");
                    return;
                  }
                  named.add(
                      new CopySignatures.NamedCopy(
                          a.table(), table(history), "Hibernate", "history"));
                  if (persister.isPropertyTemporalExcluded(attribute.getStateArrayPosition())) {
                    return;
                  }
                  findings.add(
                      "shredding: Hibernate keeps history of "
                          + entity
                          + " in "
                          + history
                          + " (@Temporal, history-table strategy), which holds the blind-index"
                          + " column "
                          + a.column()
                          + " ("
                          + a.label()
                          + "). An erasure clears "
                          + a.table()
                          + " only. Mark the field @Temporal.Excluded, then clear the copies"
                          + " already written: "
                          + clear(history, selectable.getSelectionExpression()));
                }));
  }

  // ----------------------------------------------------------------------------- associations

  private static void associations(
      EntityPersister persister, Map<String, Admitted> admitted, Set<String> findings) {
    String entity = ShreddedModel.simpleEntityName(persister.getEntityName());
    persister.forEachAttributeMapping(
        attribute -> {
          ForeignKeyDescriptor fk = null;
          if (attribute instanceof ToOneAttributeMapping toOne) {
            fk = toOne.getForeignKeyDescriptor();
          } else if (attribute instanceof PluralAttributeMapping plural) {
            fk = plural.getKeyDescriptor();
          }
          if (fk != null) {
            reference(entity, attribute, fk, admitted, findings);
          }
        });
  }

  private static void reference(
      String entity,
      AttributeMapping attribute,
      ForeignKeyDescriptor fk,
      Map<String, Admitted> admitted,
      Set<String> findings) {
    String keyTable = fk.getKeyTable();
    if (keyTable == null || keyTable.equals(fk.getTargetTable())) {
      return;
    }
    var keys = new ArrayList<String>();
    fk.visitKeySelectables((i, selectable) -> keys.add(selectable.getSelectionExpression()));
    fk.visitTargetSelectables(
        (i, selectable) -> {
          Admitted a = admitted.get(key(selectable));
          if (a == null) {
            return;
          }
          String keyColumn = i < keys.size() ? keys.get(i) : "?";
          findings.add(
              "shredding: entity "
                  + entity
                  + " maps column "
                  + keyColumn
                  + " of "
                  + keyTable
                  + " as a reference to "
                  + a.qualified()
                  + ", the blind-index column of "
                  + a.entityName()
                  + " (attribute "
                  + entity
                  + "."
                  + attribute.getAttributeName()
                  + "). "
                  + keyTable
                  + " therefore holds index values, with or without a foreign key, and no erasure"
                  + " reaches it. Reference "
                  + a.entityName()
                  + " by its identifier instead.");
        });
  }

  // ---------------------------------------------------------------------------------- helpers

  static String key(SelectableMapping selectable) {
    return key(selectable.getContainingTableExpression(), selectable.getSelectionExpression());
  }

  /**
   * One key for one (table, column) pair however it is rendered: both sides go through {@link
   * TableRef#parse}, so {@code public.t} and {@code "public"."t"} agree. A table this module cannot
   * parse keeps its rendered text, which matches no admitted table, because an admitted table is
   * always one it parsed.
   */
  static String key(String table, String column) {
    String canonical;
    try {
      canonical = TableRef.parse(table).sql();
    } catch (ShreddingException e) {
      canonical = table;
    }
    return canonical + '\u0000' + column;
  }

  static String clear(String table, String column) {
    return "UPDATE "
        + table
        + " SET "
        + column
        + " = NULL; ALTER TABLE "
        + table
        + " DROP COLUMN "
        + column
        + ".";
  }

  /** A table the mapping renders, as the catalogue leg's name list needs it. */
  static TableRef table(String rendered) {
    try {
      return TableRef.parse(rendered);
    } catch (ShreddingException e) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "shredding: the audit or history table "
              + rendered
              + " that the mapping names cannot be checked for a copy of a blind-index column ("
              + e.getMessage()
              + "). Unverifiable is not clean, so this is a refusal.",
          e);
    }
  }

  /** A column name as {@code pg_attribute} stores it: unquoted names fold to lower case. */
  static String stored(String rendered) {
    if (rendered.length() > 1 && rendered.startsWith("\"") && rendered.endsWith("\"")) {
      return rendered.substring(1, rendered.length() - 1).replace("\"\"", "\"");
    }
    return rendered.toLowerCase(java.util.Locale.ROOT);
  }

  static ShreddingException unverifiable(String what, Throwable cause) {
    return new ShreddingException(
        ErrorCodes.SCHEMA_UNVERIFIABLE,
        "shredding: "
            + what
            + " could not be read ("
            + cause.getClass().getName()
            + "), so whether it copies a blind-index column is unknown. Unverifiable is not clean,"
            + " so this is a refusal.",
        cause);
  }
}
