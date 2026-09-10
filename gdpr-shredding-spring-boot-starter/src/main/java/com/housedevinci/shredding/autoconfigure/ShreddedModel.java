package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TableRef;
import com.housedevinci.shredding.jpa.ShreddedConverter;
import jakarta.persistence.Cacheable;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityManagerFactory;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What the application declares: every {@code @Shredded} field, every {@code @BlindIndex} column,
 * and the checks that close the plaintext leak paths at startup rather than by convention (control
 * 12).
 *
 * <p>Built once, at bootstrap. Every failure here is a startup failure naming the field.
 */
public final class ShreddedModel {

  /** One shredded field: which entity, which attribute, and how to find its data subject. */
  public record ShreddedField(
      Class<?> entityClass,
      String entityName,
      String fieldName,
      SubjectExpression subject,
      boolean carriesSentinel,
      SubjectExpression tenant,
      TableRef table,
      String columnName,
      Field javaField,
      ShreddedConverter<?> converter) {

    /**
     * Design §1: {@code onPostLoad} installs the verified plaintext directly into the entity, so it
     * needs the reflective field as well as the persister's property index - the field is what the
     * placeholder is read back from to decide whether a converter ran on this row at all.
     */
    public ShreddedField {
      java.util.Objects.requireNonNull(javaField, "javaField");
      java.util.Objects.requireNonNull(converter, "converter");
      java.util.Objects.requireNonNull(table, "table");
    }

    /**
     * The same field, addressed at the table the persister maps rather than at the name derived
     * from {@code @Table(name = ...)} (design addendum 3, change 9, applied §3.9b).
     */
    ShreddedField at(TableRef resolvedTable) {
      return new ShreddedField(
          entityClass,
          entityName,
          fieldName,
          subject,
          carriesSentinel,
          tenant,
          resolvedTable,
          columnName,
          javaField,
          converter);
    }
  }

  /** One blind-index column and the shredded field it indexes. */
  public record BlindIndexField(
      Class<?> entityClass,
      String entityName,
      String fieldName,
      String ofFieldName,
      Field javaField,
      BlindIndexColumn column) {}

  private final List<ShreddedField> shreddedFields;
  private final List<BlindIndexField> blindIndexFields;

  private ShreddedModel(
      List<ShreddedField> shreddedFields, List<BlindIndexField> blindIndexFields) {
    this.shreddedFields = List.copyOf(shreddedFields);
    this.blindIndexFields = List.copyOf(blindIndexFields);
  }

  public List<ShreddedField> shreddedFields() {
    return shreddedFields;
  }

  public List<BlindIndexField> blindIndexFields() {
    return blindIndexFields;
  }

  public List<BlindIndexColumn> blindIndexColumns() {
    return blindIndexFields.stream().map(BlindIndexField::column).toList();
  }

  public int entityCount() {
    return (int) shreddedFields.stream().map(ShreddedField::entityName).distinct().count();
  }

  public int fieldCount() {
    return shreddedFields.size();
  }

  /** Fields whose type has no value that can stand for "erased" (QUESTIONS #5). */
  public List<String> fieldsWithoutSentinel() {
    return shreddedFields.stream()
        .filter(f -> !f.carriesSentinel())
        .map(f -> f.entityName() + "." + f.fieldName())
        .toList();
  }

  public Map<String, List<ShreddedField>> byEntityName() {
    var map = new LinkedHashMap<String, List<ShreddedField>>();
    shreddedFields.forEach(f -> map.computeIfAbsent(f.entityName(), k -> new ArrayList<>()).add(f));
    return map;
  }

  public Map<String, List<BlindIndexField>> blindIndexesByEntityName() {
    var map = new LinkedHashMap<String, List<BlindIndexField>>();
    blindIndexFields.forEach(
        f -> map.computeIfAbsent(f.entityName(), k -> new ArrayList<>()).add(f));
    return map;
  }

  /**
   * @param entities the persistence unit's entity classes
   * @param allowSecondLevelCache the escape hatch for {@code @Cacheable} entities (control 12)
   */
  public static ShreddedModel scan(Collection<Class<?>> entities, boolean allowSecondLevelCache) {
    return scan(entities, allowSecondLevelCache, Map.of(), null);
  }

  /**
   * @param entities the persistence unit's entity classes
   * @param allowSecondLevelCache the escape hatch for {@code @Cacheable} entities (control 12)
   * @param emfProperties the {@code EntityManagerFactory}'s resolved properties, so a global {@code
   *     jakarta.persistence.sharedCache.mode} or {@code hibernate.cache.use_query_cache} setting is
   *     caught even when no entity carries {@code @Cacheable} or {@code @Cache} at all (CIPHER-09):
   *     {@code sharedCache.mode=ALL} (and {@code DISABLE_SELECTIVE}, which behaves the same way
   *     unless a type opts out) caches <em>every</em> entity regardless of any annotation, and the
   *     query cache is control 12's second half ("Query cache likewise"), which nothing in the
   *     module looked at before this.
   *     <p>No reverse metamodel check (C-19): callers that have no real {@code
   *     EntityManagerFactory} to walk - this module's own unit tests among them - get the
   *     field-level scan only. Prefer the four-argument overload when a real factory is available.
   */
  public static ShreddedModel scan(
      Collection<Class<?>> entities,
      boolean allowSecondLevelCache,
      Map<String, Object> emfProperties) {
    return scan(entities, allowSecondLevelCache, emfProperties, null);
  }

  /**
   * @param entities the persistence unit's entity classes
   * @param allowSecondLevelCache the escape hatch for {@code @Cacheable} entities (control 12)
   * @param emfProperties the {@code EntityManagerFactory}'s resolved properties, so a global {@code
   *     jakarta.persistence.sharedCache.mode} or {@code hibernate.cache.use_query_cache} setting is
   *     caught even when no entity carries {@code @Cacheable} or {@code @Cache} at all (CIPHER-09)
   * @param entityManagerFactory C-19: the reverse check. {@code null} skips it (the three-argument
   *     overload's callers have no real factory to walk). The forward scan below only ever looks
   *     for {@code @Shredded} on a <em>field</em>; a column mapped through a class-level
   *     {@code @Convert(attributeName = ...)} or an {@code orm.xml} mapping is fully encrypted by
   *     the write path (whichever properly-annotated field put the entity in the model pushed the
   *     write scope for the whole state array) and completely unchecked on read - {@code
   *     onPostLoad} never drains it because it is not in {@code fields}, and neither the
   *     {@code @Immutable} check nor the second-level-cache refusal ever sees it. The reverse check
   *     walks the Hibernate metamodel for every attribute whose JPA converter is a {@link
   *     ShreddedConverter}, by whatever route it got there, and refuses startup on any that has no
   *     matching field-level {@code @Shredded} entry.
   */
  public static ShreddedModel scan(
      Collection<Class<?>> entities,
      boolean allowSecondLevelCache,
      Map<String, Object> emfProperties,
      EntityManagerFactory entityManagerFactory) {
    var shredded = new ArrayList<ShreddedField>();
    var indexes = new ArrayList<BlindIndexField>();
    String sharedCacheMode =
        String.valueOf(emfProperties.get("jakarta.persistence.sharedCache.mode"));
    boolean globalCacheAll =
        "ALL".equals(sharedCacheMode) || "DISABLE_SELECTIVE".equals(sharedCacheMode);
    boolean queryCacheOn =
        "true"
            .equalsIgnoreCase(String.valueOf(emfProperties.get("hibernate.cache.use_query_cache")));
    if (queryCacheOn && !allowSecondLevelCache) {
      throw config(
          "hibernate.cache.use_query_cache=true is set. The query cache can return decrypted"
              + " @Shredded values from a cached query result after the subject's key is"
              + " destroyed, exactly like the second-level cache (control 12). Turn it off, or set"
              + " shredding.allow-second-level-cache=true and accept that residual in writing.");
    }

    for (Class<?> type : entities) {
      String entityName = entityName(type);
      var shreddedHere = new ArrayList<String>();
      var shreddedFieldsHere = new ArrayList<ShreddedField>();

      for (Field field : allFields(type)) {
        Shredded annotation = field.getAnnotation(Shredded.class);
        if (annotation == null) {
          continue;
        }
        String where = entityName + "." + field.getName();
        if (Modifier.isStatic(field.getModifiers())) {
          throw config("@Shredded on " + where + " must be an instance field");
        }
        ShreddedConverter<?> converter = requireMatchingConverter(field, entityName, where);
        // CIPHER-16: a byte[] attribute is mutable by Hibernate's own reckoning, so without
        // @Immutable, AttributeConverterMutabilityPlan deep-copies the converted value - calling
        // convertToDatabaseColumn a second time, outside the onPreInsert/onPostInsert bracket - to
        // build the entity's dirty-checking snapshot. Under @GeneratedValue(IDENTITY) that second
        // call has no write scope and refuses the row's own first insert. Checked at startup,
        // naming the field, rather than surfacing as SHRED-CONTEXT-001 on whichever row happens to
        // be inserted first.
        if (byte[].class.equals(field.getType())
            && !hasAnnotation(field, "org.hibernate.annotations.Immutable")) {
          throw config(
              "@Shredded on "
                  + where
                  + " is a byte[] field with no @org.hibernate.annotations.Immutable. Hibernate"
                  + " treats byte[] as mutable and deep-copies the *converted* value to build its"
                  + " dirty-checking snapshot, which calls the converter a second time outside the"
                  + " write bracket and fails an IDENTITY-strategy insert with SHRED-CONTEXT-001."
                  + " Add @Immutable to the field - but know what it costs (C-21, README.md,"
                  + " docs/index.md): @Immutable is what stops that second, out-of-bracket deep"
                  + " copy, and the deep copy it stops is also what Hibernate's dirty checking"
                  + " compares the live array against. With no snapshot copy, an in-place mutation"
                  + " of the array this field holds (b.getPayload()[0] = x) is compared against"
                  + " itself and is never seen as dirty: no exception, no log line, no UPDATE. The"
                  + " only way to change a @Shredded byte[] field once @Immutable is present is to"
                  + " assign it a whole new array (setPayload(newArray)), never to mutate the one"
                  + " already there.");
        }
        var shreddedField =
            new ShreddedField(
                type,
                entityName,
                field.getName(),
                new SubjectExpression(where, annotation.subject()),
                converter.carriesSentinel(),
                annotation.tenant().isBlank()
                    ? null
                    : new SubjectExpression(where, annotation.tenant()),
                // Provisional: replaced by the persister's own table in resolveTables below
                // (change 9, §3.9b). It survives only for a model scanned without an
                // EntityManagerFactory, which builds no SQL.
                TableRef.of(tableName(type)),
                columnName(field),
                accessible(field),
                converter);
        shredded.add(shreddedField);
        shreddedFieldsHere.add(shreddedField);
        shreddedHere.add(field.getName());
      }

      // CIPHER-14's @SecondaryTable refusal used to live here, comparing tableName(type) with
      // itself - one value per entity, so distinct().count() was always 1 and it could never fire
      // (change 9, §3.9c). It is now in refuseSecondaryTableSplit, against the containing table of
      // each field's own mapping, which is what it always meant to say.

      for (Field field : allFields(type)) {
        BlindIndex annotation = field.getAnnotation(BlindIndex.class);
        if (annotation == null) {
          continue;
        }
        String where = entityName + "." + field.getName();
        if (!byte[].class.equals(field.getType())) {
          throw config("@BlindIndex on " + where + " must be a byte[] field");
        }
        if (!shreddedHere.contains(annotation.of())) {
          throw config(
              "@BlindIndex on "
                  + where
                  + " names of=\""
                  + annotation.of()
                  + "\", which is not a @Shredded field of "
                  + entityName);
        }
        // S-7 / S-13, design addendum 3 change 4 (applied §3.4): the of-field may declare its own
        // @Shredded(tenant = ...) again. The seventh pass refused that shape at startup because
        // the module could not prove, at scan time, that the declared tenant would ever equal the
        // value in tenantColumn - the value the erasure matches on. It is no longer guessed at
        // scan time: writeBlindIndexes refuses the write, per row, when the two disagree, so the
        // shape is allowed exactly when it is erasable. See ShreddingEventListener.
        field.setAccessible(true);
        indexes.add(
            new BlindIndexField(
                type,
                entityName,
                field.getName(),
                annotation.of(),
                field,
                // Design addendum 3 change 1 (applied §3.1): tenantColumn is a column name, and
                // the property it maps to is resolved below, from the entity's own column mapping.
                BlindIndexColumn.unresolved(
                    TableRef.of(tableName(type)),
                    columnName(field),
                    annotation.subjectColumn(),
                    annotation.tenantColumn())));
      }

      if (!shreddedHere.isEmpty()) {
        refuseSecondLevelCache(type, entityName, allowSecondLevelCache, globalCacheAll);
        refuseGeneratedRendering(type, entityName);
      }
    }

    if (entityManagerFactory != null) {
      var known = new HashSet<String>();
      var shreddedFieldNamesByEntity = new LinkedHashMap<String, Set<String>>();
      for (var field : shredded) {
        known.add(field.entityName() + "." + field.fieldName());
        shreddedFieldNamesByEntity
            .computeIfAbsent(field.entityName(), k -> new HashSet<>())
            .add(field.fieldName());
      }
      refuseUnmodelledShreddedConverters(entityManagerFactory, known);
      refuseIfShreddedFieldUnmodelled(entityManagerFactory, shredded);
      refuseCompositeIdShreddedEntities(entityManagerFactory, shreddedFieldNamesByEntity);
      resolveTables(entityManagerFactory, shredded, indexes);
      resolveIndexColumns(entityManagerFactory, indexes);
    }

    return new ShreddedModel(shredded, indexes);
  }

  /**
   * C-19. Walks the Hibernate runtime metamodel - not the field scan above - for every attribute
   * whose resolved JPA converter is a {@link ShreddedConverter}, however it got there (field-level
   * {@code @Convert}, a class-level {@code @Convert(attributeName = ...)}, an {@code orm.xml}
   * mapping). Any such attribute with no matching entry in {@code known} is a column that is fully
   * encrypted and completely unverified: refused here, at startup, naming the entity and attribute,
   * rather than left for CIPHER's own {@code Ledger.secret} repro to find on a live row.
   */
  /**
   * Design addendum 3, change 1 (applied §3.1). {@code @BlindIndex(tenantColumn = "tenant_id")}
   * names the <em>column</em> the erasure's {@code UPDATE ... WHERE tenant_id = ?} matches on. The
   * state array the write path reads, and {@code EntityPersister.getPropertyNames()}, are keyed by
   * <em>property</em> name ({@code tenantId}). Resolving one as if it were the other would either
   * refuse every correct configuration or, worse, miss and derive the index under something
   * unstated - so the column is resolved to a property here, through the entity's own column
   * mapping, once, at startup.
   *
   * <p>The resolution must yield exactly one property that is basic, {@code String}-typed, mapped
   * to the entity's primary table (the table the erasure updates), not a formula, not the
   * identifier and not itself encrypted. Anything else is refused, naming the entity, the index
   * field, the annotation attribute and what was found. Change 2: the result is stored on the
   * {@link BlindIndexColumn} beside the column it came from, so the write path and the erasure path
   * read one object rather than two independently computed values.
   *
   * <p><b>Change 8 (applied §3.8a, §3.8b).</b> {@code subjectColumn} is resolved here too, by the
   * same method under the same rules. S-20 was S-13 one column over precisely because these rules
   * were written for one axis and never applied to the other; {@link Axis} is what keeps them from
   * drifting apart again.
   */
  private static void resolveIndexColumns(
      EntityManagerFactory entityManagerFactory, List<BlindIndexField> indexes) {
    if (indexes.isEmpty()) {
      return;
    }
    var byEntityName = persistersByEntityName(entityManagerFactory);
    for (int i = 0; i < indexes.size(); i++) {
      BlindIndexField index = indexes.get(i);
      String where = index.entityName() + "." + index.fieldName();
      var persister = byEntityName.get(index.entityName());
      if (persister == null) {
        throw config(
            "@BlindIndex on "
                + where
                + " is declared on a class Hibernate's mapping metamodel does not know as an"
                + " entity, so its tenantColumn=\""
                + index.column().tenantColumn()
                + "\" and subjectColumn=\""
                + index.column().subjectColumn()
                + "\" cannot be resolved to the properties the write path reads.");
      }
      indexes.set(
          i,
          new BlindIndexField(
              index.entityClass(),
              index.entityName(),
              index.fieldName(),
              index.ofFieldName(),
              index.javaField(),
              index
                  .column()
                  .resolvedTo(
                      resolveAxisProperty(persister, index, where, Axis.TENANT),
                      resolveAxisProperty(persister, index, where, Axis.SUBJECT))));
    }
  }

  /**
   * Design addendum 3, change 9 (applied §3.9b). Every statement this module builds for a user
   * table is addressed at the table the persister maps - schema and all - rather than at a name
   * derived from {@code @Table(name = ...)}, which ignores {@code schema} and leaves the runtime
   * connection's {@code search_path} to decide which table is hit (S-21). The entity's own primary
   * table comes from the persister; each field's containing table comes from its attribute mapping,
   * which is also what makes the {@code @SecondaryTable} refusal below real.
   */
  private static void resolveTables(
      EntityManagerFactory entityManagerFactory,
      List<ShreddedField> shredded,
      List<BlindIndexField> indexes) {
    var byEntityName = persistersByEntityName(entityManagerFactory);
    var primaryTables = new LinkedHashMap<String, TableRef>();
    for (var entry : byEntityName.entrySet()) {
      primaryTables.put(entry.getKey(), primaryTable(entry.getValue()));
    }
    for (int i = 0; i < shredded.size(); i++) {
      ShreddedField field = shredded.get(i);
      TableRef primary = primaryTables.get(field.entityName());
      if (primary == null) {
        continue; // an entity Hibernate does not map; other checks refuse it by their own reasons
      }
      refuseSecondaryTableSplit(byEntityName.get(field.entityName()), field, primary);
      shredded.set(i, field.at(primary));
    }
    for (int i = 0; i < indexes.size(); i++) {
      BlindIndexField index = indexes.get(i);
      TableRef primary = primaryTables.get(index.entityName());
      if (primary == null) {
        continue; // resolveIndexColumns refuses it, naming the entity
      }
      indexes.set(
          i,
          new BlindIndexField(
              index.entityClass(),
              index.entityName(),
              index.fieldName(),
              index.ofFieldName(),
              index.javaField(),
              index.column().at(primary)));
    }
  }

  /**
   * CIPHER-14, rebuilt on the mapping rather than on the annotation (change 9, §3.9c). {@code
   * refuseIfSubjectMoved} and the post-hoc header read-back both read every shredded column of an
   * entity from its one primary table in a single query. A field mapped to a secondary table
   * ({@code @SecondaryTable} / {@code @Column(table = ...)}) would be checked against the wrong
   * table's row or make the query fail outright, so the mapping is refused at startup. The previous
   * form of this check compared {@code tableName(type)} with itself and could never fire.
   */
  private static void refuseSecondaryTableSplit(
      org.hibernate.persister.entity.EntityPersister persister,
      ShreddedField field,
      TableRef primary) {
    var attribute = persister.findAttributeMapping(field.fieldName());
    if (!(attribute instanceof org.hibernate.metamodel.mapping.BasicValuedModelPart basic)) {
      return; // refuseIfShreddedFieldUnmodelled has already refused this shape by its own reason
    }
    TableRef containing = TableRef.parse(basic.getContainingTableExpression());
    if (!containing.equals(primary)) {
      throw config(
          field.entityName()
              + "."
              + field.fieldName()
              + " is @Shredded and mapped onto the table "
              + containing
              + ", which is not "
              + field.entityName()
              + "'s primary table "
              + primary
              + " (a @SecondaryTable or @Column(table=...) mapping). The update-time"
              + " subject-immutability check reads every shredded column of an entity from its one"
              + " primary table in a single query; a field mapped to a secondary table cannot be"
              + " checked that way and is refused rather than silently skipped or checked against"
              + " the wrong table's row.");
    }
  }

  private static TableRef primaryTable(org.hibernate.persister.entity.EntityPersister persister) {
    return TableRef.parse(persister.getMappedTableDetails().getTableName());
  }

  private static LinkedHashMap<String, org.hibernate.persister.entity.EntityPersister>
      persistersByEntityName(EntityManagerFactory entityManagerFactory) {
    var sessionFactory =
        entityManagerFactory.unwrap(org.hibernate.engine.spi.SessionFactoryImplementor.class);
    var byEntityName = new LinkedHashMap<String, org.hibernate.persister.entity.EntityPersister>();
    sessionFactory
        .getMappingMetamodel()
        .forEachEntityDescriptor(
            persister -> byEntityName.put(simpleEntityName(persister.getEntityName()), persister));
    return byEntityName;
  }

  /**
   * The two axes of a blind index. One resolver, parameterised, so change 1's rules and change 8's
   * rules cannot drift apart: S-20 exists because they were written once and applied to one axis.
   */
  private enum Axis {
    TENANT("tenantColumn", "tenant", "TenantId"),
    SUBJECT("subjectColumn", "subject", "SubjectId");

    private final String attribute;
    private final String noun;
    private final String type;

    Axis(String attribute, String noun, String type) {
      this.attribute = attribute;
      this.noun = noun;
      this.type = type;
    }

    String column(BlindIndexColumn column) {
      return this == TENANT ? column.tenantColumn() : column.subjectColumn();
    }
  }

  private static String resolveAxisProperty(
      org.hibernate.persister.entity.EntityPersister persister,
      BlindIndexField index,
      String where,
      Axis axis) {
    String wanted = axis.column(index.column());
    var matches =
        new java.util.LinkedHashMap<String, org.hibernate.metamodel.mapping.BasicValuedModelPart>();
    var nested = new ArrayList<String>();
    persister
        .getAttributeMappings()
        .forEach(
            attribute ->
                collectColumnMatches(
                    attribute.getAttributeName(), attribute, wanted, matches, nested));
    String prefix =
        "@BlindIndex on " + where + " names " + axis.attribute + "=\"" + wanted + "\", which ";
    if (matches.size() > 1) {
      throw config(
          prefix
              + "the mapping of "
              + index.entityName()
              + " resolves to more than one property ("
              + String.join(", ", matches.keySet())
              + "). The write path has to read one value out of the state array for the column the"
              + " erasure matches on; two properties over one column give it no single answer.");
    }
    if (matches.isEmpty()) {
      var identifier = persister.getIdentifierMapping();
      if (identifier instanceof org.hibernate.metamodel.mapping.BasicValuedModelPart id
          && unquote(id.getSelectionExpression()).equals(wanted)) {
        // Change 8 (§3.8a) decides the case Cipher left open on the subject axis, and it is the
        // same answer the tenant axis already gave, for one more reason: the identifier is not in
        // the state array the write path reads, under GenerationType.IDENTITY it does not exist at
        // all when onPreInsert derives the index, and a SubjectId is a string while an identifier
        // is as often a Long, a UUID or a byte[] - so the equality this check exists to make would
        // need a rendering this module would have to invent, which is the same class of guess as a
        // guessed row binding.
        throw config(
            prefix
                + "is the identifier column of "
                + index.entityName()
                + ". The identifier is not part of the state array the write path reads - and"
                + " under GenerationType.IDENTITY it does not exist yet when the index is derived"
                + " - so the "
                + axis.noun
                + " the index is derived under could not be read from the row being written."
                + " Map the "
                + axis.noun
                + " as an ordinary basic String property beside the identifier and name that"
                + " property's column.");
      }
      if (!nested.isEmpty()) {
        throw config(
            prefix
                + "is mapped only inside an @Embeddable or an @ElementCollection of "
                + index.entityName()
                + " ("
                + String.join(", ", nested)
                + "). The write path reads the "
                + axis.noun
                + " out of the entity's own top-level state array; a component's attribute is not"
                + " there. Map the "
                + axis.noun
                + " column as a top-level basic property of the entity.");
      }
      throw config(
          prefix
              + "no property of "
              + index.entityName()
              + " maps to. "
              + axis.attribute
              + " is a column name, not a property name: it must name the column the erasure's"
              + " UPDATE matches on, and that column must be mapped by a basic String property of"
              + " this entity so the write path can read the value the index is derived under out"
              + " of the row being written.");
    }
    var entry = matches.entrySet().iterator().next();
    String property = entry.getKey();
    var basic = entry.getValue();
    if (basic.isFormula()) {
      throw config(
          prefix
              + "is mapped by the @Formula property "
              + index.entityName()
              + "."
              + property
              + ". A formula is computed by the database on read and has no column the erasure can"
              + " match on.");
    }
    TableRef table = TableRef.parse(basic.getContainingTableExpression());
    if (!table.equals(index.column().table())) {
      throw config(
          prefix
              + "is mapped by "
              + index.entityName()
              + "."
              + property
              + " onto the table "
              + table
              + ", not onto "
              + index.column().table()
              + " - the table the erasure's UPDATE names. A "
              + axis.noun
              + " column on a secondary table cannot be matched by that statement.");
    }
    Class<?> javaType = basic.getJavaType().getJavaTypeClass();
    if (!String.class.equals(javaType)) {
      throw config(
          prefix
              + "is mapped by "
              + index.entityName()
              + "."
              + property
              + ", whose type is "
              + javaType.getName()
              + " and not java.lang.String. The "
              + axis.noun
              + " an index is derived under is a "
              + axis.type
              + ", which is a string; a value of any other type could not be compared with the one"
              + " the erasure was asked for.");
    }
    var converter = basic.getSingleJdbcMapping().getValueConverter();
    if (converter
            instanceof org.hibernate.type.descriptor.converter.spi.JpaAttributeConverter<?, ?> jpa
        && jpa.getConverterBean().getBeanInstance() instanceof ShreddedConverter<?>) {
      throw config(
          prefix
              + "is mapped by "
              + index.entityName()
              + "."
              + property
              + ", which is itself @Shredded. The erasure matches the stored column value, which"
              + " for an encrypted column is ciphertext that changes on every write, so no index"
              + " derived under the plaintext could ever be reached by it.");
    }
    if (indexOfProperty(persister.getPropertyNames(), property) < 0) {
      throw config(
          prefix
              + "resolves to "
              + index.entityName()
              + "."
              + property
              + ", which is not one of the entity's own persistent properties, so the write path"
              + " cannot read its value out of the state array.");
    }
    return property;
  }

  private static void collectColumnMatches(
      String path,
      org.hibernate.metamodel.mapping.ModelPart part,
      String wanted,
      Map<String, org.hibernate.metamodel.mapping.BasicValuedModelPart> matches,
      List<String> nested) {
    if (part instanceof org.hibernate.metamodel.mapping.BasicValuedModelPart basic) {
      if (unquote(basic.getSelectionExpression()).equals(wanted)) {
        if (path.indexOf('.') < 0 && path.indexOf('[') < 0) {
          matches.put(path, basic);
        } else {
          nested.add(path);
        }
      }
      return;
    }
    if (part instanceof org.hibernate.metamodel.mapping.EmbeddableValuedModelPart embeddable) {
      embeddable
          .getEmbeddableTypeDescriptor()
          .getAttributeMappings()
          .forEach(
              attribute ->
                  collectColumnMatches(
                      path + "." + attribute.getAttributeName(),
                      attribute,
                      wanted,
                      matches,
                      nested));
      return;
    }
    if (part instanceof org.hibernate.metamodel.mapping.PluralAttributeMapping plural) {
      collectColumnMatches(path + "[]", plural.getElementDescriptor(), wanted, matches, nested);
    }
  }

  private static String unquote(String identifier) {
    String trimmed = identifier == null ? "" : identifier.trim();
    if (trimmed.length() > 1) {
      char first = trimmed.charAt(0);
      char last = trimmed.charAt(trimmed.length() - 1);
      if ((first == '"' && last == '"') || (first == '`' && last == '`')) {
        trimmed = trimmed.substring(1, trimmed.length() - 1);
      }
    }
    return trimmed.toLowerCase(java.util.Locale.ROOT);
  }

  private static int indexOfProperty(String[] names, String name) {
    for (int i = 0; i < names.length; i++) {
      if (names[i].equals(name)) {
        return i;
      }
    }
    return -1;
  }

  private static Field accessible(Field field) {
    field.setAccessible(true);
    return field;
  }

  private static void refuseUnmodelledShreddedConverters(
      EntityManagerFactory entityManagerFactory, Set<String> known) {
    var sessionFactory =
        entityManagerFactory.unwrap(org.hibernate.engine.spi.SessionFactoryImplementor.class);
    var mappingMetamodel = sessionFactory.getMappingMetamodel();
    mappingMetamodel.forEachEntityDescriptor(
        persister -> {
          // Hibernate's own persister entity name is the fully qualified class name unless
          // @Entity(name=...) overrides it; the model above always keys on the simple name (or the
          // @Entity name), the same convention ShreddingEventListener.entityName() uses on the
          // write path - matched here so the two never disagree about which entity a key names.
          String entityName = simpleEntityName(persister.getEntityName());
          scanAttributeMappings(entityName, entityName, persister.getAttributeMappings(), known);
        });
  }

  /**
   * S-5 (Cipher sixth pass). The forward direction of the C-19 check: for every field-level
   * {@code @Shredded} the class scan above found, the metamodel attribute of that name must resolve
   * to that field's own declared {@code ShreddedConverter}. This is the case C-19's reverse check
   * cannot catch: {@code @Access(AccessType.PROPERTY)} moves the mapping to the getters, so
   * Hibernate ignores every field-level annotation - the {@code @Convert} among them - and the
   * metamodel attribute has no converter at all. The forward scan above still reads
   * {@code @Shredded} off the field and accepts the mapping; nothing before this checked that
   * Hibernate actually applied the converter it names. Without it, the column starts as a plain,
   * unconverted varchar, caught only on the first write by the post-hoc header check (item 14) with
   * a message that names neither the entity nor the field - unlike every other mapping this module
   * cannot protect (composite id, {@code @SecondaryTable} split, {@code byte[]} without
   * {@code @Immutable}), which is refused here, at startup, naming both.
   */
  private static void refuseIfShreddedFieldUnmodelled(
      EntityManagerFactory entityManagerFactory, List<ShreddedField> shredded) {
    var sessionFactory =
        entityManagerFactory.unwrap(org.hibernate.engine.spi.SessionFactoryImplementor.class);
    var mappingMetamodel = sessionFactory.getMappingMetamodel();
    var byEntityName = new LinkedHashMap<String, org.hibernate.persister.entity.EntityPersister>();
    mappingMetamodel.forEachEntityDescriptor(
        persister -> byEntityName.put(simpleEntityName(persister.getEntityName()), persister));
    for (var field : shredded) {
      var persister = byEntityName.get(field.entityName());
      if (persister == null) {
        continue;
      }
      var attribute = persister.findAttributeMapping(field.fieldName());
      String where = field.entityName() + "." + field.fieldName();
      if (!(attribute instanceof org.hibernate.metamodel.mapping.BasicValuedModelPart basic)) {
        throw config(
            "@Shredded on "
                + where
                + " is declared on the field, but the entity's mapping resolves that attribute to"
                + " something other than a single converted column ("
                + (attribute == null ? "no such attribute" : attribute.getClass().getSimpleName())
                + "). This happens under @Access(AccessType.PROPERTY): Hibernate ignores"
                + " field-level mapping annotations - the @Convert among them - when the class is"
                + " mapped through its getters, so the converter this module found on the field was"
                + " never applied. Move every @Shredded field's mapping annotations onto its"
                + " getter, or map the entity with @Access(AccessType.FIELD).");
      }
      var converter = basic.getSingleJdbcMapping().getValueConverter();
      boolean isShreddedConverter =
          converter
                  instanceof
                  org.hibernate.type.descriptor.converter.spi.JpaAttributeConverter<?, ?>
                      jpaConverter
              && jpaConverter.getConverterBean().getBeanInstance()
                  instanceof ShreddedConverter<?> resolved
              && resolved.getClass() == field.converter().getClass();
      if (!isShreddedConverter) {
        throw config(
            "@Shredded on "
                + where
                + " is declared on the field with @Convert(converter = "
                + field.converter().getClass().getName()
                + ".class), but the entity's actual mapping for that attribute does not use it. This"
                + " happens under @Access(AccessType.PROPERTY): Hibernate ignores field-level"
                + " mapping annotations - the @Convert among them - when the class is mapped through"
                + " its getters, so the column is written and read as a plain, unconverted value."
                + " Move every @Shredded field's mapping annotations onto its getter, or map the"
                + " entity with @Access(AccessType.FIELD).");
      }
    }
  }

  /**
   * C-38. {@code refuseIfSubjectMoved} and {@code onPostLoad} both return early when the entity's
   * identifier maps to more than one column - the update-time subject-immutability check and the
   * load-time per-row re-read are both built around reading a single-column id. That leaves a
   * composite-id {@code @Shredded} entity fail-closed but unusable: every read of a row carrying a
   * stored shredded value is refused with {@code SHRED-READ-UNVERIFIED}, including rows the
   * application wrote itself and nobody touched, because {@code onPostLoad} never drains the frame.
   * A mapping this module cannot support belongs in the same startup refusal as the
   * {@code @SecondaryTable} split above, not discovered on the first read in production.
   */
  private static void refuseCompositeIdShreddedEntities(
      EntityManagerFactory entityManagerFactory, Map<String, Set<String>> shreddedByEntity) {
    Set<String> shreddedEntityNames = shreddedByEntity.keySet();
    if (shreddedEntityNames.isEmpty()) {
      return;
    }
    var sessionFactory =
        entityManagerFactory.unwrap(org.hibernate.engine.spi.SessionFactoryImplementor.class);
    var mappingMetamodel = sessionFactory.getMappingMetamodel();
    mappingMetamodel.forEachEntityDescriptor(
        persister -> {
          String entityName = simpleEntityName(persister.getEntityName());
          if (!shreddedEntityNames.contains(entityName)) {
            return;
          }
          var idMapping = persister.getIdentifierMapping();
          if (!(idMapping instanceof org.hibernate.metamodel.mapping.BasicValuedModelPart)) {
            // Cipher item 7: a single-column @EmbeddedId passes the column count below but is not
            // basic, so its value is a component object with no canonical byte form. RowId would
            // have to guess, and a guessed row binding is no binding.
            throw config(
                entityName
                    + " has @Shredded fields and a composite identifier that is not a basic value ("
                    + idMapping.getClass().getSimpleName()
                    + "). Every shredded value is bound to its row's identifier, and a composite or"
                    + " embedded identifier - even a single-column @EmbeddedId, which passes the"
                    + " column count check below - has no canonical byte form this module could"
                    + " bind to without guessing, and a guessed row binding is no binding. Use a"
                    + " basic identifier: a numeric id, a UUID, a String or a byte[].");
          }
          refuseLoadedStateHostileMappings(persister, entityName, shreddedByEntity.get(entityName));
          String[] idColumns = persister.getIdentifierColumnNames();
          if (idColumns.length != 1) {
            throw config(
                entityName
                    + " has @Shredded fields and a composite identifier ("
                    + idColumns.length
                    + " id columns). The update-time subject-immutability check and the load-time"
                    + " per-row re-read both read the entity's identifier as a single column; a"
                    + " composite id cannot be checked that way. Every read of a row carrying a"
                    + " stored shredded value would be refused, including rows this application"
                    + " wrote itself, so the mapping is refused here instead of discovered on the"
                    + " first read in production.");
          }
        });
  }

  /**
   * C-29: recurses into an {@code @Embeddable} component's own attributes ({@code
   * EmbeddableValuedModelPart}) and into an {@code @ElementCollection}'s element descriptor ({@code
   * PluralAttributeMapping}), which itself may be basic-valued or, for an element collection of
   * embeddables, embeddable-valued in turn. The previous version of this scan looked only at the
   * entity persister's own top-level {@code BasicValuedModelPart} attributes, so a
   * {@code @Shredded} field declared inside either shape - invisible to the forward field scan too,
   * which walks the entity class and its superclasses only ({@link #allFields}) - was never
   * inspected in either direction: fully encrypted on write, never checked on read.
   *
   * @param path the dotted path built so far ({@code EntityName}, {@code EntityName.embedded}, ...
   *     - {@code known} only ever contains top-level {@code EntityName.field} entries, so a nested
   *     path can never match and a {@code ShreddedConverter} found at one always refuses, which is
   *     exactly the "not supported inside a component or an element collection" outcome
   */
  private static void scanAttributeMappings(
      String entityName,
      String path,
      org.hibernate.metamodel.mapping.AttributeMappingsList mappings,
      Set<String> known) {
    mappings.forEach(
        attributeMapping ->
            scanAttribute(
                entityName,
                path + "." + attributeMapping.getAttributeName(),
                attributeMapping,
                known));
  }

  private static void scanAttribute(
      String entityName,
      String path,
      org.hibernate.metamodel.mapping.ModelPart part,
      Set<String> known) {
    if (part instanceof org.hibernate.metamodel.mapping.BasicValuedModelPart basic) {
      refuseIfConverterUnmodelled(entityName, path, basic, known);
      return;
    }
    if (part instanceof org.hibernate.metamodel.mapping.EmbeddableValuedModelPart embeddable) {
      scanAttributeMappings(
          entityName, path, embeddable.getEmbeddableTypeDescriptor().getAttributeMappings(), known);
      return;
    }
    if (part instanceof org.hibernate.metamodel.mapping.PluralAttributeMapping plural) {
      // The element descriptor is itself basic-valued (a @Convert on a scalar element type) or
      // embeddable-valued (an @ElementCollection of an @Embeddable) - either way it is one more
      // ModelPart to walk the same way, just one segment deeper.
      scanAttribute(entityName, path + "[]", plural.getElementDescriptor(), known);
      // C-37: the index descriptor - a @Convert on a map key, or an @OrderColumn's list index - is
      // a separate ModelPart from the element descriptor above and was never walked, so a
      // ShreddedConverter reached that way was modelled by neither the forward field scan nor this
      // reverse one.
      if (plural.getIndexDescriptor() != null) {
        scanAttribute(entityName, path + "[key]", plural.getIndexDescriptor(), known);
      }
    }
  }

  private static void refuseIfConverterUnmodelled(
      String entityName,
      String path,
      org.hibernate.metamodel.mapping.BasicValuedModelPart basic,
      Set<String> known) {
    var converter = basic.getSingleJdbcMapping().getValueConverter();
    if (!(converter
        instanceof
        org.hibernate.type.descriptor.converter.spi.JpaAttributeConverter<?, ?> jpaConverter)) {
      return;
    }
    Object bean = jpaConverter.getConverterBean().getBeanInstance();
    if (!(bean instanceof ShreddedConverter<?> shreddedConverter)) {
      return;
    }
    if (!known.contains(path)) {
      throw config(
          "the attribute "
              + path
              + " is mapped by "
              + shreddedConverter.getClass().getName()
              + " (a ShreddedConverter for "
              + shreddedConverter.entity()
              + "."
              + shreddedConverter.field()
              + "), but has no field-level @Shredded annotation of its own. This happens when"
              + " @Convert is declared at the class level (@Converts on the entity), through an"
              + " orm.xml mapping, or on a field nested inside an @Embeddable or an"
              + " @ElementCollection of embeddables - none of which the field-level scan looks"
              + " inside. A @Shredded field nested inside a component or an element collection is"
              + " not supported: the subject expression, the @Immutable check, the"
              + " secondary-table check and onPostLoad's field list are all built from the"
              + " entity's own top-level declared fields. Move the field - @Shredded, @Convert and"
              + " all - onto the entity itself.");
    }
  }

  /**
   * The converter that maps a {@code @Shredded} field has to name the same entity and field, or the
   * AAD binds a value to a pair that does not describe where it lives. A copy-pasted converter is
   * the obvious way to get this wrong, so it is checked rather than trusted.
   */
  private static ShreddedConverter<?> requireMatchingConverter(
      Field field, String entityName, String where) {
    Convert convert = field.getAnnotation(Convert.class);
    if (convert == null
        || Void.class.equals(convert.converter())
        || void.class.equals(convert.converter())) {
      throw config(
          "@Shredded on "
              + where
              + " has no @Convert. Add one naming a converter that extends a Shredded*Converter"
              + " with (\""
              + entityName
              + "\", \""
              + field.getName()
              + "\"). See QUESTIONS #1 for why the converter carries the names.");
    }
    Class<?> converterType = convert.converter();
    if (!ShreddedConverter.class.isAssignableFrom(converterType)) {
      throw config(
          "@Shredded on "
              + where
              + " is mapped by "
              + converterType.getName()
              + ", which does not extend ShreddedConverter");
    }
    ShreddedConverter<?> converter;
    try {
      var constructor = converterType.getDeclaredConstructor();
      constructor.setAccessible(true);
      converter = (ShreddedConverter<?>) constructor.newInstance();
    } catch (ReflectiveOperationException e) {
      throw config(
          converterType.getName()
              + " needs a public no-argument constructor that calls super(\""
              + entityName
              + "\", \""
              + field.getName()
              + "\")");
    }
    if (!entityName.equals(converter.entity()) || !field.getName().equals(converter.field())) {
      throw config(
          "the converter on "
              + where
              + " declares ("
              + converter.entity()
              + ", "
              + converter.field()
              + ") but maps ("
              + entityName
              + ", "
              + field.getName()
              + "). The pair is bound into the AAD, so it must describe where the value actually"
              + " lives.");
    }
    return converter;
  }

  /**
   * A second-level cached entity keeps serving decrypted values from the cache after the key has
   * been destroyed, so the erasure is invisible until the region is evicted (control 12).
   *
   * <p>CIPHER-09: {@code globalCacheAll} covers the case no per-entity annotation can express -
   * {@code jakarta.persistence.sharedCache.mode=ALL} (or {@code DISABLE_SELECTIVE}) caches every
   * entity in the persistence unit whether or not it carries {@code @Cacheable} at all, unless it
   * explicitly opts out with {@code @Cacheable(false)}.
   */
  private static void refuseSecondLevelCache(
      Class<?> type, String entityName, boolean allowSecondLevelCache, boolean globalCacheAll) {
    Cacheable annotation = type.getAnnotation(Cacheable.class);
    boolean explicitlyOptedOut = annotation != null && !annotation.value();
    boolean cacheable = annotation != null && annotation.value();
    boolean hibernateCache = hasAnnotation(type, "org.hibernate.annotations.Cache");
    boolean cachedByGlobalMode = globalCacheAll && !explicitlyOptedOut;
    if ((cacheable || hibernateCache || cachedByGlobalMode) && !allowSecondLevelCache) {
      throw config(
          entityName
              + " has @Shredded fields and is second-level cached"
              + (cachedByGlobalMode && !cacheable && !hibernateCache
                  ? " (jakarta.persistence.sharedCache.mode caches every entity; add"
                      + " @Cacheable(false) to opt this one out, or turn the global mode off)"
                  : "")
              + ". A cached entity keeps serving the decrypted value after the subject's key is"
              + " destroyed, so the erasure is invisible until the cache region is evicted. Remove"
              + " the cache annotation, or set shredding.allow-second-level-cache=true and accept"
              + " that residual in writing.");
    }
  }

  /**
   * Control 12, the half that can be checked without running anything: a class that generates
   * {@code toString}, {@code equals} and {@code hashCode} over every field cannot hold a
   * {@code @Shredded} one.
   *
   * <p>A record does exactly that, by language rule, and is detectable from the class file: {@link
   * Class#isRecord()} is true regardless of source retention. The decrypted value would otherwise
   * reach the first log line that interpolates the entity, and a log line outlives the erasure.
   *
   * <p>CIPHER-06: this method used to also look for {@code lombok.Data}, {@code lombok.Value},
   * {@code lombok.ToString} and {@code lombok.EqualsAndHashCode} via {@code
   * Class.getAnnotations()}. All four are {@code @Retention(SOURCE)} - Lombok deletes them from the
   * class file it writes - so that loop could never match; it read as a control and was not one,
   * and both {@code SECURITY-NOTES.md} and {@code QUESTIONS.md} #9 wrongly reported it as applied.
   * There is no annotation-based way to see a {@code SOURCE}-retention type at runtime: Lombok's
   * one {@code CLASS}-retained marker, {@code lombok.Generated}, is put on the generated
   * <em>methods</em> it emits, not on the type, so detecting it here would mean walking every
   * declared method looking for an annotation this class never asks Lombok's classpath for - a
   * different and heavier check than the rest of this method makes, and still only a heuristic (a
   * hand-written method can carry the same annotation). The honest fix is to drop the claim instead
   * of leaving code that cannot do what it says: the record check stays, ships with no test at all,
   * and the sample's {@code ShreddedFieldsDoNotLeakTest} ArchUnit rule is the reference users copy
   * for the Lombok case - see {@code docs/index.md}.
   */
  /**
   * Cipher item 10 / ruling D4. {@code onPostLoad} installs the verified plaintext into the entity
   * <em>and</em> into the persistence context's loaded state, and three Hibernate mappings make
   * that unsound. Each is refused at startup, naming what to change, rather than discovered as a
   * row that cannot be updated.
   *
   * <p>Read off the runtime persister rather than off the annotations (the module's
   * framework-integration rule): {@code @SelectBeforeUpdate} does not even exist as an annotation
   * in Hibernate 7, optimistic locking and natural ids can both be declared in {@code orm.xml} or
   * in a mapped superclass, and the persister is where every route ends up.
   *
   * <ul>
   *   <li>{@code OptimisticLockStyle.ALL} and {@code DIRTY}: the UPDATE's {@code WHERE} clause is
   *       built from the loaded state, so it would carry the installed <em>plaintext</em> against a
   *       column that holds ciphertext. No update would ever match its row, and the failure would
   *       look like a concurrency problem rather than a mapping one.
   *   <li>select-before-update: Hibernate re-reads the row with {@code getDatabaseSnapshot}, which
   *       runs the converters again but fires no {@code PostLoad}, so the snapshot is made of read
   *       placeholders and compared against installed plaintext.
   *   <li>a {@code @Shredded} column that is also part of the natural id: natural-id resolution and
   *       its cache read the column through the converter outside any load event, for the same
   *       reason - and a natural id that is personal data cannot be an index key in the first
   *       place.
   * </ul>
   */
  private static void refuseLoadedStateHostileMappings(
      org.hibernate.persister.entity.EntityPersister persister,
      String entityName,
      Set<String> shreddedFieldNames) {
    var style = persister.optimisticLockStyle();
    if (style == org.hibernate.engine.OptimisticLockStyle.ALL
        || style == org.hibernate.engine.OptimisticLockStyle.DIRTY) {
      throw config(
          entityName
              + " has @Shredded fields and optimistic locking of style "
              + style
              + ". The UPDATE's WHERE clause is built from the persistence context's loaded state,"
              + " into which this module installs the verified plaintext, so it would be compared"
              + " against a column that holds ciphertext and no update would ever match its row."
              + " Use OptimisticLockType.VERSION or NONE.");
    }
    if (persister.isSelectBeforeUpdateRequired()) {
      throw config(
          entityName
              + " has @Shredded fields and requires a select-before-update. Hibernate re-reads the"
              + " row with getDatabaseSnapshot, which runs the @Shredded converters again but fires"
              + " no PostLoad event, so the snapshot is made of read placeholders and is compared"
              + " against installed plaintext. Remove select-before-update from this mapping.");
    }
    if (persister.hasNaturalIdentifier() && shreddedFieldNames != null) {
      String[] names = persister.getPropertyNames();
      for (int index : persister.getNaturalIdentifierProperties()) {
        if (index >= 0 && index < names.length && shreddedFieldNames.contains(names[index])) {
          throw config(
              entityName
                  + "."
                  + names[index]
                  + " is both @Shredded and part of the natural id. Natural-id resolution reads the"
                  + " column through the converter outside any load event, so it sees the read"
                  + " placeholder rather than the value - and a natural id that is personal data"
                  + " cannot be an index key in the first place. Use a @BlindIndex column instead.");
        }
      }
    }
  }

  private static void refuseGeneratedRendering(Class<?> type, String entityName) {
    if (type.isRecord()) {
      throw config(
          entityName
              + " has @Shredded fields and is a record. A record generates toString, equals and"
              + " hashCode over every component, so the decrypted value reaches the first log line"
              + " that renders it. Use a class with a toString that prints identifiers only.");
    }
  }

  private static boolean hasAnnotation(Class<?> type, String annotationName) {
    for (var annotation : type.getAnnotations()) {
      if (annotation.annotationType().getName().equals(annotationName)) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasAnnotation(Field field, String annotationName) {
    for (var annotation : field.getAnnotations()) {
      if (annotation.annotationType().getName().equals(annotationName)) {
        return true;
      }
    }
    return false;
  }

  /** Strips a Hibernate persister's fully qualified default entity name to its simple name. */
  private static String simpleEntityName(String persisterEntityName) {
    int dot = persisterEntityName.lastIndexOf('.');
    return dot < 0 ? persisterEntityName : persisterEntityName.substring(dot + 1);
  }

  static String entityName(Class<?> type) {
    Entity entity = type.getAnnotation(Entity.class);
    return entity != null && !entity.name().isBlank() ? entity.name() : type.getSimpleName();
  }

  private static String tableName(Class<?> type) {
    var table = type.getAnnotation(jakarta.persistence.Table.class);
    if (table != null && !table.name().isBlank()) {
      return table.name();
    }
    return camelToSnake(type.getSimpleName());
  }

  private static String columnName(Field field) {
    var column = field.getAnnotation(jakarta.persistence.Column.class);
    if (column != null && !column.name().isBlank()) {
      return column.name();
    }
    return camelToSnake(field.getName());
  }

  private static String camelToSnake(String name) {
    var sb = new StringBuilder();
    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);
      if (Character.isUpperCase(c) && i > 0) {
        sb.append('_');
      }
      sb.append(Character.toLowerCase(c));
    }
    return sb.toString();
  }

  private static List<Field> allFields(Class<?> type) {
    var fields = new ArrayList<Field>();
    for (Class<?> t = type; t != null && t != Object.class; t = t.getSuperclass()) {
      fields.addAll(List.of(t.getDeclaredFields()));
    }
    return fields;
  }

  private static ShreddingException config(String message) {
    return new ShreddingException(ErrorCodes.CONFIG, message);
  }
}
