package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
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
      String tableName,
      String columnName) {}

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
                tableName(type),
                columnName(field));
        shredded.add(shreddedField);
        shreddedFieldsHere.add(shreddedField);
        shreddedHere.add(field.getName());
      }

      // CIPHER-14: refuseIfSubjectMoved reads every shredded column of the entity in one query
      // against one table. An entity whose @Shredded fields are split across a secondary table
      // (@SecondaryTable / @Column(table=...)) would have that query silently check only some of
      // them against the wrong table's row, or fail outright - refused here, at startup, instead.
      if (shreddedFieldsHere.size() > 1) {
        long distinctTables =
            shreddedFieldsHere.stream().map(ShreddedField::tableName).distinct().count();
        if (distinctTables > 1) {
          throw config(
              entityName
                  + " has @Shredded fields spanning more than one table (a @SecondaryTable or"
                  + " @Column(table=...) mapping). The update-time subject-immutability check"
                  + " reads every shredded column of an entity from its one primary table in a"
                  + " single query; a field mapped to a secondary table cannot be checked that way"
                  + " and is refused rather than silently skipped or checked against the wrong"
                  + " table.");
        }
      }

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
        field.setAccessible(true);
        indexes.add(
            new BlindIndexField(
                type,
                entityName,
                field.getName(),
                annotation.of(),
                field,
                new BlindIndexColumn(
                    tableName(type),
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
      var shreddedEntityNames = new HashSet<String>();
      for (var field : shredded) {
        known.add(field.entityName() + "." + field.fieldName());
        shreddedEntityNames.add(field.entityName());
      }
      refuseUnmodelledShreddedConverters(entityManagerFactory, known);
      refuseCompositeIdShreddedEntities(entityManagerFactory, shreddedEntityNames);
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
      EntityManagerFactory entityManagerFactory, Set<String> shreddedEntityNames) {
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
