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
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
      SubjectExpression tenant) {}

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
    var shredded = new ArrayList<ShreddedField>();
    var indexes = new ArrayList<BlindIndexField>();

    for (Class<?> type : entities) {
      String entityName = entityName(type);
      var shreddedHere = new ArrayList<String>();

      for (Field field : allFields(type)) {
        Shredded annotation = field.getAnnotation(Shredded.class);
        if (annotation == null) {
          continue;
        }
        String where = entityName + "." + field.getName();
        if (Modifier.isStatic(field.getModifiers())) {
          throw config("@Shredded on " + where + " must be an instance field");
        }
        requireMatchingConverter(field, entityName, where);
        shredded.add(
            new ShreddedField(
                type,
                entityName,
                field.getName(),
                new SubjectExpression(where, annotation.subject()),
                annotation.tenant().isBlank()
                    ? null
                    : new SubjectExpression(where, annotation.tenant())));
        shreddedHere.add(field.getName());
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
        refuseSecondLevelCache(type, entityName, allowSecondLevelCache);
      }
    }
    return new ShreddedModel(shredded, indexes);
  }

  /**
   * The converter that maps a {@code @Shredded} field has to name the same entity and field, or the
   * AAD binds a value to a pair that does not describe where it lives. A copy-pasted converter is
   * the obvious way to get this wrong, so it is checked rather than trusted.
   */
  private static void requireMatchingConverter(Field field, String entityName, String where) {
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
  }

  /**
   * A second-level cached entity keeps serving decrypted values from the cache after the key has
   * been destroyed, so the erasure is invisible until the region is evicted (control 12).
   */
  private static void refuseSecondLevelCache(
      Class<?> type, String entityName, boolean allowSecondLevelCache) {
    boolean cacheable =
        type.isAnnotationPresent(Cacheable.class) && type.getAnnotation(Cacheable.class).value();
    boolean hibernateCache = hasAnnotation(type, "org.hibernate.annotations.Cache");
    if ((cacheable || hibernateCache) && !allowSecondLevelCache) {
      throw config(
          entityName
              + " has @Shredded fields and is second-level cached. A cached entity keeps serving"
              + " the decrypted value after the subject's key is destroyed, so the erasure is"
              + " invisible until the cache region is evicted. Remove the cache annotation, or set"
              + " shredding.allow-second-level-cache=true and accept that residual in writing.");
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
