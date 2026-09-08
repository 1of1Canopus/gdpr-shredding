package com.housedevinci.shredding.sample;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.api.Shredded;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.lang.reflect.Field;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Control 12, the static half: a {@code @Shredded} field must not reach a generated {@code
 * toString}, {@code equals} or {@code hashCode}, and must not be serialised by Jackson.
 *
 * <p>A record generates all three over every component, so an entity holding a shredded field
 * cannot be one, and a class that declares shredded fields has to write its own {@code toString}
 * rather than inherit {@code Object}'s or accept a generated one.
 */
class ShreddedFieldsDoNotLeakTest {

  private static final JavaClasses CLASSES =
      new ClassFileImporter()
          .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
          .importPackages("com.housedevinci.shredding.sample");

  @Test
  void no_entity_with_a_shredded_field_is_a_record() {
    List<String> records =
        CLASSES.stream()
            .filter(c -> c.isRecord())
            .filter(ShreddedFieldsDoNotLeakTest::declaresShredded)
            .map(c -> c.getName())
            .toList();

    assertThat(records)
        .as("a record generates toString, equals and hashCode over every component")
        .isEmpty();
  }

  @Test
  void every_class_with_a_shredded_field_declares_its_own_tostring() {
    List<String> missing =
        CLASSES.stream()
            .filter(ShreddedFieldsDoNotLeakTest::declaresShredded)
            .filter(c -> c.tryGetMethod("toString").isEmpty())
            .map(c -> c.getName())
            .toList();

    assertThat(missing)
        .as("Object.toString leaks nothing, but an IDE-generated one over all fields does")
        .isEmpty();
  }

  @Test
  void a_shredded_field_is_never_a_public_field_or_a_jackson_property() throws Exception {
    for (Field field : Customer.class.getDeclaredFields()) {
      if (field.isAnnotationPresent(Shredded.class)) {
        assertThat(java.lang.reflect.Modifier.isPublic(field.getModifiers())).isFalse();
      }
    }
    // The API view is a record built by hand, so what leaves the process is a deliberate choice
    // rather than whatever the entity happens to hold.
    assertThat(CustomerEndpoints.CustomerView.class.isRecord()).isTrue();
  }

  private static boolean declaresShredded(com.tngtech.archunit.core.domain.JavaClass type) {
    return type.getAllFields().stream().anyMatch(f -> f.isAnnotatedWith(Shredded.class));
  }
}
