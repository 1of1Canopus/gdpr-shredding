package com.housedevinci.shredding.api;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an entity field as personal data encrypted under its data subject's own key.
 *
 * <p>The field must also carry a {@code @Convert} naming a converter that extends one of the {@code
 * Shredded*Converter} base classes with this entity and field name; the starter cross-checks the
 * two at startup and refuses to start if they disagree. A Hibernate {@code AttributeConverter} is
 * instantiated once per class, not once per attribute, so the entity and field it protects have to
 * come from the converter class itself.
 *
 * <p>{@link #subject()} is a SpEL expression over the entity, evaluated in a read-only property
 * context: no bean references, no {@code T()} type references, no constructors, no method calls. It
 * is parsed once at bootstrap and a parse failure fails startup. The resolved id is validated and
 * only ever reaches SQL as a bind parameter.
 *
 * <p>The subject is captured at first persist and is immutable afterwards: a later change would
 * silently re-encrypt the row under another subject's key and move it out of the first subject's
 * erasure scope, so it is refused with a typed error.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Shredded {

  /** SpEL over the entity, for example {@code "#{id}"} or {@code "#{owner.id}"}. */
  String subject();

  /** SpEL over the entity for the tenant; empty means the ambient tenant context is used. */
  String tenant() default "";
}
