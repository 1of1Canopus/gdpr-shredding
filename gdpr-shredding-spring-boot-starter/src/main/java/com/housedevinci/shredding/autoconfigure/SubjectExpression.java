package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.util.Objects;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

/**
 * The {@code @Shredded(subject = "#{...}")} expression (control 14).
 *
 * <p>Evaluated in a {@link SimpleEvaluationContext} built with {@code forReadOnlyDataBinding}: no
 * bean references, no {@code T()} type references, no constructors, no method invocation, no
 * assignment. A subject expression is a field path over the entity, not a scripting hook, and an
 * entity is often built from request data.
 *
 * <p>Parsed once, at bootstrap. A parse failure fails startup rather than surfacing on the first
 * write of a customer record at three in the morning.
 */
public final class SubjectExpression {

  private static final SpelExpressionParser PARSER = new SpelExpressionParser();

  private final String source;
  private final Expression expression;

  public SubjectExpression(String where, String source) {
    this.source = Objects.requireNonNull(source, "source");
    if (source.isBlank()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG, "@Shredded(subject=...) on " + where + " must not be blank");
    }
    try {
      // "#{...}" is the template form; the parser is given the same delimiters Spring uses.
      this.expression =
          PARSER.parseExpression(
              source, new org.springframework.expression.common.TemplateParserContext());
    } catch (ParseException e) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "@Shredded(subject=...) on " + where + " is not a valid SpEL expression: " + source,
          e);
    }
  }

  public String source() {
    return source;
  }

  public String evaluate(Object entity) {
    var context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    Object value;
    try {
      value = expression.getValue(context, entity);
    } catch (RuntimeException e) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "@Shredded(subject=\""
              + source
              + "\") could not be evaluated against "
              + entity.getClass().getName()
              + ". Only property reads are permitted: no bean references, no T() type references,"
              + " no constructors and no method calls.",
          e);
    }
    if (value == null) {
      throw new ShreddingException(
          ErrorCodes.INVALID,
          "@Shredded(subject=\""
              + source
              + "\") resolved to null on "
              + entity.getClass().getSimpleName()
              + ". A shredded field cannot be written before its data subject is known.");
    }
    // L12: only a type with an honest, stable String.valueOf() may become a subject. Without this,
    // a mistyped expression such as "#{#this}" or "#{#root}" - both permitted by
    // SimpleEvaluationContext.forReadOnlyDataBinding(), which only restricts property navigation,
    // not which root object a bare reference resolves to - hands back the entity itself, and
    // String.valueOf(entity) is Object's default "ClassName@identityHashCode": a different value
    // for every instance and every JVM run. The row is then encrypted under a key nobody will ever
    // ask for again - an erasure for the real subject never touches it - and nothing warns.
    if (!(value instanceof CharSequence
        || value instanceof Number
        || value instanceof java.util.UUID
        || value instanceof Enum<?>
        || value instanceof java.util.Date
        || value instanceof java.time.temporal.Temporal)) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "@Shredded(subject=\""
              + source
              + "\") resolved to a "
              + value.getClass().getName()
              + " on "
              + entity.getClass().getSimpleName()
              + ". A subject expression must resolve to a CharSequence, Number, UUID, Enum or"
              + " date/time value - not an object, so that String.valueOf() of it is a stable,"
              + " meaningful identifier rather than Object's default \"ClassName@identityHashCode\""
              + " shape, which differs on every instance and every JVM run and would encrypt the"
              + " row under a key nobody could ever ask an erasure for again.");
    }
    String resolved = String.valueOf(value);
    if (looksLikeIdentityHash(resolved, value)) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "@Shredded(subject=\""
              + source
              + "\") resolved to \""
              + resolved
              + "\" on "
              + entity.getClass().getSimpleName()
              + ", which has the exact shape of Object's default toString()"
              + " (\"ClassName@identityHashCode\"). That is never a real data subject; fix the"
              + " expression to name an actual identifier field.");
    }
    return resolved;
  }

  /** {@code java.lang.SomeClass@1a2b3c4d}: the shape only {@code Object.toString()} produces. */
  private static boolean looksLikeIdentityHash(String resolved, Object value) {
    if (!(value instanceof CharSequence)) {
      // A Number/UUID/Enum/date can never coincidentally have this shape; only a String can, and
      // only a string that genuinely is one of these render this way is worth the check below.
      return false;
    }
    int at = resolved.lastIndexOf('@');
    if (at < 1 || at == resolved.length() - 1) {
      return false;
    }
    String prefix = resolved.substring(0, at);
    String suffix = resolved.substring(at + 1);
    if (!prefix.matches("[A-Za-z_$][A-Za-z0-9_$.]*")) {
      return false;
    }
    return suffix.matches("[0-9a-f]+");
  }
}
