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
    return String.valueOf(value);
  }
}
