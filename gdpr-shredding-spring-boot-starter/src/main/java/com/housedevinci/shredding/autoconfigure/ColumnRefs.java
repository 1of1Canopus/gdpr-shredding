package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import org.hibernate.boot.model.naming.Identifier;
import org.hibernate.dialect.Dialect;
import org.hibernate.dialect.PostgreSQLDialect;
import org.hibernate.metamodel.mapping.SelectableMapping;
import org.hibernate.sql.Template;

/**
 * The one place a {@link ColumnRef} is built (design addendum 4, §4.2). Nothing else in this module
 * may derive a column identifier from anything: not from an annotation's text, not from a field
 * name, not by unquoting a string by hand. That is the whole of S-22's fix.
 *
 * <p><b>The parse is Hibernate's.</b> {@code SelectableMapping.getSelectionExpression()} is not a
 * name, it is a dialect-quoted SQL fragment: for {@code @Column(name = "\"Owner\"")} it is
 * literally {@code "Owner"}, quote characters included, because {@code SelectableMappingImpl.from}
 * stores {@code Column.getText(dialect)}, which is {@code getQuotedName(dialect)} when the column
 * is quoted. It is therefore parsed by {@link Identifier#toIdentifier(String)} - the
 * <em>static</em> one, deliberately, and never {@code IdentifierHelper.toIdentifier}, whose {@code
 * normalizeQuoting} <em>adds</em> quoting the mapping never had whenever {@code
 * globally_quoted_identifiers}, {@code auto_quote_keyword} on a reserved word, a leading {@code _}
 * or a {@code $} is in play. With the helper, the round-trip below would fail for a column mapped
 * unquoted and named {@code user} under {@code hibernate.auto_quote_keyword=true}, and refuse a
 * valid application at startup blaming "round-trip divergence" instead of the real reason.
 *
 * <p><b>The round trip is the proof.</b> Whatever the parse produced has to render back, character
 * for character, to the expression Hibernate handed over - through {@link
 * Identifier#render(Dialect)} and through {@link ColumnRef#sql()} both. If either differs, this
 * module has mis-parsed and says so at startup rather than interpolating an identifier that
 * addresses something else.
 */
final class ColumnRefs {

  private ColumnRefs() {}

  /**
   * The column a mapped selectable addresses, or a startup refusal naming the reason.
   *
   * @param where the property being resolved, for the message - {@code Entity.field}
   */
  static ColumnRef of(SelectableMapping selectable, String where, Dialect dialect) {
    requirePostgreSql(dialect, where);
    if (selectable.isFormula()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          where
              + " is mapped by a @Formula, not by a column. A formula is computed by the database"
              + " on read: there is no column for this module's UPDATE to set, for its WHERE to"
              + " match on, or for an erasure to clear. The refusal is on Hibernate's own"
              + " isFormula() flag, not on the shape of the expression (\""
              + selectable.getSelectionExpression()
              + "\"), because @Formula(\"owner_id\") is a plain identifier and would otherwise pass"
              + " a shape test.");
    }
    // Hibernate populates a read expression for *every* column - the templated "{@}.col" it uses to
    // qualify the column with its table alias - and "?" for every write, so a null check here would
    // never fire and a non-null check would refuse every application. What marks a
    // @ColumnTransformer is a read that is not the plain template of this column's own expression,
    // or a write that is not a bare parameter.
    String plainRead = Template.TEMPLATE + "." + selectable.getSelectionExpression();
    String read = selectable.getCustomReadExpression();
    String write = selectable.getCustomWriteExpression();
    boolean transformedOnRead = read != null && !read.equals(plainRead);
    boolean transformedOnWrite = write != null && !"?".equals(write.trim());
    if (transformedOnRead || transformedOnWrite) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          where
              + " has a @ColumnTransformer (read = "
              + quoteForMessage(read)
              + ", write = "
              + quoteForMessage(write)
              + "). The column identifier is perfectly plain, and that is the danger: the column"
              + " stores something other than the value this module binds, so a WHERE on it matches"
              + " nothing and a SET of NULL on it is not what Hibernate would write. That is the"
              + " same failure as a mis-addressed name, reached by value instead - and it would be"
              + " recorded as a completed erasure. Remove the transformer from this column, or"
              + " point @BlindIndex at a column that has none.");
    }
    ColumnRef ref = parse(selectable.getSelectionExpression(), where);
    assertRoundTrip(ref, selectable.getSelectionExpression(), where, dialect);
    refuseIfUnquotedReservedWord(ref, where);
    return ref;
  }

  /**
   * The round trip above proves this module reproduces the expression Hibernate's mapping holds -
   * it says nothing about whether that expression can survive an <em>unqualified</em> reference.
   * Hibernate's own SQL always qualifies a column with its table alias ({@code n1_0.user}), where
   * PostgreSQL's grammar allows a reserved word after the dot; this module's {@code UPDATE} and
   * {@code WHERE} do not qualify, and a bare reserved word there is parsed as the keyword, not as a
   * column reference - {@code user} becomes {@code CURRENT_USER}, silently matching nothing. Refuse
   * at startup, naming the mapping, rather than let every erasure of that column fail for ever with
   * a message that blames something else.
   */
  private static void refuseIfUnquotedReservedWord(ColumnRef ref, String where) {
    if (!ref.quoted() && PostgreSqlReservedKeywords.isReserved(ref.text())) {
      String quotedMapping = "@Column(name = \"" + "\\\"" + ref.text() + "\\\"" + "\")";
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          where
              + " maps column "
              + ref.text()
              + " unquoted, and \""
              + ref.text().toLowerCase(java.util.Locale.ROOT)
              + "\" is one of PostgreSQL's reserved key words. Hibernate's own SQL qualifies every"
              + " column reference with a table alias and is unaffected, but this module's WHERE and"
              + " SET are not qualified, so an unqualified reserved word there is parsed as the"
              + " keyword itself rather than as this column - and every erasure of "
              + where
              + " would then match nothing, forever, without saying why. Quote it in the mapping: "
              + quotedMapping
              + ".");
    }
  }

  /**
   * The parse alone, without a mapping: Hibernate's own reading of the quoting present in the text,
   * adding none.
   */
  static ColumnRef parse(String expression, String where) {
    if (expression == null || expression.isBlank()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG, where + " has a null or blank column expression");
    }
    Identifier identifier = Identifier.toIdentifier(expression);
    if (identifier == null) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          where
              + " has a column expression Hibernate does not parse as an"
              + " identifier: \""
              + expression
              + "\"");
    }
    try {
      return new ColumnRef(identifier.getText(), identifier.isQuoted());
    } catch (ShreddingException e) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          where
              + ": "
              + e.getMessage()
              + " (the mapping's column expression is \""
              + expression
              + "\")");
    }
  }

  /**
   * §4.2's round trip. Two renderings of the same parse - Hibernate's and this module's - both have
   * to reproduce the expression verbatim. It holds by construction for every column with the static
   * parse above; it fails the moment the parse is ever changed to one that normalises.
   */
  private static void assertRoundTrip(
      ColumnRef ref, String expression, String where, Dialect dialect) {
    String hibernate = new Identifier(ref.text(), ref.quoted()).render(dialect);
    if (!expression.equals(hibernate) || !expression.equals(ref.sql())) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          where
              + " has a column expression this module cannot reproduce. Hibernate's mapping renders"
              + " it as \""
              + expression
              + "\"; parsed and rendered back it is \""
              + hibernate
              + "\" (Hibernate) and \""
              + ref.sql()
              + "\" (this module). Since the expression is not a formula (that is refused by its own"
              + " flag), the mapping sets Column.assignmentExpression on this column, or names it in"
              + " a way this module has not been shown to address. Either way, interpolating it"
              + " would address a column nobody named, so startup refuses instead.");
    }
  }

  /**
   * PostgreSQL is the only dialect this module supports: {@link ColumnRef#sql()} renders {@code "}
   * and nothing else, and {@code TableRef} makes the same assumption. Refused here, at startup,
   * rather than by rendering an identifier another database reads as something different.
   */
  private static void requirePostgreSql(Dialect dialect, String where) {
    if (!(dialect instanceof PostgreSQLDialect)) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "this module builds SQL identifiers itself and supports PostgreSQL only, but Hibernate's"
              + " dialect is "
              + dialect.getClass().getName()
              + " (resolving "
              + where
              + "). A quoted identifier is rendered with double quotes and folded lower case when"
              + " unquoted; on another database both are different rules, and every statement this"
              + " module builds would address a column other than the one the mapping addresses.");
    }
  }

  private static String quoteForMessage(String value) {
    return value == null ? "none" : "\"" + value + "\"";
  }
}
