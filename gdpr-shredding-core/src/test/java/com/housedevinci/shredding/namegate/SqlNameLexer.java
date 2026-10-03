package com.housedevinci.shredding.namegate;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The name gate's lexer, section 3.5.2 of the name-resolution design.
 *
 * <p>It decides one thing about a statement: that no name in it is left for the server to resolve
 * by {@code search_path}. It is a drift gate, not a proof - it never decides that a statement is
 * correct.
 *
 * <p>Why a lexer and not a list of spellings: revision 1's gate was twelve symbolic spellings and
 * the review measured 22 missing. The operator rule here is a <b>maximal-munch run of the
 * PostgreSQL operator character class</b>, so no enumeration can be short; {@code ~}, {@code @>},
 * {@code ->>} and {@code #} are refused by construction rather than by being listed. The keyword
 * operators are the grammar's own closed list and are refused by name. Any character the lexer does
 * not classify is a refusal: "unverifiable is not clean" has to hold at the character level too, or
 * a subscript, an array constructor or an escaped token walks through the one path the gate does
 * not model.
 *
 * <p>Comments are <b>lexed</b>, not stripped by a regex, and {@code $tag$ ... $tag$} bodies are
 * lexed recursively, which is how the three guard bodies in the bundled script are covered.
 */
public final class SqlNameLexer {

  /** One name the gate refuses, with enough context for the failure message to be actionable. */
  public record Refusal(String rule, String token, String context) {
    @Override
    public String toString() {
      return rule + ": `" + token + "` in ..." + context + "...";
    }
  }

  /** The characters PostgreSQL allows in a user-defined operator name. */
  private static final String OPERATOR_CHARS = "+-*/<>=~!@#%^&|`?";

  /**
   * The type spellings PostgreSQL's own grammar produces, and nothing else.
   *
   * <p>Allowed unquoted in a type position and before {@code (} with a length modifier, because
   * every spelling here is a production in {@code gram.y} rather than a name the server looks up -
   * {@code varchar(255)} in expression position is a syntax error (C-5a), and so is {@code
   * boolean(x)}. The <b>quoted</b> spelling is not allowed: {@code "numeric"(1)} with {@code CREATE
   * FUNCTION app."numeric"(int4)} in place resolves to the function (C-5d), so the allowance is
   * keyed on the token being an unquoted identifier whose text is in this list, never on the text
   * alone.
   *
   * <p><b>Six spellings the review removed (C-A-1, C-A-2).</b> {@code text}, {@code bytea}, {@code
   * timestamptz}, {@code int2}, {@code int4} and {@code int8} were listed here as if they were
   * grammar keywords. They are not: the grammar has no {@code TEXT}, {@code BYTEA}, {@code
   * TIMESTAMPTZ}, {@code INT2}, {@code INT4} or {@code INT8} production, so all six are ordinary
   * type names resolved along {@code search_path}, and all six are also ordinary function names.
   * The review measured {@code CREATE DOMAIN decoy.text AS char(3)} turning {@code
   * 'abcdefgh'::text} into {@code abc} silently with {@code pg_typeof} still printing {@code text}.
   * Every use of the six in this module is therefore written {@code pg_catalog.text} and the gate
   * refuses the bare spelling in both positions. The length-modifier allowance is keyed on the
   * token being a production, never on it naming a type.
   */
  private static final Set<String> GRAMMAR_TYPES =
      Set.of(
          "varchar",
          "char",
          "character",
          "numeric",
          "decimal",
          "bit",
          "time",
          "timestamp",
          "interval",
          "boolean",
          "bigint",
          "smallint",
          "integer",
          "int",
          "real",
          "double");

  /**
   * Keyword operators: names the grammar spells as words, which resolve along {@code search_path}
   * exactly as symbolic ones do and which cannot be written {@code OPERATOR(pg_catalog....)} at
   * all. {@code LIKE} is {@code ~~}; {@code IS DISTINCT FROM} reaches the type's {@code =}.
   */
  private static final Set<String> KEYWORD_OPERATORS =
      Set.of("like", "ilike", "between", "overlaps", "collate");

  /** SQL and plpgsql keywords, which are never a function call even when followed by {@code (}. */
  private static final Set<String> KEYWORDS =
      Set.of(
          "select",
          "insert",
          "update",
          "delete",
          "from",
          "where",
          "and",
          "or",
          "not",
          "in",
          "values",
          "set",
          "into",
          "on",
          "conflict",
          "do",
          "nothing",
          "returning",
          "order",
          "group",
          "by",
          "having",
          "limit",
          "offset",
          "asc",
          "desc",
          "join",
          "left",
          "right",
          "inner",
          "outer",
          "full",
          "cross",
          "exists",
          "case",
          "when",
          "then",
          "else",
          "end",
          "if",
          "elsif",
          "begin",
          "declare",
          "return",
          "raise",
          "exception",
          "using",
          "message",
          "detail",
          "hint",
          "errcode",
          "execute",
          "perform",
          "for",
          "loop",
          "share",
          "distinct",
          "null",
          "is",
          "as",
          "create",
          "replace",
          "table",
          "index",
          "unique",
          "function",
          "trigger",
          "sequence",
          "primary",
          "key",
          "foreign",
          "references",
          "check",
          "constraint",
          "default",
          "with",
          "without",
          "zone",
          "language",
          "security",
          "definer",
          "invoker",
          "returns",
          "row",
          "before",
          "after",
          "each",
          "statement",
          "instead",
          "of",
          "lock",
          "cast",
          "all",
          "any",
          "some",
          "array",
          "true",
          "false",
          "new",
          "old",
          "tg_op",
          "to",
          "nowait",
          "only",
          "add",
          "column",
          "alter",
          "drop",
          "cascade",
          "restrict",
          "grant",
          "revoke",
          "comment",
          "immutable",
          "stable",
          "volatile",
          "strict",
          "called",
          "input",
          "parallel",
          "safe",
          "unsafe",
          "cost",
          "rows",
          "owner",
          "exclusive",
          "mode",
          "concurrently");

  private final String sql;
  private final List<Refusal> refusals = new ArrayList<>();

  /** Token indices this statement creates a name at rather than resolves one at (C-A-3). */
  private Set<Integer> ddlObjectNames = Set.of();

  /** Token indices that are the {@code ON <relation>} of a {@code CREATE INDEX} (C-A-3). */
  private Set<Integer> indexTargets = Set.of();

  private SqlNameLexer(String sql) {
    this.sql = sql;
  }

  /** Every name in {@code sql} the gate refuses; empty means the statement resolves no name. */
  public static List<Refusal> refusals(String sql) {
    var lexer = new SqlNameLexer(sql);
    lexer.run();
    return List.copyOf(lexer.refusals);
  }

  // ------------------------------------------------------------------ tokens

  private enum Kind {
    IDENT,
    QUOTED_IDENT,
    STRING,
    NUMBER,
    OPERATOR,
    PARAM,
    HOLE,
    CAST_MARK,
    ASSIGN_MARK,
    PUNCT,
    DOLLAR_BODY
  }

  private record Token(Kind kind, String text, int at) {
    boolean isIdent(String word) {
      return kind == Kind.IDENT && text.equalsIgnoreCase(word);
    }

    boolean isPunct(String p) {
      return kind == Kind.PUNCT && text.equals(p);
    }
  }

  private void run() {
    List<Token> tokens = tokenise(sql);
    apply(tokens);
    for (Token t : tokens) {
      if (t.kind() == Kind.DOLLAR_BODY) {
        // The guard bodies: lexed with the same rules, which is what holds the parentheses of E3a
        // in place and what refuses a backslash inside a body (revision 1's R4 residual).
        refusals.addAll(refusals(t.text()));
      }
    }
  }

  /** The hole token: the one spelling a Java-side non-literal becomes. */
  static final String HOLE = "\u0001HOLE\u0001";

  /**
   * The second hole spelling: a non-literal {@link SqlSites} has established <b>carries its
   * schema</b>, because the call that produced it cannot return a one-part name.
   *
   * <p>Why two spellings and not one (C-A-5). Revision 1 of the gate skipped a hole in relation
   * position on the stated ground that a hole "carries a name the module holds as data and not a
   * name the server resolves". For {@code VerifiedSchema.qualify} that is true by construction -
   * {@code quote(name) + "." + quote(relation)} has no branch that drops the schema. For {@code
   * TableRef.sql()} it is false: {@code TableRef.schema} is an {@link java.util.Optional} and an
   * entity whose mapping names no schema renders {@code "t"}, which {@code search_path} resolves.
   * One spelling could not tell those apart, so the leg skipped both and was dead against every
   * relation this module emits.
   */
  static final String QUALIFIED_HOLE = "\u0001QHOLE\u0001";

  private List<Token> tokenise(String s) {
    var out = new ArrayList<Token>();
    int i = 0;
    while (i < s.length()) {
      char c = s.charAt(i);
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f') {
        i++;
        continue;
      }
      if (s.startsWith(HOLE, i)) {
        out.add(new Token(Kind.HOLE, HOLE, i));
        i += HOLE.length();
        continue;
      }
      if (s.startsWith(QUALIFIED_HOLE, i)) {
        out.add(new Token(Kind.HOLE, QUALIFIED_HOLE, i));
        i += QUALIFIED_HOLE.length();
        continue;
      }
      if (c == '-' && i + 1 < s.length() && s.charAt(i + 1) == '-') {
        int nl = s.indexOf('\n', i);
        i = nl < 0 ? s.length() : nl + 1;
        continue;
      }
      if (c == '/' && i + 1 < s.length() && s.charAt(i + 1) == '*') {
        int depth = 1;
        i += 2;
        while (i < s.length() && depth > 0) {
          if (s.startsWith("/*", i)) {
            depth++;
            i += 2;
          } else if (s.startsWith("*/", i)) {
            depth--;
            i += 2;
          } else {
            i++;
          }
        }
        continue;
      }
      if (c == '\'') {
        int j = i + 1;
        while (j < s.length()) {
          if (s.charAt(j) == '\'' && j + 1 < s.length() && s.charAt(j + 1) == '\'') {
            j += 2;
          } else if (s.charAt(j) == '\'') {
            break;
          } else {
            j++;
          }
        }
        out.add(new Token(Kind.STRING, s.substring(i, Math.min(j + 1, s.length())), i));
        i = j + 1;
        continue;
      }
      if (c == '"') {
        int j = s.indexOf('"', i + 1);
        if (j < 0) {
          j = s.length() - 1;
        }
        out.add(new Token(Kind.QUOTED_IDENT, s.substring(i, j + 1), i));
        i = j + 1;
        continue;
      }
      if (c == '$') {
        int tagEnd = s.indexOf('$', i + 1);
        if (tagEnd > 0 && isTag(s.substring(i + 1, tagEnd))) {
          String tag = s.substring(i, tagEnd + 1);
          int close = s.indexOf(tag, tagEnd + 1);
          if (close > 0) {
            out.add(new Token(Kind.DOLLAR_BODY, s.substring(tagEnd + 1, close), i));
            i = close + tag.length();
            continue;
          }
        }
        refuse("unclassified character", "$", i);
        i++;
        continue;
      }
      if (Character.isDigit(c)) {
        int j = i;
        while (j < s.length() && (Character.isDigit(s.charAt(j)) || s.charAt(j) == '.')) {
          j++;
        }
        out.add(new Token(Kind.NUMBER, s.substring(i, j), i));
        i = j;
        continue;
      }
      if (s.startsWith("::", i)) {
        out.add(new Token(Kind.CAST_MARK, "::", i));
        i += 2;
        continue;
      }
      if (s.startsWith(":=", i)) {
        out.add(new Token(Kind.ASSIGN_MARK, ":=", i));
        i += 2;
        continue;
      }
      if (c == '?'
          && (i + 1 >= s.length() || OPERATOR_CHARS.indexOf(s.charAt(i + 1)) < 0)
          && (i == 0 || OPERATOR_CHARS.indexOf(s.charAt(i - 1)) < 0)) {
        out.add(new Token(Kind.PARAM, "?", i));
        i++;
        continue;
      }
      if (OPERATOR_CHARS.indexOf(c) >= 0) {
        int j = i;
        while (j < s.length() && OPERATOR_CHARS.indexOf(s.charAt(j)) >= 0) {
          j++;
        }
        out.add(new Token(Kind.OPERATOR, s.substring(i, j), i));
        i = j;
        continue;
      }
      if (Character.isLetter(c) && c < 128 || c == '_') {
        int j = i;
        while (j < s.length()
            && (Character.isLetterOrDigit(s.charAt(j)) && s.charAt(j) < 128
                || s.charAt(j) == '_')) {
          j++;
        }
        out.add(new Token(Kind.IDENT, s.substring(i, j), i));
        i = j;
        continue;
      }
      if (c == '(' || c == ')' || c == ',' || c == ';' || c == '.') {
        out.add(new Token(Kind.PUNCT, String.valueOf(c), i));
        i++;
        continue;
      }
      refuse("unclassified character", String.valueOf(c), i);
      i++;
    }
    return out;
  }

  private static boolean isTag(String tag) {
    return tag.isEmpty() || tag.chars().allMatch(ch -> Character.isLetterOrDigit(ch) || ch == '_');
  }

  // ------------------------------------------------------------------- rules

  private void apply(List<Token> t) {
    // The DDL object-name positions of this statement, decided by the grammar's shape and not by
    // proximity (C-A-3). Computed once, before any rule runs.
    ddlObjectNames = ddlObjectNames(t);
    indexTargets = indexTargets(t);

    boolean inSetClause = false;
    // The parenthesis depth at which the current SET clause's assignments live, and whether the
    // next `=` at that depth is one. An assignment is the first `=` after a SET-clause target at
    // the clause's own depth; the `=` of `SET a = (b = c)` is an operator (C-A-4).
    int depth = 0;
    int setDepth = -1;
    boolean awaitingAssignment = false;
    // Operator applications seen since the innermost `(`, per nesting level: two at the same level
    // with no parentheses between them re-associate once the operators are OPERATOR()-qualified,
    // which all take one generic precedence (M6, C-16d, E3a).
    var applications = new ArrayList<Integer>();
    applications.add(0);

    for (int i = 0; i < t.size(); i++) {
      Token tok = t.get(i);
      checkRelationPosition(t, i);
      if (tok.isIdent("OPERATOR") && qualifiedOperatorRun(t, i)) {
        // The whole six-token run is ONE operator application, and it is an application at the
        // depth the run sits at, not inside its own parentheses. Consumed here so the run's `(`
        // never opens a nesting level and its `OPERATOR` never looks like a function call.
        bump(applications, t, i + 4);
        i += 5;
        continue;
      }
      switch (tok.kind()) {
        case PUNCT -> {
          if (tok.text().equals("(")) {
            depth++;
            applications.add(0);
          } else if (tok.text().equals(")")) {
            depth--;
            if (applications.size() > 1) {
              applications.remove(applications.size() - 1);
            }
          } else if (tok.text().equals(";") || tok.text().equals(",")) {
            if (tok.text().equals(";")) {
              inSetClause = false;
              setDepth = -1;
              awaitingAssignment = false;
            } else if (inSetClause && depth == setDepth) {
              awaitingAssignment = true;
            }
            applications.set(applications.size() - 1, 0);
          }
        }
        case IDENT -> {
          String word = tok.text().toLowerCase(Locale.ROOT);
          if (word.equals("set")) {
            inSetClause = true;
            setDepth = depth;
            awaitingAssignment = true;
          } else if (word.equals("where")
              || word.equals("from")
              || word.equals("returning")
              || word.equals("values")) {
            inSetClause = false;
            setDepth = -1;
            awaitingAssignment = false;
          }
          checkKeywordOperator(t, i);
          checkFunctionCall(t, i);
          checkCast(t, i);
        }
        case QUOTED_IDENT -> {
          if (i + 1 < t.size() && t.get(i + 1).isPunct("(") && !isDdlObjectName(t, i)) {
            // A quoted name in a function position is always a resolvable call, even when the text
            // inside the quotes is a grammar keyword: CREATE FUNCTION app."numeric"(int4) with
            // "numeric"(1) returned HIJACK-numeric (C-5d). The grammar allowance is keyed on the
            // token being an UNQUOTED identifier, which this is not.
            refuse("unqualified function or aggregate", t.get(i).text() + "(", context(tok.at()));
          }
        }
        case CAST_MARK -> checkCastTarget(t, i);
        case OPERATOR -> {
          if (isStar(t, i)) {
            // `*` in `SELECT *` and `pg_catalog.count(*)` is the grammar's star, not an operator.
          } else if (awaitingAssignment && depth == setDepth && isAssignment(t, i, inSetClause)) {
            // `SET <col> =` and `DO UPDATE SET <col> =`: an assignment position, not a name. Only
            // the first `=` after a target, and only at the clause's own depth (C-A-4).
            awaitingAssignment = false;
          } else {
            refuse(
                "unqualified operator",
                tok.text(),
                context(tok.at()) + " (write it OPERATOR(pg_catalog." + tok.text() + "))");
            bump(applications, t, i);
          }
        }
        default -> {
          // strings, numbers, params, quoted identifiers and holes resolve no name
        }
      }
    }
  }

  private void bump(List<Integer> applications, List<Token> t, int i) {
    int level = applications.size() - 1;
    int now = applications.get(level) + 1;
    applications.set(level, now);
    if (now == 2) {
      refuse(
          "unparenthesised operator sequence",
          t.get(i).text(),
          context(t.get(i).at())
              + " (OPERATOR() erases precedence: parenthesise each application)");
    }
  }

  /**
   * True when this operator token is the one inside an {@code OPERATOR(pg_catalog....)}.
   *
   * <p>A token sequence, not a string match (M7): exactly six tokens with nothing of any other kind
   * between them <b>and no whitespace</b>, because the review measured that {@code OPERATOR (
   * pg_catalog . = )} and {@code OPERATOR("pg_catalog".=)} both parse and both answer {@code t}
   * (C-16e), while {@code OPERATOR(app.=)} is the attack itself. One spelling is written by this
   * module; the gate accepts that one. The schema must be the unquoted identifier {@code
   * pg_catalog}: a quoted spelling lexes as a QUOTED_IDENT and never matches here.
   */
  private boolean qualifiedOperatorRun(List<Token> t, int i) {
    return i + 5 < t.size()
        && t.get(i).isIdent("OPERATOR")
        && t.get(i + 1).isPunct("(")
        && t.get(i + 2).kind() == Kind.IDENT
        && t.get(i + 2).text().equals("pg_catalog")
        && t.get(i + 3).isPunct(".")
        && t.get(i + 4).kind() == Kind.OPERATOR
        && t.get(i + 5).isPunct(")")
        && adjacent(t, i, i + 5);
  }

  /** No whitespace and no other token anywhere inside this run (M7). */
  private boolean adjacent(List<Token> t, int from, int to) {
    for (int j = from; j < to; j++) {
      if (t.get(j).at() + t.get(j).text().length() != t.get(j + 1).at()) {
        return false;
      }
    }
    return true;
  }

  private boolean isStar(List<Token> t, int i) {
    if (!t.get(i).text().equals("*")) {
      return false;
    }
    if (i == 0) {
      return true;
    }
    Token prev = t.get(i - 1);
    return prev.isPunct("(")
        || prev.isPunct(",")
        || prev.isIdent("select")
        || prev.isIdent("count")
        || prev.isIdent("distinct");
  }

  /**
   * True when this {@code =} is a SET-clause assignment rather than an operator.
   *
   * <p>The caller has already established that the clause is open, that this token sits at the
   * clause's own parenthesis depth and that no assignment has been seen since the clause started or
   * since the last comma at that depth. All three are needed: revision 1 asked only "is an
   * identifier to the left while a SET clause is open", which read the inner {@code =} of {@code
   * SET a = (b = c)} as a second assignment target and let a resolvable operator through (C-A-4).
   * Nothing in this module writes that shape; the gate exists for the edit that does.
   */
  private boolean isAssignment(List<Token> t, int i, boolean inSetClause) {
    if (!t.get(i).text().equals("=") || !inSetClause || i == 0) {
      return false;
    }
    Kind prev = t.get(i - 1).kind();
    // A hole is an assignment target too: `SET <col> = ?` where the column name is one the module
    // holds as data (a ColumnRef), which is exactly the shape every UPDATE in the adapters has.
    return prev == Kind.IDENT || prev == Kind.QUOTED_IDENT || prev == Kind.HOLE;
  }

  private void checkKeywordOperator(List<Token> t, int i) {
    Token tok = t.get(i);
    String word = tok.text().toLowerCase(Locale.ROOT);
    if (KEYWORD_OPERATORS.contains(word)) {
      refuse("keyword operator", tok.text(), context(tok.at()));
      return;
    }
    if (word.equals("similar") && next(t, i, "to")) {
      refuse("keyword operator", "SIMILAR TO", context(tok.at()));
      return;
    }
    if (word.equals("at") && next(t, i, "time")) {
      refuse("keyword operator", "AT TIME ZONE", context(tok.at()));
      return;
    }
    if (word.equals("distinct") && i > 0 && (t.get(i - 1).isIdent("is") || isIsNot(t, i - 1))) {
      refuse("keyword operator", "IS DISTINCT FROM", context(tok.at()));
      return;
    }
    if (word.equals("in") && i + 1 < t.size() && t.get(i + 1).isPunct("(") && !isDdlIn(t, i)) {
      refuse("keyword operator", "IN", context(tok.at()));
      return;
    }
    if ((word.equals("any") || word.equals("all") || word.equals("some"))
        && i + 1 < t.size()
        && t.get(i + 1).isPunct("(")
        && !precededByQualifiedOperator(t, i)) {
      refuse("keyword operator with a bare operator", tok.text(), context(tok.at()));
    }
  }

  /** {@code IN} in a plpgsql argument-mode or {@code FOR x IN} position is not an operator. */
  private boolean isDdlIn(List<Token> t, int i) {
    return i > 0 && (t.get(i - 1).isIdent("for") || t.get(i - 1).isPunct(","));
  }

  private boolean isIsNot(List<Token> t, int i) {
    return t.get(i).isIdent("not") && i > 0 && t.get(i - 1).isIdent("is");
  }

  private boolean precededByQualifiedOperator(List<Token> t, int i) {
    return i >= 6 && t.get(i - 1).isPunct(")") && qualifiedOperatorRun(t, i - 6);
  }

  private boolean next(List<Token> t, int i, String word) {
    return i + 1 < t.size() && t.get(i + 1).isIdent(word);
  }

  private void checkFunctionCall(List<Token> t, int i) {
    Token tok = t.get(i);
    if (i + 1 >= t.size() || !t.get(i + 1).isPunct("(")) {
      return;
    }
    String word = tok.text().toLowerCase(Locale.ROOT);
    if (KEYWORDS.contains(word) || GRAMMAR_TYPES.contains(word)) {
      // A grammar keyword, or a grammar production with a length modifier - `numeric(1)`,
      // `varchar(255)`. Unquoted only: a quoted "numeric" is a QUOTED_IDENT token and never
      // reaches this branch (C-5d). The allowance holds because a production in a call position is
      // a syntax error rather than a lookup; it must never be keyed on the token naming a type.
      // `text(x)`, `int8(x)`, `bytea(x)`, `timestamptz(x)`, `int2(x)` and `int4(x)` are plain
      // function calls resolved along search_path - the function-syntax cast - and are refused
      // since those six left GRAMMAR_TYPES (C-A-2).
      return;
    }
    if (isQualified(t, i)) {
      String schema = t.get(i - 2).text();
      if (!schema.equals("pg_catalog")) {
        refuse(
            "function qualified with a schema other than pg_catalog",
            schema + "." + tok.text(),
            context(tok.at()));
      }
      return;
    }
    if (isDdlObjectName(t, i) || isTriggerFunctionName(t, i) || isIndexTarget(t, i)) {
      return;
    }
    refuse("unqualified function or aggregate", tok.text() + "(", context(tok.at()));
  }

  /**
   * {@code CREATE TABLE x (}, {@code CREATE FUNCTION x (}: created in {@code current_schema()}, not
   * resolved along the path.
   */
  private boolean isDdlObjectName(List<Token> t, int i) {
    return ddlObjectNames.contains(i);
  }

  /**
   * The object-name position of every {@code CREATE} / {@code ALTER} / {@code DROP} in a statement,
   * decided by the grammar's shape: after the verb, the grammar allows only its own keywords -
   * {@code OR REPLACE}, {@code UNIQUE}, the object type, {@code IF NOT EXISTS}, {@code
   * CONCURRENTLY} - until the name, so the <b>first non-keyword identifier after the verb</b> is
   * the name and nothing further along is.
   *
   * <p>Why not a lookback (C-A-3). Revision 1 scanned back up to six tokens for an object-type
   * keyword and four more for the verb, so {@code CREATE INDEX i ON t (lower(c))} put {@code lower}
   * four tokens from {@code index} and the whole index expression was read as the object being
   * created: zero refusals for a statement whose {@code lower} resolves along the applying
   * session's path. The bundled script escaped only because {@code IF NOT EXISTS} pushes {@code
   * index} out of the window - an accident of token count, not a rule.
   */
  private Set<Integer> ddlObjectNames(List<Token> t) {
    var out = new HashSet<Integer>();
    for (int i = 0; i < t.size(); i++) {
      if (!(t.get(i).isIdent("create") || t.get(i).isIdent("alter") || t.get(i).isIdent("drop"))) {
        continue;
      }
      int j = i + 1;
      while (j < t.size()
          && t.get(j).kind() == Kind.IDENT
          && KEYWORDS.contains(t.get(j).text().toLowerCase(Locale.ROOT))) {
        j++;
      }
      if (j >= t.size()) {
        continue;
      }
      Kind kind = t.get(j).kind();
      if (kind != Kind.IDENT && kind != Kind.QUOTED_IDENT) {
        continue;
      }
      out.add(j);
      // `CREATE TABLE "s"."t" (`: the schema is named, not resolved, and the second part is the
      // object. Neither depends on search_path.
      if (j + 2 < t.size() && t.get(j + 1).isPunct(".")) {
        out.add(j + 2);
      }
    }
    return Set.copyOf(out);
  }

  /**
   * The relation a {@code CREATE INDEX} attaches to: {@code CREATE INDEX IF NOT EXISTS i ON t
   * (cols)}, where {@code t} is followed by {@code (} and would otherwise read as a function call.
   *
   * <p>This is the same class as {@link #isTriggerFunctionName} and is stated with the same reason
   * (design section 5.2). The script cannot qualify it: an unqualified {@code CREATE TABLE} targets
   * {@code current_schema()}, so the script has no schema name to write at parse time, and the
   * {@code ON} relation is then resolved in the <b>applying</b> session's path. What covers it is
   * not qualification but verification: {@code SchemaVerification} reads the indexes of the
   * verified schema's own relations, so an index that landed on a same-named relation earlier on
   * the applying session's path leaves the verified schema's table without it and boot refuses.
   *
   * <p>Revision 1 of the gate allowed this token by accident rather than by rule: the six-token
   * lookback found {@code INDEX} at exactly distance six through {@code IF NOT EXISTS}, so the
   * relation was read as the object being created. With the lookback replaced (C-A-3) the rule has
   * to be written down, which is what this is.
   */
  private boolean isIndexTarget(List<Token> t, int i) {
    return indexTargets.contains(i);
  }

  private Set<Integer> indexTargets(List<Token> t) {
    var out = new HashSet<Integer>();
    for (int i = 0; i < t.size(); i++) {
      if (!t.get(i).isIdent("create")) {
        continue;
      }
      boolean index = false;
      int j = i + 1;
      while (j < t.size()
          && t.get(j).kind() == Kind.IDENT
          && KEYWORDS.contains(t.get(j).text().toLowerCase(Locale.ROOT))) {
        index |= t.get(j).isIdent("index");
        j++;
      }
      if (!index) {
        continue;
      }
      while (j < t.size() && !t.get(j).isPunct(";") && !t.get(j).isIdent("on")) {
        j++;
      }
      if (j + 1 >= t.size() || !t.get(j).isIdent("on")) {
        continue;
      }
      out.add(j + 1);
      if (j + 3 < t.size() && t.get(j + 2).isPunct(".")) {
        out.add(j + 3);
      }
    }
    return Set.copyOf(out);
  }

  /**
   * {@code EXECUTE FUNCTION shredding_...()} inside {@code CREATE TRIGGER}, and the guard names in
   * the script's {@code DO} blocks: section 5.2 of the design. These names resolve in the
   * <b>applying</b> session's path, not the runtime role's, and the script cannot know its own
   * schema at parse time - that is section 5's whole problem. They are covered by a leg rather than
   * by qualification: verification reads {@code p.pronamespace} for the function each trigger
   * points at and refuses a trigger whose function is not in the verified schema. Stated here as a
   * rule with its reason, never allowlisted by file or by line.
   */
  private boolean isTriggerFunctionName(List<Token> t, int i) {
    return i >= 2
        && t.get(i - 1).isIdent("function")
        && t.get(i - 2).isIdent("execute")
        && t.get(i).text().startsWith("shredding_");
  }

  private boolean isQualified(List<Token> t, int i) {
    return i >= 2 && t.get(i - 1).isPunct(".") && t.get(i - 2).kind() == Kind.IDENT;
  }

  /**
   * The relation leg: {@code FROM}, {@code JOIN}, {@code INSERT INTO}, {@code UPDATE}, {@code LOCK
   * TABLE}.
   *
   * <p><b>Every token kind, not only an unquoted identifier (C-A-5).</b> Revision 1 returned early
   * unless the token was an unquoted {@code IDENT}, which made the leg dead against everything this
   * module emits: {@code TableRef.sql()} and {@code VerifiedSchema.qualify} both quote, so a
   * relation reaches the lexer as a {@code QUOTED_IDENT} or, through a Java-side call, as a hole.
   * The leg reported the three statements of design section 3.4 clean while {@code SELECT
   * email_cipher FROM "customer"} was measured reading {@code decoy.customer} on a role's own
   * hostile path. Quoting changes the case folding of a name; it does not stop the server resolving
   * it.
   *
   * <p>A hole is accepted only in its {@link #QUALIFIED_HOLE} spelling, which {@link SqlSites}
   * emits for a call that cannot return a one-part name. A plain hole in relation position is a
   * refusal: the gate has no evidence about what it carries.
   */
  private void checkRelationPosition(List<Token> t, int i) {
    Token tok = t.get(i);
    if (i == 0) {
      return;
    }
    Token prev = t.get(i - 1);
    boolean relationPosition =
        prev.isIdent("from")
            || prev.isIdent("join")
            || (prev.isIdent("into") && !t.get(Math.max(0, i - 2)).isIdent("conflict"))
            || (prev.isIdent("update") && !(i >= 2 && t.get(i - 2).isIdent("do")))
            || (prev.isIdent("table") && i >= 2 && t.get(i - 2).isIdent("lock"));
    if (!relationPosition) {
      return;
    }
    if (tok.kind() == Kind.HOLE) {
      if (tok.text().equals(QUALIFIED_HOLE)) {
        return;
      }
      refuse("unqualified relation", "<>", context(tok.at()));
      return;
    }
    if (tok.kind() != Kind.IDENT && tok.kind() != Kind.QUOTED_IDENT) {
      return;
    }
    if (i + 1 < t.size() && t.get(i + 1).isPunct(".")) {
      return; // schema-qualified
    }
    if (tok.kind() == Kind.IDENT && KEYWORDS.contains(tok.text().toLowerCase(Locale.ROOT))) {
      return;
    }
    refuse("unqualified relation", tok.text(), context(tok.at()));
  }

  /** {@code CAST(<expr> AS <type>)} is a type position exactly as {@code ::} is (M4, C-4). */
  private void checkCast(List<Token> t, int i) {
    if (!t.get(i).isIdent("cast") || i + 1 >= t.size() || !t.get(i + 1).isPunct("(")) {
      return;
    }
    int depth = 0;
    for (int j = i + 1; j < t.size(); j++) {
      Token tok = t.get(j);
      if (tok.isPunct("(")) {
        depth++;
      } else if (tok.isPunct(")")) {
        depth--;
        if (depth == 0) {
          return;
        }
      } else if (depth == 1 && tok.isIdent("as")) {
        checkTypeName(t, j + 1);
        return;
      }
    }
  }

  private void checkCastTarget(List<Token> t, int i) {
    checkTypeName(t, i + 1);
  }

  private void checkTypeName(List<Token> t, int i) {
    if (i >= t.size()) {
      return;
    }
    Token tok = t.get(i);
    if (tok.kind() == Kind.HOLE) {
      return;
    }
    if (tok.kind() == Kind.IDENT
        && i + 1 < t.size()
        && t.get(i + 1).isPunct(".")
        && tok.text().equals("pg_catalog")) {
      return;
    }
    if (tok.kind() == Kind.IDENT && GRAMMAR_TYPES.contains(tok.text().toLowerCase(Locale.ROOT))) {
      return; // an unquoted grammar type keyword
    }
    refuse(
        "unqualified type",
        tok.text(),
        context(tok.at()) + " (write it ::pg_catalog." + tok.text() + ")");
  }

  private void refuse(String rule, String token, String context) {
    refusals.add(new Refusal(rule, token, context));
  }

  private void refuse(String rule, String token, int at) {
    refusals.add(new Refusal(rule, token, context(at)));
  }

  private String context(int at) {
    int from = Math.max(0, at - 30);
    int to = Math.min(sql.length(), at + 30);
    return sql.substring(from, to)
        .replace('\n', ' ')
        .replace(HOLE, "<>")
        .replace(QUALIFIED_HOLE, "<s.>");
  }
}
