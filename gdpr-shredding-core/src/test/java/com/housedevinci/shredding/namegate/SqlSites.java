package com.housedevinci.shredding.namegate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What text the gate reads: reachability, not keywords (section 3.5.1 of the name-resolution
 * design).
 *
 * <p>A chain of string literals is SQL if and only if it <b>reaches a statement call</b> - {@code
 * prepareStatement}, {@code execute}, {@code executeQuery}, {@code executeUpdate}, {@code addBatch}
 * - either directly as the argument, or through a local {@code String}, a field the constructor
 * composes, or a {@code StringBuilder} whose appends are literal chains.
 *
 * <p><b>Non-literal parts of a chain become a hole token, and a hole is not a clean bill (finding
 * C-A-5).</b> Revision 1 said a hole carries "a name the module holds as data and not a name the
 * server resolves", and used that to skip it everywhere. Half of it was false: {@code
 * VerifiedSchema.qualify} cannot return a one-part name, but {@code TableRef.sql()} renders {@code
 * "t"} for any mapping that names no schema, and {@code search_path} resolves that. The two are now
 * different tokens - {@link SqlNameLexer#QUALIFIED_HOLE} for the calls listed in {@code
 * QUALIFYING_CALLS}, {@link SqlNameLexer#HOLE} for everything else - and the lexer refuses a plain
 * hole in relation position.
 *
 * <p>The naive alternative - "a literal containing a SQL keyword" - was measured and rejected: on
 * this head it selects 31 chains that never reach a statement, 27 of them prose error messages
 * ({@code "shredding.jdbc.initialize-schema=true, and running the bundled ..."}) and 4 statement
 * fragments. Reachability selects neither.
 *
 * <p><b>A statement call whose argument this resolver cannot resolve is a refusal, not a skip.</b>
 * "Unverifiable is not clean" is the whole reason the gate exists. The one accepted exception is
 * named, not inferred: {@code JdbcSupport.schemaScript()} is a file read, and {@link
 * #FILE_READ_CALLS} lists it; the gate that uses this resolver must then assert that the file it
 * lexed is the resource {@code JdbcSupport.SCHEMA_RESOURCE} names, byte for byte, so it can never
 * pass by lexing a file the module does not ship.
 */
public final class SqlSites {

  /**
   * One resolved statement site. {@code variants} is more than one when a ternary is in the chain.
   */
  public record Site(String file, int line, List<String> variants) {}

  /** A statement call the resolver could not resolve: a gate failure by itself. */
  public record Unresolved(String file, int line, String argument) {}

  /** The result of a scan: what was resolved, and what was not. */
  public record Scan(List<Site> sites, List<Unresolved> unresolved) {}

  /**
   * Package-private, not private (C-A-13): {@code NameQualificationGateTest} asserts its starter
   * file list is closed against this exact set, so a file the gate does not read that calls one of
   * these methods fails the gate rather than passing silently.
   */
  static final Set<String> STATEMENT_CALLS =
      Set.of(
          "prepareStatement",
          "execute",
          "executeQuery",
          "executeUpdate",
          "addBatch",
          "prepareCall");

  /**
   * Statement arguments that are a file read rather than a composed string. Accepted by name, with
   * the resource-identity assertion in the gate as the condition (the review's ruling on the first
   * of the two unresolved sites).
   */
  public static final Set<String> FILE_READ_CALLS = Set.of("schemaScript()");

  /**
   * The calls whose result <b>cannot be a one-part name</b>, so a hole they produce carries its
   * schema (C-A-5).
   *
   * <p>One entry, and it is a construction rule rather than a convention. {@link
   * com.housedevinci.shredding.adapter.jdbc.VerifiedSchema#qualify} is {@code quote(name) + "." +
   * quote(relation)} with no branch: there is no input for which it returns one part, and the
   * schema it names is the one {@code current_schema()} answered on the connection verification ran
   * on. An operand ending in this call resolves to {@link SqlNameLexer#QUALIFIED_HOLE}, which is
   * the only hole the lexer accepts in relation position.
   *
   * <p>{@code TableRef.sql()} is deliberately <b>not</b> here. {@code TableRef.schema} is an {@code
   * Optional} and the method renders {@code "t"} when the mapping names no schema, so a hole it
   * produces is exactly the case the gate must refuse; design section 3.2's startup refusal, which
   * makes a schema-less {@code @Shredded} mapping impossible, is PR B1's and not this PR's. Until
   * it lands the six user-table relation sites are carried as named open refusals in the gate's
   * test, each with that mechanism named.
   */
  static final Set<String> QUALIFYING_CALLS = Set.of("qualify");

  private SqlSites() {}

  static Map<String, List<String>> debugBindings(Path file) {
    return bindings(lexJava(read(file)));
  }

  /** Scans every {@code .java} file given, in order. */
  public static Scan scan(List<Path> files) {
    var sites = new ArrayList<Site>();
    var unresolved = new ArrayList<Unresolved>();
    for (Path file : files) {
      scanOne(file, sites, unresolved);
    }
    return new Scan(List.copyOf(sites), List.copyOf(unresolved));
  }

  private static void scanOne(Path file, List<Site> sites, List<Unresolved> unresolved) {
    String source = read(file);
    List<Tok> toks = lexJava(source);
    Map<String, List<String>> bindings = bindings(toks);
    String name = file.getFileName().toString();

    for (int i = 0; i < toks.size(); i++) {
      Tok t = toks.get(i);
      if (t.kind != K.IDENT || !STATEMENT_CALLS.contains(t.text)) {
        continue;
      }
      if (i + 1 >= toks.size() || !toks.get(i + 1).is("(")) {
        continue;
      }
      int close = matching(toks, i + 1);
      List<Tok> arg = toks.subList(i + 2, close);
      if (arg.isEmpty()) {
        continue; // ps.executeQuery(), ps.executeUpdate(): the text was resolved at prepare time
      }
      List<String> variants = resolve(arg, bindings);
      if (variants.isEmpty()) {
        String text = arg.stream().map(a -> a.text).reduce("", String::concat);
        if (FILE_READ_CALLS.contains(text)) {
          continue; // resolved by the gate as a file read, with the resource-identity assertion
        }
        unresolved.add(new Unresolved(name, line(source, t.at), text));
        continue;
      }
      sites.add(new Site(name, line(source, t.at), variants));
    }
  }

  /**
   * Every local or field binding in this file whose value is a resolvable literal chain, keyed by
   * name. A {@code StringBuilder} contributes its constructor argument and every {@code append} in
   * source order, which is the only shape this module builds a statement in.
   */
  private static Map<String, List<String>> bindings(List<Tok> toks) {
    var out = new LinkedHashMap<String, List<String>>();
    for (int i = 0; i < toks.size(); i++) {
      Tok t = toks.get(i);
      // <Type> <name> = <expr> ;   with Type one of String / StringBuilder / var
      if (t.kind == K.IDENT
          && (t.text.equals("String") || t.text.equals("StringBuilder") || t.text.equals("var"))
          && i + 2 < toks.size()
          && toks.get(i + 1).kind == K.IDENT
          && toks.get(i + 2).is("=")) {
        String name = toks.get(i + 1).text;
        int end = terminator(toks, i + 3);
        List<Tok> expr = toks.subList(i + 3, end);
        out.put(name, resolveInitialiser(expr, out));
      }
      // this.<name> = <expr> ;   a field the constructor composes, which is how the adapters hold
      // their qualified table expressions (`this.dataKeyTable = schema.qualify(...)`). Without this
      // the field reads as a bare hole at every statement that interpolates it, and the relation
      // leg has nothing to decide on.
      if (t.kind == K.IDENT
          && t.text.equals("this")
          && i + 4 < toks.size()
          && toks.get(i + 1).is(".")
          && toks.get(i + 2).kind == K.IDENT
          && toks.get(i + 3).is("=")
          && !toks.get(i + 4).is("=")) {
        String name = toks.get(i + 2).text;
        int end = terminator(toks, i + 4);
        out.put(name, resolveInitialiser(toks.subList(i + 4, end), out));
      }
      // <name>.append(<expr>) and <name>.append(<expr>).append(<expr>) ...
      if (t.kind == K.IDENT && out.containsKey(t.text) && i + 1 < toks.size()) {
        int j = i + 1;
        var parts = new ArrayList<List<String>>();
        while (j + 2 < toks.size()
            && toks.get(j).is(".")
            && toks.get(j + 1).kind == K.IDENT
            && toks.get(j + 1).text.equals("append")
            && toks.get(j + 2).is("(")) {
          int close = matching(toks, j + 2);
          parts.add(orHole(resolve(toks.subList(j + 3, close), out)));
          j = close + 1;
        }
        if (!parts.isEmpty()) {
          List<String> base = out.get(t.text);
          for (List<String> part : parts) {
            base = cross(base, part);
          }
          out.put(t.text, base);
          i = j - 1;
        }
      }
    }
    return out;
  }

  /**
   * {@code new StringBuilder(<expr>)} contributes {@code <expr>}, and so does every {@code append}
   * chained onto it in the same initialiser - dropping those would hide a literal from the lexer,
   * which is the one thing a gate may not do.
   */
  private static List<String> resolveInitialiser(
      List<Tok> expr, Map<String, List<String>> bindings) {
    if (expr.size() >= 4
        && expr.get(0).is("new")
        && expr.get(1).text.equals("StringBuilder")
        && expr.get(2).is("(")) {
      int close = matching(expr, 2);
      List<String> base = resolve(expr.subList(3, close), bindings);
      if (base.isEmpty()) {
        base = List.of("");
      }
      int j = close + 1;
      while (j + 2 < expr.size()
          && expr.get(j).is(".")
          && expr.get(j + 1).text.equals("append")
          && expr.get(j + 2).is("(")) {
        int argClose = matching(expr, j + 2);
        base = cross(base, orHole(resolve(expr.subList(j + 3, argClose), bindings)));
        j = argClose + 1;
      }
      return base;
    }
    return resolve(expr, bindings);
  }

  /**
   * Resolves an expression to the SQL text or texts it can produce.
   *
   * <p>The expression is split at its top-level {@code +} into operands, and each operand resolves
   * to a set of alternatives: a string literal to itself; a known binding to its own resolution; a
   * ternary to <b>both</b> branches, so neither branch escapes the lexer; anything else - a field,
   * a method call, a {@code TableRef.sql()} - to one hole token, because what it carries is a name
   * the module holds as data rather than a name the server resolves. An expression with no literal
   * anywhere in it resolves to nothing, which is how an unresolvable statement argument becomes a
   * refusal instead of a skip.
   */
  private static List<String> resolve(List<Tok> expr, Map<String, List<String>> bindings) {
    var variants = List.of("");
    boolean sawLiteral = false;
    for (List<Tok> operand : splitTopLevel(expr, "+")) {
      List<String> alternatives = operandOf(operand, bindings);
      if (alternatives.isEmpty()) {
        continue;
      }
      if (!alternatives.equals(List.of(SqlNameLexer.HOLE))) {
        sawLiteral = true;
      }
      variants = cross(variants, alternatives);
    }
    return sawLiteral ? List.copyOf(variants) : List.of();
  }

  private static List<String> operandOf(List<Tok> operand, Map<String, List<String>> bindings) {
    var trimmed = unwrap(operand);
    if (trimmed.isEmpty()) {
      return List.of();
    }
    int q = indexOf(trimmed, 0, "?");
    if (q > 0) {
      int colon = indexOf(trimmed, q, ":");
      if (colon > q) {
        var both = new ArrayList<String>();
        both.addAll(orHole(resolve(trimmed.subList(q + 1, colon), bindings)));
        both.addAll(orHole(resolve(trimmed.subList(colon + 1, trimmed.size()), bindings)));
        return List.copyOf(both);
      }
    }
    if (trimmed.size() == 1 && trimmed.get(0).kind == K.STRING) {
      return List.of(unquote(trimmed.get(0).text));
    }
    if (trimmed.get(0).kind == K.IDENT && bindings.containsKey(trimmed.get(0).text)) {
      List<String> bound = bindings.get(trimmed.get(0).text);
      if (!bound.isEmpty()) {
        return bound;
      }
    }
    if (QUALIFYING_CALLS.contains(lastCall(trimmed))) {
      return List.of(SqlNameLexer.QUALIFIED_HOLE);
    }
    if (trimmed.stream().anyMatch(t -> t.kind == K.STRING)) {
      // A chain inside a shape this resolver does not model (a call argument, a stream lambda).
      // Flattened token by token rather than recursed on, so every literal in it is still lexed
      // and the recursion cannot turn on itself: a literal contributes its text, anything else one
      // hole, consecutive holes collapse to one.
      var flat = new StringBuilder();
      boolean lastWasHole = false;
      for (Tok tok : trimmed) {
        if (tok.kind == K.STRING) {
          flat.append(unquote(tok.text));
          lastWasHole = false;
        } else if (!lastWasHole && !tok.is("+") && !tok.is("(") && !tok.is(")")) {
          flat.append(SqlNameLexer.HOLE);
          lastWasHole = true;
        }
      }
      return List.of(flat.toString());
    }
    return List.of(SqlNameLexer.HOLE);
  }

  /**
   * The name of the last method invoked in an operand, or {@code ""} when it invokes none. {@code
   * schema.qualify(SchemaExpectations.DATA_KEY)} answers {@code qualify}; {@code
   * first.tableName().sql()} answers {@code sql}.
   */
  private static String lastCall(List<Tok> operand) {
    String last = "";
    int depth = 0;
    for (int i = 0; i < operand.size(); i++) {
      Tok t = operand.get(i);
      if (t.is("(")) {
        depth++;
      } else if (t.is(")")) {
        depth--;
      } else if (depth == 0
          && t.kind == K.IDENT
          && i + 1 < operand.size()
          && operand.get(i + 1).is("(")) {
        last = t.text;
      }
    }
    return last;
  }

  private static List<String> orHole(List<String> resolved) {
    return resolved.isEmpty() ? List.of(SqlNameLexer.HOLE) : resolved;
  }

  /** Strips one layer of parentheses that wraps the whole operand, repeatedly. */
  private static List<Tok> unwrap(List<Tok> operand) {
    var out = operand;
    while (out.size() > 2 && out.get(0).is("(") && matching(out, 0) == out.size() - 1) {
      out = out.subList(1, out.size() - 1);
    }
    return out;
  }

  /** Splits at a token that sits at parenthesis depth zero. */
  private static List<List<Tok>> splitTopLevel(List<Tok> expr, String separator) {
    var out = new ArrayList<List<Tok>>();
    int depth = 0;
    int from = 0;
    for (int i = 0; i < expr.size(); i++) {
      Tok t = expr.get(i);
      if (t.is("(") || t.is("{") || t.is("[")) {
        depth++;
      } else if (t.is(")") || t.is("}") || t.is("]")) {
        depth--;
      } else if (depth == 0 && t.is(separator)) {
        out.add(expr.subList(from, i));
        from = i + 1;
      }
    }
    out.add(expr.subList(from, expr.size()));
    return out;
  }

  private static int indexOf(List<Tok> expr, int from, String text) {
    int depth = 0;
    for (int i = from; i < expr.size(); i++) {
      Tok t = expr.get(i);
      if (t.is("(")) {
        depth++;
      } else if (t.is(")")) {
        depth--;
      } else if (depth == 0 && t.is(text)) {
        return i;
      }
    }
    return -1;
  }

  private static List<String> cross(List<String> left, List<String> right) {
    var out = new ArrayList<String>();
    for (String a : left) {
      for (String b : right) {
        out.add(a + b);
      }
    }
    return out;
  }

  // ------------------------------------------------------------- a Java lexer

  private enum K {
    IDENT,
    STRING,
    NUMBER,
    PUNCT
  }

  private record Tok(K kind, String text, int at) {
    boolean is(String p) {
      return text.equals(p);
    }
  }

  private static List<Tok> lexJava(String s) {
    var out = new ArrayList<Tok>();
    int i = 0;
    while (i < s.length()) {
      char c = s.charAt(i);
      if (Character.isWhitespace(c)) {
        i++;
        continue;
      }
      if (s.startsWith("//", i)) {
        int nl = s.indexOf('\n', i);
        i = nl < 0 ? s.length() : nl + 1;
        continue;
      }
      if (s.startsWith("/*", i)) {
        int end = s.indexOf("*/", i + 2);
        i = end < 0 ? s.length() : end + 2;
        continue;
      }
      if (s.startsWith("\"\"\"", i)) {
        int end = s.indexOf("\"\"\"", i + 3);
        out.add(new Tok(K.STRING, s.substring(i, end < 0 ? s.length() : end + 3), i));
        i = end < 0 ? s.length() : end + 3;
        continue;
      }
      if (c == '"') {
        int j = i + 1;
        while (j < s.length() && s.charAt(j) != '"') {
          j += s.charAt(j) == '\\' ? 2 : 1;
        }
        out.add(new Tok(K.STRING, s.substring(i, Math.min(j + 1, s.length())), i));
        i = j + 1;
        continue;
      }
      if (c == '\'') {
        int j = i + 1;
        while (j < s.length() && s.charAt(j) != '\'') {
          j += s.charAt(j) == '\\' ? 2 : 1;
        }
        out.add(new Tok(K.PUNCT, "'char'", i));
        i = j + 1;
        continue;
      }
      if (Character.isJavaIdentifierStart(c)) {
        int j = i;
        while (j < s.length() && Character.isJavaIdentifierPart(s.charAt(j))) {
          j++;
        }
        out.add(new Tok(K.IDENT, s.substring(i, j), i));
        i = j;
        continue;
      }
      if (Character.isDigit(c)) {
        int j = i;
        while (j < s.length()
            && (Character.isLetterOrDigit(s.charAt(j))
                || s.charAt(j) == '.'
                || s.charAt(j) == '_')) {
          j++;
        }
        out.add(new Tok(K.NUMBER, s.substring(i, j), i));
        i = j;
        continue;
      }
      out.add(new Tok(K.PUNCT, String.valueOf(c), i));
      i++;
    }
    return out;
  }

  private static int matching(List<Tok> toks, int open) {
    int depth = 0;
    for (int i = open; i < toks.size(); i++) {
      if (toks.get(i).is("(")) {
        depth++;
      } else if (toks.get(i).is(")")) {
        depth--;
        if (depth == 0) {
          return i;
        }
      }
    }
    return toks.size() - 1;
  }

  private static int terminator(List<Tok> toks, int from) {
    int depth = 0;
    for (int i = from; i < toks.size(); i++) {
      Tok t = toks.get(i);
      if (t.is("(") || t.is("{")) {
        depth++;
      } else if (t.is(")") || t.is("}")) {
        depth--;
      } else if (depth == 0 && t.is(";")) {
        return i;
      }
    }
    return toks.size();
  }

  private static String unquote(String literal) {
    String body =
        literal.startsWith("\"\"\"")
            ? literal.substring(3, Math.max(3, literal.length() - 3))
            : literal.substring(1, Math.max(1, literal.length() - 1));
    return body.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\\"", "\"")
        .replace("\\'", "'")
        .replace("\\\\", "\\");
  }

  private static int line(String source, int at) {
    int line = 1;
    for (int i = 0; i < at && i < source.length(); i++) {
      if (source.charAt(i) == '\n') {
        line++;
      }
    }
    return line;
  }

  static String read(Path p) {
    try {
      return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("the gate could not read " + p, e);
    }
  }
}
