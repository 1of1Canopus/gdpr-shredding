package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * The four pinned files of one PostgreSQL major that the function-grants leg judges native code by
 * (C-PR45-3, design revisions 4 and 5): the initdb baseline of withheld functions, the extension
 * manifest (one line per native member of each installable extension version, with the support
 * functions of an aggregate), the list of every available extension version with whether the pinned
 * image installs it, and the record of every core native function (R7).
 *
 * <p>The files are data DDL cannot rewrite. They are generated from a pristine install of the
 * pinned image by {@code tools/generate-pinned-catalogue.sh}, never typed by hand, and a test
 * compares them byte for byte with the image. The only code that reads the server's major is the
 * file name choice. A missing, unreadable or malformed file is {@code SHRED-SCHEMA-005}, never an
 * empty list: unverifiable is not clean.
 */
final class PinnedCatalogue {

  /** One initdb function the server ships without EXECUTE for PUBLIC. */
  record Withheld(
      long oid, String signature, String key, String symbol, boolean securityDefiner, String acl) {}

  /**
   * One native member function of one extension version, as its pristine install creates it. For an
   * aggregate, {@code supports} lists its support functions by slot and key ({@code
   * transfn=key;finalfn=key}, slot order); it is empty for any other function (revision 5).
   */
  record Member(
      String extension,
      String version,
      String key,
      String symbol,
      boolean securityDefiner,
      boolean withheld,
      String supports) {

    /** A member that is not an aggregate. */
    Member(
        String extension,
        String version,
        String key,
        String symbol,
        boolean securityDefiner,
        boolean withheld) {
      this(extension, version, key, symbol, securityDefiner, withheld, "");
    }
  }

  /**
   * One core native function (oid below 16384, in no extension) as initdb ships it (R7,
   * C-PR45-3-17). Keyed by signature, not oid: an oid of {@link #FIXED_OID_LIMIT} or more is given
   * by initdb at run time, so it is not a stable key (the baseline refuses such oids for the same
   * reason). {@code library} is {@code -} when the function has none.
   */
  record CoreNative(
      String signature, String language, String symbol, String library, boolean securityDefiner) {}

  /** One row of {@code pg_available_extension_versions} on the pinned image. */
  record Version(String extension, String version, boolean installable, String error) {}

  /** The only error a version may fail with and still be written (C-PR45-3-13). */
  static final String LOAD_FAILURE = "could not load library";

  /** Byte order of the UTF-8 text, as {@code COLLATE "C"} sorts it: how the pinned files sort. */
  static final java.util.Comparator<String> C_ORDER =
      (a, b) ->
          java.util.Arrays.compareUnsigned(
              a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));

  /** An initdb oid of this value or more is assigned at initdb and is not a stable key. */
  static final long FIXED_OID_LIMIT = 10_000;

  private final int major;
  private final List<Withheld> baseline;
  private final List<Member> manifest;
  private final List<Version> versions;
  private final List<CoreNative> core;

  private PinnedCatalogue(
      int major,
      List<Withheld> baseline,
      List<Member> manifest,
      List<Version> versions,
      List<CoreNative> core) {
    this.major = major;
    this.baseline = List.copyOf(baseline);
    this.manifest = List.copyOf(manifest);
    this.versions = List.copyOf(versions);
    this.core = List.copyOf(core);
  }

  static String baselineResource(int major) {
    return "pg-initdb-withheld-" + major + ".tsv";
  }

  static String manifestResource(int major) {
    return "pg-extension-manifest-" + major + ".tsv";
  }

  static String versionsResource(int major) {
    return "pg-extension-versions-" + major + ".tsv";
  }

  static String coreResource(int major) {
    return "pg-core-native-" + major + ".tsv";
  }

  /**
   * The files shipped in this jar for {@code major}, or empty when this release has none for it
   * (the caller refuses with {@code 005}). A file that exists but cannot be read or parsed is a
   * refusal here, never an empty result.
   */
  static Optional<PinnedCatalogue> forMajor(int major) {
    return load(major, PinnedCatalogue.class::getResourceAsStream);
  }

  /** As {@link #forMajor}, from any resource opener: the seam the tests use. */
  static Optional<PinnedCatalogue> load(int major, Function<String, InputStream> open) {
    Optional<String> base = read(open, baselineResource(major));
    Optional<String> members = read(open, manifestResource(major));
    Optional<String> listed = read(open, versionsResource(major));
    Optional<String> natives = read(open, coreResource(major));
    if (base.isEmpty() && members.isEmpty() && listed.isEmpty() && natives.isEmpty()) {
      return Optional.empty();
    }
    String missing =
        base.isEmpty()
            ? baselineResource(major)
            : members.isEmpty()
                ? manifestResource(major)
                : listed.isEmpty()
                    ? versionsResource(major)
                    : natives.isEmpty() ? coreResource(major) : "";
    if (!missing.isEmpty()) {
      throw malformed(missing, 0, "the file is missing while the other pinned files exist");
    }
    return Optional.of(
        of(
            major,
            parseBaseline(baselineResource(major), base.orElseThrow()),
            parseManifest(manifestResource(major), members.orElseThrow()),
            parseVersions(versionsResource(major), listed.orElseThrow()),
            parseCore(coreResource(major), natives.orElseThrow())));
  }

  /** Builds and cross-checks a catalogue: every manifest version has an installable line. */
  static PinnedCatalogue of(
      int major,
      List<Withheld> baseline,
      List<Member> manifest,
      List<Version> versions,
      List<CoreNative> core) {
    if (core.isEmpty()) {
      throw malformed(coreResource(major), 0, "the core record has no line");
    }
    if (baseline.isEmpty()) {
      throw malformed(baselineResource(major), 0, "the baseline has no line");
    }
    if (versions.isEmpty()) {
      throw malformed(versionsResource(major), 0, "the versions list has no line");
    }
    var installable = new HashSet<String>();
    versions.stream()
        .filter(Version::installable)
        .forEach(v -> installable.add(v.extension() + "\t" + v.version()));
    for (Member m : manifest) {
      if (!installable.contains(m.extension() + "\t" + m.version())) {
        throw malformed(
            manifestResource(major),
            0,
            "extension "
                + m.extension()
                + " "
                + m.version()
                + " has members but no ok line in "
                + versionsResource(major));
      }
    }
    return new PinnedCatalogue(major, baseline, manifest, versions, core);
  }

  /**
   * The majors this release ships files for, for a refusal message only: the files themselves are
   * what the gate loads, and a unit test holds this list equal to them.
   */
  static List<Integer> shippedMajors() {
    return List.of(16, 17);
  }

  /** No files: statement 1 then reports only the rules that need none (R2, R4). */
  static PinnedCatalogue none(int major) {
    return new PinnedCatalogue(major, List.of(), List.of(), List.of(), List.of());
  }

  int major() {
    return major;
  }

  /** The normal-form shipped ACL of baseline function {@code oid}. */
  Optional<String> baselineAcl(long oid) {
    return baseline.stream().filter(w -> w.oid() == oid).map(Withheld::acl).findFirst();
  }

  List<Withheld> baseline() {
    return baseline;
  }

  List<Member> manifest() {
    return manifest;
  }

  List<Version> versions() {
    return versions;
  }

  List<CoreNative> core() {
    return core;
  }

  /** Names of extensions with at least one version the image installs. */
  Set<String> installableExtensions() {
    var out = new LinkedHashSet<String>();
    versions.stream().filter(Version::installable).forEach(v -> out.add(v.extension()));
    return out;
  }

  /** True when the image lists {@code extension} but installs none of its versions. */
  boolean listedButNotInstallable(String extension) {
    return versions.stream().anyMatch(v -> v.extension().equals(extension))
        && versions.stream().noneMatch(v -> v.extension().equals(extension) && v.installable());
  }

  /** The installable versions of {@code extension}, in file order, for a message. */
  List<String> installableVersions(String extension) {
    return versions.stream()
        .filter(v -> v.installable() && v.extension().equals(extension))
        .map(Version::version)
        .toList();
  }

  /**
   * The accepted third-party list, checked against this major's installable names (C-PR45-3,
   * revision 4): an entry that equals one ignoring case refuses, because accepting a shipped
   * extension would reopen the launder F41. A name the image lists but cannot install ({@code
   * plperl}) may be accepted.
   */
  void refuseInstallableNames(List<String> accepted) {
    for (String name : accepted) {
      for (String shipped : installableExtensions()) {
        if (shipped.toLowerCase(Locale.ROOT).equals(name.toLowerCase(Locale.ROOT))) {
          throw new ShreddingException(
              ErrorCodes.CONFIG,
              "shredding.jdbc.accepted-third-party-extensions names "
                  + com.housedevinci.shredding.application.LogText.escape(name)
                  + ", an extension the PostgreSQL "
                  + major
                  + " image ships and this module's manifest records. Accepting it would trust"
                  + " a re-created member of "
                  + shipped
                  + " as shipped (path F41). Remove it from the list: shipped extensions are"
                  + " judged against the manifest and need no acceptance.");
        }
      }
    }
  }

  // ---------------------------------------------------------------- parsers

  static List<Withheld> parseBaseline(String file, String text) {
    var out = new ArrayList<Withheld>();
    var oids = new HashSet<Long>();
    int n = 0;
    for (String line : lines(file, text)) {
      n++;
      if (line.startsWith("#")) {
        continue;
      }
      String[] f = columns(file, n, line, 6);
      long oid = oid(file, n, f[0]);
      if (oid >= FIXED_OID_LIMIT) {
        throw malformed(file, n, "oid " + oid + " is not fixed by pg_proc.dat");
      }
      if (!oids.add(oid)) {
        throw malformed(file, n, "oid " + oid + " appears twice");
      }
      if (!f[5].matches("[^,=]+=[A-Za-z]+\\*?(,[^,=]+=[A-Za-z]+\\*?)*")) {
        throw malformed(file, n, "the ACL is not in normal form");
      }
      out.add(
          new Withheld(
              oid, text(file, n, f[1]), text(file, n, f[2]), f[3], flag(file, n, f[4]), f[5]));
    }
    return out;
  }

  static List<Member> parseManifest(String file, String text) {
    var out = new ArrayList<Member>();
    var keys = new HashSet<String>();
    int n = 0;
    for (String line : lines(file, text)) {
      n++;
      if (line.startsWith("#")) {
        continue;
      }
      String[] f = columns(file, n, line, 7);
      if (!keys.add(f[0] + "\t" + f[1] + "\t" + f[2])) {
        throw malformed(file, n, "extension " + f[0] + " " + f[1] + " lists " + f[2] + " twice");
      }
      out.add(
          new Member(
              text(file, n, f[0]),
              text(file, n, f[1]),
              text(file, n, f[2]),
              f[3],
              flag(file, n, f[4]),
              flag(file, n, f[5]),
              supports(file, n, f[6])));
    }
    return out;
  }

  /** The R7 record: one line per core native function, by signature (C-PR45-3-17). */
  static List<CoreNative> parseCore(String file, String text) {
    var out = new ArrayList<CoreNative>();
    var signatures = new HashSet<String>();
    int n = 0;
    for (String line : lines(file, text)) {
      n++;
      if (line.startsWith("#")) {
        continue;
      }
      String[] f = columns(file, n, line, 5);
      if (!signatures.add(f[0])) {
        throw malformed(file, n, "signature " + f[0] + " appears twice");
      }
      if (!f[1].equals("internal") && !f[1].equals("c")) {
        throw malformed(file, n, "the language must be internal or c");
      }
      out.add(
          new CoreNative(
              text(file, n, f[0]),
              f[1],
              text(file, n, f[2]),
              text(file, n, f[3]),
              flag(file, n, f[4])));
    }
    return out;
  }

  /** The support column of a manifest line: empty, or {@code slot=key} items joined by ';'. */
  private static String supports(String file, int n, String text) {
    if (!text.isEmpty() && !text.matches("[a-z]+=[^;=]+\\)(;[a-z]+=[^;=]+\\))*")) {
      throw malformed(file, n, "the support column is not slot=key items joined by ';'");
    }
    return text;
  }

  static List<Version> parseVersions(String file, String text) {
    var out = new ArrayList<Version>();
    var seen = new HashSet<String>();
    var ok = new HashSet<String>();
    var fails = new HashSet<String>();
    int n = 0;
    for (String line : lines(file, text)) {
      n++;
      if (line.startsWith("#")) {
        continue;
      }
      String[] f = columns(file, n, line, 4);
      if (!seen.add(f[0] + "\t" + f[1])) {
        throw malformed(file, n, "extension " + f[0] + " " + f[1] + " appears twice");
      }
      boolean installable;
      switch (f[2]) {
        case "ok" -> {
          if (!f[3].isEmpty()) {
            throw malformed(file, n, "an ok line carries an error");
          }
          installable = true;
          ok.add(f[0]);
        }
        case "fails" -> {
          if (!f[3].startsWith(LOAD_FAILURE)) {
            throw malformed(file, n, "a fails line must carry a \"" + LOAD_FAILURE + "\" error");
          }
          installable = false;
          fails.add(f[0]);
        }
        default -> throw malformed(file, n, "status must be ok or fails");
      }
      out.add(new Version(text(file, n, f[0]), text(file, n, f[1]), installable, f[3]));
    }
    for (String name : ok) {
      if (fails.contains(name)) {
        throw malformed(file, 0, "extension " + name + " has both ok and fails versions");
      }
    }
    return out;
  }

  private static Optional<String> read(Function<String, InputStream> open, String name) {
    try (InputStream in = open.apply(name)) {
      if (in == null) {
        return Optional.empty();
      }
      return Optional.of(new String(in.readAllBytes(), StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "shredding: the pinned file "
              + name
              + " could not be read, so native functions cannot be judged. Unverifiable is not"
              + " clean.",
          e);
    }
  }

  private static List<String> lines(String file, String text) {
    if (text.isEmpty() || !text.endsWith("\n") || text.contains("\r")) {
      throw malformed(file, 0, "the file must be non-empty LF-terminated lines");
    }
    return List.of(text.substring(0, text.length() - 1).split("\n", -1));
  }

  private static String[] columns(String file, int n, String line, int count) {
    String[] f = line.split("\t", -1);
    if (f.length != count) {
      throw malformed(file, n, "expected " + count + " tab-separated columns, found " + f.length);
    }
    return f;
  }

  private static long oid(String file, int n, String text) {
    if (!text.matches("[1-9][0-9]{0,9}")) {
      throw malformed(file, n, "the oid is not a number");
    }
    return Long.parseLong(text);
  }

  private static boolean flag(String file, int n, String text) {
    return switch (text) {
      case "t" -> true;
      case "f" -> false;
      default -> throw malformed(file, n, "a flag must be t or f");
    };
  }

  private static String text(String file, int n, String text) {
    if (text.isEmpty()) {
      throw malformed(file, n, "an empty column");
    }
    return text;
  }

  private static ShreddingException malformed(String file, int line, String why) {
    return new ShreddingException(
        ErrorCodes.SCHEMA_UNVERIFIABLE,
        "shredding: the pinned file "
            + file
            + " is malformed"
            + (line > 0 ? " at line " + line : "")
            + " ("
            + why
            + "), so native functions cannot be judged. It ships in this jar and is generated by"
            + " tools/generate-pinned-catalogue.sh; a changed file means a changed jar."
            + " Unverifiable is not clean.");
  }
}
