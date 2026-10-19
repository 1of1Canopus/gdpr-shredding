package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import javax.sql.DataSource;

/**
 * The schema {@link JdbcSupport#verifySchema} resolved with {@code current_schema()} and then
 * verified, object by object, on that same connection.
 *
 * <p>Design §16 (finding C-D2-1). Every statement this module issues is qualified with this name,
 * so none of them depends on {@code search_path} at parse time. Three attacks close together as a
 * result, and all three were reproduced against the unqualified form: a second schema the runtime
 * role owns holding same-named unguarded copies and placed first on the path; a {@code
 * pg_temp.shredding_erasure} created by the runtime role itself while it holds {@code TEMPORARY};
 * and a plain {@code SET search_path} issued between two adapter calls on a pooled connection. In
 * every one of them {@code current_schema()} still answered {@code public} and boot verification
 * still answered clean, while the appends went somewhere else.
 *
 * <p><b>A class with a package-private constructor, not a record</b> (finding C-13-3). This type is
 * the capability that stands for "this schema was verified": the adapters will not construct
 * without one, which is what closes the "a caller hands core its own {@code DataSource}" row of the
 * integration surface. A record's canonical constructor is public, so {@code new
 * VerifiedSchema("public")} compiled anywhere and that row's control was a naming convention rather
 * than a capability. Only {@link SchemaVerification}, in this package, produces one.
 *
 * <p>The name is never caller input: it comes from the server's own {@code current_schema()} on the
 * connection verification ran on. It is quoted anyway, with {@code "} doubled, so an operator whose
 * schema is {@code Public}, {@code my schema} or {@code s"q} gets the relation they verified rather
 * than a parse error or, worse, a different relation.
 *
 * <p><b>Bound to the DataSource it was verified on</b> (finding C-PR-1). A schema name alone said
 * "this schema was verified" but not "on which database": a store built from {@code gate.schema()}
 * and a second {@code DataSource} wrote keys, erasure log, tombstones and the anchor to a database
 * whose guards nobody checked, while the boot log said verified. The capability now carries the
 * {@code DataSource} object verification ran on, and the stores take their pool from it. There is
 * exactly one constructor and it requires both: there is no way to mint a name-only capability.
 * Equality follows the pool by identity, never by {@code DataSource.equals}.
 *
 * <p><b>Bound to what the pool reached</b> (finding C-PR-1b). The pool object staying the same does
 * not mean its target did: a routing pool, a refresh-scoped proxy, a retargeted delegate or a
 * mutable URL can reach another database later through the very object that was verified. The
 * capability therefore also carries the {@link DatabaseIdentity} verification read - cluster,
 * database, schema, login role, current role - and every store connection is compared with it
 * before its work ({@code SHRED-SCHEMA-012}).
 *
 * <p><b>The login marker</b> (finding C-PR-1c). Each verification draws a random 128-bit value. The
 * per-call check stores it in a backend once that backend's login role is found to be the verified
 * one, so later calls on the backend skip the costly read ({@link DatabaseIdentity}). It is a check
 * value, not a credential: knowing it helps only a superuser login, which can already forge every
 * fact of the check. It is never part of {@link #toString}, {@link #equals} or any message.
 */
public final class VerifiedSchema {

  private static final SecureRandom MARKERS = new SecureRandom();

  private final String name;
  private final DataSource dataSource;
  private final DatabaseIdentity identity;
  private final String loginMarker;

  VerifiedSchema(String name, DataSource dataSource, DatabaseIdentity identity) {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(dataSource, "dataSource");
    Objects.requireNonNull(identity, "identity");
    if (name.isBlank()) {
      throw new IllegalArgumentException("verified schema name is blank");
    }
    this.name = name;
    this.dataSource = dataSource;
    this.identity = identity;
    this.loginMarker = newMarker();
  }

  private static String newMarker() {
    byte[] bytes = new byte[16];
    MARKERS.nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }

  /** This verification's login marker (C-PR-1c). Package-private, like the pool. */
  String loginMarker() {
    return loginMarker;
  }

  /** What verification's connection reached (C-PR-1b). Package-private, like the pool. */
  DatabaseIdentity identity() {
    return identity;
  }

  /**
   * The {@code DataSource} object this schema was verified on. Package-private on purpose: only the
   * stores of this package read it, and they compare it by identity ({@code ==}).
   */
  DataSource dataSource() {
    return dataSource;
  }

  /** The schema {@code current_schema()} resolved to, as the server spelled it. */
  public String name() {
    return name;
  }

  /**
   * C-PR-1: the check of every constructor that still takes a {@code DataSource}. Identity ({@code
   * !=}), never {@code equals} and never the URL: a second pool to the same database can log in as
   * another role, and an application class can override {@code equals}. Returns the schema so a
   * delegating constructor can run it inside its {@code this(...)} call, before the target
   * constructor opens any connection.
   *
   * @param store the store's simple class name, for the message
   */
  static VerifiedSchema requireVerifiedOn(DataSource given, VerifiedSchema schema, String store) {
    Objects.requireNonNull(given, "dataSource");
    Objects.requireNonNull(schema, "schema");
    if (given != schema.dataSource) {
      throw new ShreddingException(
          ErrorCodes.STORE_DATASOURCE_UNVERIFIED,
          "shredding: "
              + store
              + " was given a DataSource that is not the one its VerifiedSchema was verified on."
              + " Its writes would go to a database whose guards were never checked, so it"
              + " refuses. Build it with new "
              + store
              + "(schema, ...) and no DataSource: in Spring, schema ="
              + " ShreddingSchemaGate.schema(); without Spring, schema ="
              + " JdbcSupport.verifySchema(yourDataSource).schema(). ("
              + ErrorCodes.STORE_DATASOURCE_UNVERIFIED
              + ")");
    }
    return schema;
  }

  /** {@code "myschema"."shredding_erasure"} - both parts quoted, never interpolated bare. */
  public String qualify(String relation) {
    Objects.requireNonNull(relation, "relation");
    return quote(name) + "." + quote(relation);
  }

  private static String quote(String identifier) {
    return "\"" + identifier.replace("\"", "\"\"") + "\"";
  }

  /**
   * Same name, the same {@code DataSource} object and the same {@link DatabaseIdentity}. Two
   * verifications through two different {@code DataSource} objects are not equal, even on the same
   * database: a second pool can log in as another role. {@code DataSource.equals} is never
   * consulted, because an application class can override it to answer true.
   */
  @Override
  public boolean equals(Object other) {
    return other instanceof VerifiedSchema that
        && name.equals(that.name)
        && dataSource == that.dataSource
        && identity.equals(that.identity);
  }

  @Override
  public int hashCode() {
    return 31 * (31 * name.hashCode() + System.identityHashCode(dataSource)) + identity.hashCode();
  }

  /**
   * The name only. The pool's own {@code toString} can carry a URL or a user, so it is left out.
   */
  @Override
  public String toString() {
    return name;
  }
}
