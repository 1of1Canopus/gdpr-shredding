package com.housedevinci.shredding.namegate;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * C-A-9's membership rule, checked rather than assumed: {@link SqlNameLexer#CATCODE_C_KEYWORDS} is
 * a constant captured once from PostgreSQL 16.14's own {@code pg_get_keywords()}, and this test
 * compares it against a live query on the digest the module's own tests pin ({@link #IMAGE}, the
 * same one {@code CipherProbeNamePr13eTest} uses). A drift between the two means the constant is no
 * longer the membership rule it claims to be, and {@link SqlNameLexer#GRAMMAR_TYPES} - which the
 * constant exists to check - would again carry a name the server can resolve.
 */
@Testcontainers
class CatcodeCKeywordsTest {

  private static final String IMAGE =
      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777";

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(DockerImageName.parse(IMAGE).asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @BeforeAll
  static void start() {
    POSTGRES.start();
  }

  @AfterAll
  static void stop() {
    POSTGRES.stop();
  }

  @Test
  void the_catcode_c_constant_matches_a_live_query_on_the_pinned_digest() throws Exception {
    var live = new HashSet<String>();
    try (Connection c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery("SELECT word FROM pg_get_keywords() WHERE catcode = 'C'")) {
      while (rs.next()) {
        live.add(rs.getString(1).toLowerCase(Locale.ROOT));
      }
    }
    assertThat(live)
        .describedAs(
            "SqlNameLexer.CATCODE_C_KEYWORDS must be exactly pg_get_keywords()'s catcode 'C' list"
                + " on the pinned digest, or the constant is not the membership rule it claims to"
                + " be (C-A-9)")
        .isEqualTo(SqlNameLexer.CATCODE_C_KEYWORDS);
  }

  @Test
  void every_grammar_type_is_catcode_c() {
    Set<String> grammarTypes =
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
            "real");
    assertThat(SqlNameLexer.CATCODE_C_KEYWORDS)
        .describedAs(
            "every spelling the length-modifier allowance exempts from the function-call and"
                + " type-position checks must be catcode 'C': the one it must never be allowed to"
                + " carry again is `double`, catcode 'U' (C-A-9)")
        .containsAll(grammarTypes);
    assertThat(SqlNameLexer.CATCODE_C_KEYWORDS).doesNotContain("double");
  }
}
