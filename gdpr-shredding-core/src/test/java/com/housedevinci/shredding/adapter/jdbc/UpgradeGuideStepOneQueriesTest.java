package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review C-32-1: the queries in step 1 of the upgrade guide are run as written against a
 * blind-index table whose only copies sit on a partition (statistics, expression index, extended
 * statistics, publication, trigger, rule) and on a legacy inheritance child. Each must find the
 * copy on the child, because startup checks the whole family.
 */
@Testcontainers
class UpgradeGuideStepOneQueriesTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String[] FIXTURE = {
    "CREATE TABLE customer (id int, email_idx text, k int) PARTITION BY LIST (k)",
    "CREATE TABLE customer_p1 PARTITION OF customer FOR VALUES IN (1)",
    "INSERT INTO customer SELECT g, 'v' || g, 1 FROM generate_series(1, 200) g",
    "CREATE INDEX ON customer_p1 (lower(email_idx))",
    "CREATE STATISTICS st1 ON id, email_idx FROM customer_p1",
    "CREATE PUBLICATION pub FOR TABLE customer",
    "CREATE FUNCTION tf() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
    "CREATE TRIGGER tr AFTER INSERT ON customer_p1 FOR EACH ROW EXECUTE FUNCTION tf()",
    "CREATE RULE rl AS ON INSERT TO customer_p1 DO ALSO NOTHING",
    "CREATE TABLE customer_aud (email_idx text)",
    "CREATE MATERIALIZED VIEW mv AS SELECT email_idx FROM customer",
    "CREATE MATERIALIZED VIEW mvc AS SELECT email_idx FROM customer_p1",
    "ANALYZE customer",
    "ANALYZE customer_p1"
  };

  /** Legacy inheritance: parent "legacy", child "legacy_c" (a different attnum for email_idx). */
  private static final String[] LEGACY_FIXTURE = {
    "CREATE TABLE legacy (id int, email_idx text, k int)",
    "CREATE TABLE legacy_c (extra int) INHERITS (legacy)",
    "ALTER TABLE legacy_c DROP COLUMN extra",
    "INSERT INTO legacy_c SELECT g, 'v' || g, 1 FROM generate_series(1, 200) g",
    "CREATE INDEX ON legacy_c (lower(email_idx))",
    "CREATE STATISTICS st2 ON id, email_idx FROM legacy_c",
    "CREATE PUBLICATION pub2 FOR TABLE legacy_c",
    "CREATE FUNCTION tf() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
    "CREATE TRIGGER tr2 AFTER INSERT ON legacy_c FOR EACH ROW EXECUTE FUNCTION tf()",
    "CREATE RULE rl2 AS ON INSERT TO legacy_c DO ALSO NOTHING",
    "CREATE TABLE legacy_aud (email_idx text)",
    "CREATE MATERIALIZED VIEW mvl AS SELECT email_idx FROM legacy",
    "CREATE MATERIALIZED VIEW mvlc AS SELECT email_idx FROM legacy_c",
    "ANALYZE legacy",
    "ANALYZE legacy_c"
  };

  @Test
  void the_step_one_queries_find_the_copies_on_the_partition() throws Exception {
    String all = String.join("\n", run(FIXTURE, "customer"));
    assertThat(all)
        .contains("customer_p1|email_idx|-1") // statistics target on the partition
        .contains("public|customer_p1|email_idx|f") // pg_stats on the partition
        .contains("customer_p1_lower_idx") // expression index on the partition
        .contains("customer_p1|st1") // extended statistics on the partition
        .contains("customer_p1|tr|O") // trigger
        .contains("customer_p1|rl") // rule
        .contains("pub|t|customer_p1|") // publication reports the partition
        .contains("customer_aud|") // leftover table
        .contains("materialized view mv|") // dependents: view over the root
        .contains("materialized view mvc|"); // dependents: view over the partition (C-32-8)
  }

  @Test
  void the_step_one_queries_find_the_copies_on_the_inheritance_child() throws Exception {
    List<String> found = run(LEGACY_FIXTURE, "legacy");
    String all = String.join("\n", found);
    assertThat(all)
        .contains("legacy_c|email_idx|-1")
        .contains("public|legacy_c|email_idx|f")
        .contains("legacy_c_lower_idx")
        .contains("legacy_c|st2")
        .contains("legacy_c|tr2|O")
        .contains("legacy_c|rl2")
        .contains("pub2|t|legacy_c|")
        .contains("legacy_aud|")
        .contains("materialized view mvl|")
        .contains("materialized view mvlc|"); // C-32-8, C-32-9
  }

  private static List<String> run(String[] fixture, String table) throws Exception {
    String guide = Files.readString(Path.of("..", "docs", "upgrading-0.2.0.md"));
    String step = guide.substring(guide.indexOf("### 1. Record"), guide.indexOf("### 2. Move"));
    List<String> statements = new ArrayList<>();
    Matcher m = Pattern.compile("```sql\n(.*?)```", Pattern.DOTALL).matcher(step);
    while (m.find()) {
      for (String s : m.group(1).replaceAll("(?m)^--.*$", "").split(";")) {
        if (!s.isBlank()) {
          statements.add(
              s.trim()
                  .replace("<runtime role>", POSTGRES.getUsername())
                  .replace("public.customer", "public." + table));
        }
      }
    }
    try (Connection c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement()) {
      st.execute("DROP SCHEMA IF EXISTS public CASCADE");
      st.execute("CREATE SCHEMA public");
      st.execute("SET search_path = public");
      for (String f : fixture) {
        st.execute(f);
      }
      List<String> found = new ArrayList<>();
      for (String q : statements) {
        if (q.startsWith("CREATE TEMPORARY TABLE fam")) {
          st.execute(q);
        } else if (q.startsWith("SELECT") && !q.contains("shredding")) {
          try (ResultSet rs = st.executeQuery(q)) {
            StringBuilder row = new StringBuilder();
            while (rs.next()) {
              for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
                row.append(rs.getString(i)).append('|');
              }
              row.append('\n');
            }
            found.add(row.toString());
          }
        }
      }
      // the leftover-table query names neither the partition nor the view
      assertThat(found).contains(table + "_aud|\n");
      return found;
    }
  }
}
