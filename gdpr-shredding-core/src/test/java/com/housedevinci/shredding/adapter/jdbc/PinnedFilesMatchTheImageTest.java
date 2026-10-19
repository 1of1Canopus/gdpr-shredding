package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The pinned files in the jar are what the pinned images give, byte for byte (C-PR45-3, revision 4,
 * ruling items 13 and 16). Each image is generated once, by the same generator the tool script
 * runs, in a pristine container; a digest bump that changes the record turns these red.
 */
class PinnedFilesMatchTheImageTest {

  private static final Map<Integer, PinnedCatalogueGenerator.Output> GENERATED = new HashMap<>();

  private static synchronized PinnedCatalogueGenerator.Output generated(int major)
      throws SQLException {
    var out = GENERATED.get(major);
    if (out == null) {
      try (var pg = TwoRoleCluster.pristine(TwoRoleCluster.image(major))) {
        pg.start();
        out = PinnedCatalogueGenerator.generate(pg);
      }
      GENERATED.put(major, out);
    }
    return out;
  }

  private static String shipped(String name) throws IOException {
    try (InputStream in = PinnedCatalogue.class.getResourceAsStream(name)) {
      assertThat(in).describedAs(name + " ships in the jar").isNotNull();
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void initdb_baseline_file_equals_the_live_record_on_each_pin(int major) throws Exception {
    assertThat(generated(major).baseline())
        .isEqualTo(shipped(PinnedCatalogue.baselineResource(major)));
  }

  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void extension_manifest_file_equals_a_pristine_install_on_each_pin(int major) throws Exception {
    assertThat(generated(major).manifest())
        .isEqualTo(shipped(PinnedCatalogue.manifestResource(major)));
  }

  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void extension_versions_file_equals_the_image(int major) throws Exception {
    assertThat(generated(major).versions())
        .isEqualTo(shipped(PinnedCatalogue.versionsResource(major)));
  }

  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void pristine_install_of_every_available_extension_version_gives_no_r5_row(int major)
      throws Exception {
    // The generator refuses on any R5 row; reaching here means none. No other leg fires either:
    // the false-refusal count of R4, leg 3 and every other rule on a clean install is zero.
    var out = generated(major);
    assertThat(out.databasesJudged()).isGreaterThan(150);
    assertThat(out.otherLegRows()).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void generator_installs_under_the_default_search_path(int major) throws Exception {
    String versions = generated(major).versions();
    for (String ext : new String[] {"pg_stat_statements", "dblink", "tablefunc"}) {
      assertThat(versions).containsPattern("(?m)^" + ext + "\t[^\t]+\tok\t$");
      assertThat(versions).doesNotContainPattern("(?m)^" + ext + "\t[^\t]+\tfails\t");
    }
    assertThat(versions).contains("plpgsql\t1.0\tok\t\n");
    assertThat(versions.lines().filter(l -> l.contains("\tfails\t")).count()).isEqualTo(14);
  }
}
