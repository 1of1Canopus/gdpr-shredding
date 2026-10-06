package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.copies.enversok.EnvOkNote;
import com.housedevinci.shredding.autoconfigure.copies.enversok.EnversFirstIntegrator;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import jakarta.persistence.EntityManagerFactory;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * The mapping leg of audit-table coverage (design section 3, rows 1-8, 12, 33-36, 43): every copy
 * of a blind-index column that Hibernate or Hibernate Envers writes refuses startup with {@code
 * SHRED-SCHEMA-010}, read from the runtime metamodel, before any listener-order check. One test per
 * path, named as in the design's table. Fixtures in {@code copies.*}, one package per path.
 */
@Testcontainers
class CopyMappingStarterTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  static class Tenant {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.enversidx.EnvIdxNote.class)
  static class EnvIdxApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.enverswhole.EnvWholeNote.class)
  static class EnvWholeApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.enversfield.EnvFieldNote.class)
  static class EnvFieldApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.enversschema.EnvSchemaNote.class)
  static class EnvSchemaApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.nativeidx.NatIdxNote.class)
  static class NatIdxApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.nativeexcl.NatExclNote.class)
  static class NatExclApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses = com.housedevinci.shredding.autoconfigure.copies.temporal.TempNote.class)
  static class TempApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses = com.housedevinci.shredding.autoconfigure.copies.elemcoll.ElemNote.class)
  static class ElemApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses = com.housedevinci.shredding.autoconfigure.copies.assoc.AssocNote.class)
  static class AssocApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses = com.housedevinci.shredding.autoconfigure.copies.twoentity.TwoNote.class)
  static class TwoApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses = com.housedevinci.shredding.autoconfigure.copies.embedded.EmbNote.class)
  static class EmbApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.enversoverride.OverNote.class)
  static class OverApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.temporalexcl.TempExclNote.class)
  static class TempExclApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses = com.housedevinci.shredding.autoconfigure.copies.twoplain.PlainNote.class)
  static class TwoPlainApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses = com.housedevinci.shredding.autoconfigure.copies.nativesec.SecNote.class)
  static class NatSecApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.nativesecexcl.SecNote.class)
  static class NatSecExclApp extends Tenant {}

  /** The documented composition: Envers' integrator first, this module's listener last. */
  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = EnvOkNote.class)
  static class EnvOkApp extends Tenant {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    HibernatePropertiesCustomizer enversFirst() {
      return props ->
          props.put(
              org.hibernate.jpa.boot.spi.JpaSettings.INTEGRATOR_PROVIDER,
              (org.hibernate.jpa.boot.spi.IntegratorProvider)
                  () -> List.of(new EnversFirstIntegrator()));
    }
  }

  /**
   * A context that refuses to start never runs create-drop's drop, and a table it left that holds
   * an index column and revision columns is, by shape, a copy for every later fixture (row 45).
   * Each test starts from an empty schema.
   */
  @BeforeEach
  void emptySchema() throws SQLException {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      st.execute("DROP SCHEMA IF EXISTS audit CASCADE");
      st.execute("DROP SCHEMA public CASCADE");
      st.execute("CREATE SCHEMA public");
    }
  }

  // ------------------------------------------------------------------- Hibernate Envers

  @Test
  void e1_envers_auto_registered_audited_index_is_refused_naming_envers_and_column() {
    ShreddingException refusal = refusal(EnvIdxApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessage(
            "shredding: Hibernate Envers copies the blind-index column public.env_idx_note.email_idx"
                + " (@BlindIndex EnvIdxNote.emailIndex) into its audit table"
                + " public.env_idx_note_aud. An erasure clears the index in public.env_idx_note"
                + " only, so every audit row keeps the erased subject's index, matchable with the"
                + " application's index secret. Mark EnvIdxNote.emailIndex @NotAudited, then clear"
                + " the copies already written: UPDATE public.env_idx_note_aud SET email_idx ="
                + " NULL; ALTER TABLE public.env_idx_note_aud DROP COLUMN email_idx.");
  }

  @Test
  void e2_envers_manual_mode_audited_index_is_refused() {
    ShreddingException refusal =
        refusal(
            EnvIdxApp.class, "spring.jpa.properties.hibernate.envers.autoRegisterListeners=false");

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal).hasMessageContaining("into its audit table public.env_idx_note_aud");
  }

  @Test
  void e3_envers_whole_entity_audited_refusal_names_envers() {
    ShreddingException refusal = refusal(EnvWholeApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.CONFIG);
    assertThat(refusal)
        .hasMessage(
            "shredding: Hibernate Envers audits the @Shredded field EnvWholeNote.email: its audit"
                + " entity EnvWholeNote_AUD (table public.env_whole_note_aud) maps the column"
                + " through"
                + " com.housedevinci.shredding.autoconfigure.copies.enverswhole.EnvWholeNote$EmailConverter."
                + " An audited ciphertext column is not supported. Mark the field @NotAudited, and"
                + " mark every @BlindIndex field of EnvWholeNote @NotAudited too: an audited blind"
                + " index survives every erasure and is refused (SHRED-SCHEMA-010). Then register"
                + " Envers as docs/index.md \"Using Hibernate Envers\" shows; its default"
                + " registration is refused on listener order.");
  }

  @Test
  void e4_envers_field_level_audited_index_is_refused() {
    ShreddingException refusal = refusal(EnvFieldApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining("Hibernate Envers copies the blind-index column")
        .hasMessageContaining("public.env_field_note.email_idx");
  }

  @Test
  void e6_envers_audit_table_in_other_schema_is_named() {
    ShreddingException refusal =
        refusal(
            EnvSchemaApp.class, "spring.jpa.properties.hibernate.hbm2ddl.create_namespaces=true");

    assertThat(refusal)
        .hasMessageContaining("into its audit table audit.env_schema_note_history.")
        .hasMessageContaining("UPDATE audit.env_schema_note_history SET email_idx = NULL;");
  }

  @Test
  void e8_envers_documented_composition_boots_erases_and_audit_holds_no_index() throws Exception {
    try (ConfigurableApplicationContext ctx =
        builder(
                EnvOkApp.class,
                "spring.jpa.properties.hibernate.envers.autoRegisterListeners=false")
            .run()) {
      persist(ctx, new EnvOkNote(1L, "s1", "org-b", "a@b.test"));
      assertThat(count("SELECT count(*) FROM public.env_ok_note_aud")).isEqualTo(1);
      assertThat(
              count(
                  "SELECT count(*) FROM information_schema.columns WHERE table_name ="
                      + " 'env_ok_note_aud' AND column_name IN ('email', 'email_idx')"))
          .isZero();

      var result =
          ctx.getBean(ErasureService.class)
              .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("s1"), "dpo", "art 17"));

      assertThat(result.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
      assertThat(count("SELECT count(*) FROM public.env_ok_note WHERE email_idx IS NOT NULL"))
          .isZero();
    }
  }

  @Test
  void e11_blind_index_inside_embeddable_is_refused() {
    ShreddingException refusal = refusal(EmbApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.CONFIG);
    assertThat(refusal)
        .hasMessageStartingWith(
            "@BlindIndex on Contact.phoneIndex, inside an @Embeddable used by EmbNote.contact, is not"
                + " supported");
  }

  @Test
  void e14_second_entity_on_same_table_audits_index_is_refused() {
    ShreddingException refusal = refusal(TwoApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining(
            "Hibernate Envers copies the blind-index column public.two_note.email_idx through"
                + " entity TwoNoteView (attribute emailIndex), which maps the same table, into its"
                + " audit table public.two_note_aud.")
        .hasMessageContaining("Mark TwoNoteView.emailIndex @NotAudited");
  }

  // ------------------------------------------------------ Hibernate's own audit and history

  @Test
  void n1_native_audited_index_is_refused() {
    ShreddingException refusal = refusal(NatIdxApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageStartingWith(
            "shredding: Hibernate audits the blind-index column public.nat_idx_note.email_idx"
                + " (@BlindIndex NatIdxNote.emailIndex): @org.hibernate.annotations.Audited on"
                + " NatIdxNote writes it into")
        .hasMessageContaining("Mark the field @Audited.Excluded")
        .hasMessageNotContaining("Envers");
  }

  @Test
  void n4_native_audited_index_excluded_admits() {
    try (ConfigurableApplicationContext ctx = builder(NatExclApp.class).run()) {
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
      assertThat(ctx.getBean(ShreddedModel.class).copySignatures().named())
          .anySatisfy(n -> assertThat(n.kind()).isEqualTo("audit"));
    }
  }

  @Test
  void n2_temporal_history_table_index_is_refused() {
    ShreddingException refusal =
        refusal(
            Temp.class, "spring.jpa.properties.hibernate.temporal.table_strategy=HISTORY_TABLE");

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining("Hibernate keeps history of TempNote in")
        .hasMessageContaining("(@Temporal, history-table strategy), which holds the blind-index")
        .hasMessageNotContaining("Envers");
  }

  @Test
  void n3_temporal_in_table_history_is_refused() {
    ShreddingException refusal =
        refusal(Temp.class, "spring.jpa.properties.hibernate.temporal.table_strategy=SINGLE_TABLE");

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining(
            "Hibernate keeps history of TempNote inside public.temp_note itself (@Temporal,"
                + " single-table strategy).");
  }

  @Test
  void e5_envers_audit_override_inherited_index_is_refused() {
    ShreddingException refusal = refusal(OverApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining(
            "Hibernate Envers copies the blind-index column public.over_note.email_idx (@BlindIndex"
                + " OverNote.emailIndex) into its audit table public.over_note_aud.");
  }

  @Test
  void e7_envers_validity_strategy_store_at_delete_index_not_audited_admits_and_erases()
      throws Exception {
    try (ConfigurableApplicationContext ctx =
        builder(
                EnvOkApp.class,
                "spring.jpa.properties.hibernate.envers.autoRegisterListeners=false",
                "spring.jpa.properties.org.hibernate.envers.audit_strategy="
                    + "org.hibernate.envers.strategy.internal.ValidityAuditStrategy",
                "spring.jpa.properties.org.hibernate.envers.store_data_at_delete=true")
            .run()) {
      persist(ctx, new EnvOkNote(7L, "s7", "org-b", "a@b.test"));
      var result =
          ctx.getBean(ErasureService.class)
              .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("s7"), "dpo", "art 17"));

      assertThat(result.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
      assertThat(
              count(
                  "SELECT count(*) FROM information_schema.columns WHERE table_name ="
                      + " 'env_ok_note_aud' AND column_name IN ('email', 'email_idx', 'revend')"))
          .describedAs("the validity strategy adds REVEND and no index column")
          .isEqualTo(1);
    }
  }

  @Test
  void e16_second_entity_unaudited_is_admitted() {
    try (ConfigurableApplicationContext ctx = builder(TwoPlainApp.class).run()) {
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
    }
  }

  @Test
  void n6_temporal_excluded_index_admitted_only_if_history_table_lacks_the_column()
      throws Exception {
    Throwable thrown =
        catchThrowable(
            () ->
                builder(
                        TempExclApp.class,
                        "spring.jpa.properties.hibernate.temporal.table_strategy=HISTORY_TABLE",
                        // create, not create-drop: the history table must outlive the refused
                        // context to be measured.
                        "spring.jpa.hibernate.ddl-auto=create")
                    .run()
                    .close());
    long historyColumns =
        count(
            "SELECT count(*) FROM information_schema.columns WHERE table_name ="
                + " 'temp_excl_note_history' AND column_name = 'email_idx'");
    System.out.println("N6 history table holds email_idx: " + historyColumns + ", " + thrown);
    if (historyColumns == 0) {
      assertThat(thrown).describedAs("excluded and absent from history: admitted").isNull();
    } else {
      // Hibernate kept the column in the history table despite the exclusion: the catalogue leg
      // refuses it by name, so exclusion alone is never trusted (design 3a.3).
      ShreddingException refusal = null;
      for (Throwable t = thrown; t != null; t = t.getCause()) {
        if (t instanceof ShreddingException s) {
          refusal = s;
        }
      }
      assertThat(refusal).isNotNull();
      assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
      assertThat(refusal).hasMessageContaining("temp_excl_note_history has a column email_idx");
    }
  }

  @Test
  void n5_native_audited_secondary_table_index_is_refused() {
    ShreddingException refusal = refusal(NatSecApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining(
            "Hibernate audits the blind-index column public.nativesec_note.email_idx (@BlindIndex"
                + " SecNote.emailIndex): @org.hibernate.annotations.Audited on SecView writes it"
                + " into")
        .hasMessageContaining("nativesec_trail on every insert and update");
  }

  @Test
  void n5b_excluded_secondary_index_with_a_leftover_audit_column_is_refused() throws Exception {
    try (ConfigurableApplicationContext ctx =
        builder(NatSecExclApp.class, "spring.jpa.hibernate.ddl-auto=create").run()) {
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
    }
    // The column an earlier, unexcluded mapping wrote into the secondary audit table.
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      st.execute(
          "CREATE TABLE IF NOT EXISTS public.nativesecexcl_trail (id bigint, rev integer,"
              + " revtype smallint)");
      st.execute("ALTER TABLE public.nativesecexcl_trail ADD COLUMN IF NOT EXISTS email_idx bytea");
    }

    ShreddingException refusal = refusal(NatSecExclApp.class, "spring.jpa.hibernate.ddl-auto=none");

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining(
            "public.nativesecexcl_trail has a column email_idx and is the audit table Hibernate"
                + " writes for public.nativesecexcl_note.");
  }

  @Test
  void e19_envers_off_leftover_audit_table_under_configured_names_is_refused() throws Exception {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      st.execute("CREATE SCHEMA audit");
      // No revision columns: only the configured name can identify it.
      st.execute("CREATE TABLE audit.pre_env_idx_note_hist (id bigint, email_idx bytea)");
    }

    ShreddingException refusal =
        refusal(
            EnvIdxApp.class,
            "spring.jpa.properties.hibernate.integration.envers.enabled=false",
            "spring.jpa.properties.org.hibernate.envers.audit_table_prefix=pre_",
            "spring.jpa.properties.org.hibernate.envers.audit_table_suffix=_hist",
            "spring.jpa.properties.org.hibernate.envers.default_schema=audit");

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining(
            "audit.pre_env_idx_note_hist has a column email_idx and is the audit table Hibernate"
                + " Envers writes for public.env_idx_note.");
  }

  // ---------------------------------------------------------------------- associations

  @Test
  void f2_association_referencing_index_column_without_constraint_is_refused() {
    ShreddingException refusal = refusal(AssocApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining(
            "shredding: entity AssocOrder maps column customer_email_idx of public.assoc_order as a"
                + " reference to public.assoc_note.email_idx, the blind-index column of AssocNote"
                + " (attribute AssocOrder.customer). public.assoc_order therefore holds index"
                + " values, with or without a foreign key, and no erasure reaches it. Reference"
                + " AssocNote by its identifier instead.");
  }

  @Test
  void f3_element_collection_keyed_on_index_column_is_refused() {
    ShreddingException refusal = refusal(ElemApp.class);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageContaining(
            "maps column note_email_idx of public.elem_note_tag as a reference to"
                + " public.elem_note.email_idx");
  }

  // ---------------------------------------------------------------------------- helpers

  /** Alias so the temporal tests read as the design names them. */
  static class Temp extends TempApp {}

  private ShreddingException refusal(Class<?> app, String... extra) {
    Throwable thrown = catchThrowable(() -> builder(app, extra).run().close());
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s;
      }
    }
    throw new AssertionError("no ShreddingException in the cause chain", thrown);
  }

  private SpringApplicationBuilder builder(Class<?> app, String... extra) {
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(
            Stream.concat(
                    Stream.of(
                        "shredding.master-key=" + b64("copy-mapping-master-key-32-bytes"),
                        "shredding.jdbc.initialize-schema=true",
                        "shredding.jdbc.allow-privileged-runtime-role=true",
                        "shredding.erasure-log.hmac-secret="
                            + b64("copy-mapping-chain-secret-32-byte"),
                        "shredding.blind-index.hmac-secret="
                            + b64("copy-mapping-index-secret-32-byte"),
                        "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "spring.datasource.username=" + POSTGRES.getUsername(),
                        "spring.datasource.password=" + POSTGRES.getPassword(),
                        "spring.data.jpa.repositories.enabled=false",
                        "spring.jpa.hibernate.ddl-auto=create-drop",
                        "spring.jpa.properties.hibernate.dialect="
                            + "org.hibernate.dialect.PostgreSQLDialect"),
                    Stream.of(extra))
                .toArray(String[]::new));
  }

  private static void persist(ConfigurableApplicationContext ctx, Object entity) {
    var em = ctx.getBean(EntityManagerFactory.class).createEntityManager();
    try {
      em.getTransaction().begin();
      em.persist(entity);
      em.getTransaction().commit();
    } finally {
      em.close();
    }
  }

  private static long count(String sql) throws SQLException {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getLong(1) : -1L;
    }
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }
}
