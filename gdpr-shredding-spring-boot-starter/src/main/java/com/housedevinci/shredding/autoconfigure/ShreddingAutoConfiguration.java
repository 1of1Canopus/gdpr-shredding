package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore;
import com.housedevinci.shredding.adapter.jdbc.JdbcKeyProvider;
import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.application.DataKeyCache;
import com.housedevinci.shredding.application.ErasureChainVerifier;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.application.FieldCipher;
import com.housedevinci.shredding.application.KeyProvider;
import com.housedevinci.shredding.application.PostErasureHook;
import com.housedevinci.shredding.domain.BlindIndex;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import jakarta.annotation.PreDestroy;
import jakarta.persistence.EntityManagerFactory;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.hibernate.jpa.boot.spi.IntegratorProvider;
import org.hibernate.jpa.boot.spi.JpaSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;

/**
 * Wires the module. Everything a security control depends on is decided here, at startup, and a
 * misconfiguration is a startup failure naming the property.
 */
@AutoConfiguration
@ConditionalOnClass({EntityManagerFactory.class, DataSource.class})
@EnableConfigurationProperties(ShreddingProperties.class)
public class ShreddingAutoConfiguration {

  private static final Logger log = LoggerFactory.getLogger(ShreddingAutoConfiguration.class);

  @Bean
  @ConditionalOnMissingBean
  public Clock shreddingClock() {
    return Clock.systemUTC();
  }

  @Bean
  @ConditionalOnMissingBean
  public RandomSource shreddingRandomSource() {
    return RandomSource.secure();
  }

  @Bean
  @ConditionalOnMissingBean
  public MasterKey shreddingMasterKey(ShreddingProperties properties) {
    return MasterKey.fromBase64("shredding.master-key", properties.getMasterKey());
  }

  @Bean
  @ConditionalOnMissingBean
  public ErasureChain shreddingErasureChain(ShreddingProperties properties) {
    var log0 = properties.getErasureLog();
    if (log0.isUnkeyed()) {
      if (log0.getHmacSecret() != null && !log0.getHmacSecret().isBlank()) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "shredding.erasure-log.unkeyed=true and shredding.erasure-log.hmac-secret are both"
                + " set; pick one.");
      }
      log.warn(
          "shredding: the erasure log is UNKEYED (shredding.erasure-log.unkeyed=true). Its"
              + " integrity then rests only on database privilege separation: anyone who can write"
              + " the table can rewrite the whole chain consistently. Set"
              + " shredding.erasure-log.hmac-secret instead. Separately, the log's subject"
              + " pseudonyms are still an HMAC keyed by shredding.subject-pseudonym.pepper, which"
              + " is required in this mode: without it they would be recomputable by anyone from"
              + " this module's own published canonical form (CIPHER-07).");
      return ErasureChain.unkeyed();
    }
    byte[] secret = requiredSecret("shredding.erasure-log.hmac-secret", log0.getHmacSecret());
    return ErasureChain.keyed(secret, log0.getHmacKeyId());
  }

  @Bean
  @ConditionalOnMissingBean
  public Pseudonymiser shreddingPseudonymiser(ShreddingProperties properties) {
    var log0 = properties.getErasureLog();
    // CIPHER-07: unkeyed mode is about the chain, not about the pseudonym. A constant pepper
    // shipped in the module's own source is a public function, exactly as reversible as SHA-256
    // with no key at all, so unkeyed=true requires its own secret here rather than falling back to
    // one anyone can read out of the jar.
    byte[] secret =
        log0.isUnkeyed()
            ? requiredSecret(
                "shredding.subject-pseudonym.pepper", properties.getSubjectPseudonym().getPepper())
            : requiredSecret("shredding.erasure-log.hmac-secret", log0.getHmacSecret());
    return new Pseudonymiser(secret);
  }

  @Bean
  @ConditionalOnMissingBean
  public DataKeyCache shreddingDataKeyCache(ShreddingProperties properties, Clock clock) {
    var cache = properties.getDataKeyCache();
    return new DataKeyCache(cache.getTtl(), cache.getMaxSize(), clock);
  }

  @Bean
  @ConditionalOnMissingBean
  public KeyProvider shreddingKeyProvider(
      DataSource dataSource, MasterKey masterKey, RandomSource random, Clock clock) {
    JdbcSupport.initializeSchema(dataSource);
    return new JdbcKeyProvider(dataSource, masterKey, random, clock);
  }

  @Bean
  @ConditionalOnMissingBean
  public ShreddedModel shreddedModel(
      EntityManagerFactory entityManagerFactory, ShreddingProperties properties) {
    var entities = new ArrayList<Class<?>>();
    entityManagerFactory.getMetamodel().getEntities().forEach(e -> entities.add(e.getJavaType()));
    return ShreddedModel.scan(
        entities, properties.isAllowSecondLevelCache(), entityManagerFactory.getProperties());
  }

  @Bean
  @ConditionalOnMissingBean
  public FieldCipher shreddingFieldCipher(
      KeyProvider keys, DataKeyCache cache, RandomSource random, ShreddingProperties properties) {
    return new FieldCipher(keys, cache, random, properties.getCrypto().getMaxEncryptionsPerKey());
  }

  @Bean
  @ConditionalOnMissingBean
  public BlindIndex shreddingBlindIndex(ShreddingProperties properties) {
    var index = properties.getBlindIndex();
    if (index.getHmacSecret() == null || index.getHmacSecret().isBlank()) {
      // Not an error yet: an application with no @BlindIndex column never needs it. The event
      // listener refuses at the first indexed write if it is still missing.
      return null;
    }
    return new BlindIndex(
        requiredSecret("shredding.blind-index.hmac-secret", index.getHmacSecret()),
        index.getBits());
  }

  @Bean
  @ConditionalOnMissingBean
  public JdbcErasureStore shreddingErasureStore(
      DataSource dataSource, ErasureChain chain, ShreddedModel model) {
    JdbcSupport.initializeSchema(dataSource);
    return new JdbcErasureStore(dataSource, chain, model.blindIndexColumns());
  }

  @Bean
  @ConditionalOnMissingBean
  public ErasureService shreddingErasureService(
      JdbcErasureStore store,
      DataKeyCache cache,
      Pseudonymiser pseudonymiser,
      ObjectProvider<PostErasureHook> hooks,
      ShreddingProperties properties,
      Clock clock,
      ShreddedModel model) {
    return new ErasureService(
        store,
        cache,
        pseudonymiser,
        hooks.orderedStream().toList(),
        properties.getErasure().getBackupRetention(),
        clock,
        model.entityCount(),
        model.fieldCount());
  }

  @Bean
  @ConditionalOnMissingBean
  public ErasureChainVerifier shreddingErasureChainVerifier(
      JdbcErasureStore store, ShreddingProperties properties) {
    var log0 = properties.getErasureLog();
    var keyring = new LinkedHashMap<String, byte[]>();
    if (!log0.isUnkeyed()) {
      byte[] activeSecret =
          requiredSecret("shredding.erasure-log.hmac-secret", log0.getHmacSecret());
      keyring.put(log0.getHmacKeyId(), activeSecret);
      log0.getHmacKeys()
          .forEach(
              (id, secret) -> {
                byte[] resolved = requiredSecret("shredding.erasure-log.hmac-keys." + id, secret);
                // I3: repeating the active key id here with a different secret would silently
                // replace it in the keyring - the verifier would then accept rows actually signed
                // under the active secret as if they were signed under this one. A repeat with the
                // *same* secret is a harmless duplicate and is allowed.
                if (id.equals(log0.getHmacKeyId())
                    && !java.util.Arrays.equals(resolved, activeSecret)) {
                  throw new ShreddingException(
                      ErrorCodes.CONFIG,
                      "shredding.erasure-log.hmac-keys."
                          + id
                          + " repeats the active key id (shredding.erasure-log.hmac-key-id="
                          + id
                          + ") with a different secret. The keyring cannot hold two secrets for one"
                          + " key id.");
                }
                keyring.put(id, resolved);
              });
    }
    return new ErasureChainVerifier(store, store, Map.copyOf(keyring));
  }

  @Bean
  @ConditionalOnMissingBean
  public ShreddingEventListener.TenantSupplier shreddingTenantSupplier() {
    // No default tenant (control 15): the fallback supplier hands back null, and the listener
    // turns that into SHRED-TENANT-MISSING rather than an empty string.
    return () -> null;
  }

  @Bean
  public HibernatePropertiesCustomizer shreddingHibernateCustomizer(
      ObjectProvider<ShreddedModel> model,
      ShreddingEventListener.TenantSupplier tenantSupplier,
      ObjectProvider<BlindIndex> blindIndex) {
    var listener =
        new ShreddingEventListener(model::getObject, tenantSupplier, blindIndex.getIfAvailable());
    return properties ->
        properties.put(
            JpaSettings.INTEGRATOR_PROVIDER,
            (IntegratorProvider) () -> List.of(new ShreddingIntegrator(listener)));
  }

  @Bean
  public ShreddingStartupCheck shreddingStartupCheck(
      ShreddingProperties properties,
      FieldCipher cipher,
      ShreddedModel model,
      DataSource dataSource) {
    return new ShreddingStartupCheck(properties, cipher, model, dataSource);
  }

  static byte[] requiredSecret(String property, String value) {
    if (value == null || value.isBlank()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          property + " is required. Supply at least 32 bytes through the environment.");
    }
    byte[] raw;
    try {
      raw = Base64.getDecoder().decode(value.strip());
    } catch (IllegalArgumentException notBase64) {
      raw = value.getBytes(StandardCharsets.UTF_8);
    }
    if (raw.length < 32) {
      throw new ShreddingException(
          ErrorCodes.CONFIG, property + " must be at least 32 bytes; it is " + raw.length + ".");
    }
    return raw;
  }

  @PreDestroy
  public void clearRuntime() {
    ShreddingRuntime.clear();
  }
}
