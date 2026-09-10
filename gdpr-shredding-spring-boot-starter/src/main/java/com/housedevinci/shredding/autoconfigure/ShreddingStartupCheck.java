package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.application.FieldCipher;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * Publishes the runtime the converters read, and says out loud, at <em>every</em> startup, which
 * weaker modes are on. Not once, not on the first request: an operator who reads one boot log a
 * month must see it in that log.
 */
public final class ShreddingStartupCheck implements InitializingBean {

  private static final Logger log = LoggerFactory.getLogger(ShreddingStartupCheck.class);

  private final ShreddingProperties properties;
  private final FieldCipher cipher;
  private final ShreddedModel model;
  private final DataSource dataSource;
  private final EntityManagerFactory entityManagerFactory;
  private final ShreddingEventListener shreddingEventListener;

  public ShreddingStartupCheck(
      ShreddingProperties properties,
      FieldCipher cipher,
      ShreddedModel model,
      DataSource dataSource,
      EntityManagerFactory entityManagerFactory,
      ShreddingEventListener shreddingEventListener) {
    this.properties = properties;
    this.cipher = cipher;
    this.model = model;
    this.dataSource = dataSource;
    this.entityManagerFactory = entityManagerFactory;
    this.shreddingEventListener = shreddingEventListener;
  }

  @Override
  public void afterPropertiesSet() {
    ShreddingRuntime.set(new ShreddingRuntime(cipher, properties.getErasedValue().getPolicy()));
    refuseIfVerifierNotRegisteredFirst();

    if (properties.isDevMode()) {
      log.warn(
          "shredding: shredding.dev-mode=true. Data keys may be held in memory and lost on"
              + " restart, which erases every subject at once. Never in production.");
    }
    if (properties.isAllowSecondLevelCache()) {
      log.warn(
          "shredding: shredding.allow-second-level-cache=true. A cached @Shredded entity keeps"
              + " serving the decrypted value after the subject's key is destroyed, so an erasure"
              + " is invisible until the cache region is evicted.");
    }
    if (properties.getErasedValue().getPolicy() == ErasedValuePolicy.NULL) {
      log.warn(
          "shredding: shredding.erased-value.policy=null. An erased field is then indistinguishable"
              + " from one that was never filled in, and application code cannot tell the"
              + " difference. Prefer sentinel or exception.");
    }
    if (properties.getErasedValue().getPolicy() == ErasedValuePolicy.SENTINEL
        && !model.fieldsWithoutSentinel().isEmpty()) {
      // Dollar's ruling on QUESTIONS #5: no fake sentinel values, but nobody should discover this
      // from a null pointer at three in the morning.
      log.warn(
          "shredding: shredding.erased-value.policy=sentinel, but these field(s) have a type with"
              + " no value that can stand for \"erased\" and will read as null once their subject"
              + " is erased: {}. Set shredding.erased-value.policy=exception if the application"
              + " cannot tell an erased value from one that was never filled in.",
          String.join(", ", model.fieldsWithoutSentinel()));
    }
    if (properties.getErasureLog().isUnkeyed()) {
      log.warn(
          "shredding: shredding.erasure-log.unkeyed=true. The erasure log's integrity rests only on"
              + " database privilege separation.");
    }
    // L3: the append-only triggers stop the runtime role; they cannot stop the table's owner,
    // who can ALTER TABLE ... DISABLE TRIGGER and defeat control 8. SECURITY-NOTES.md prescribes
    // running with a role that only has INSERT/SELECT; this is the check that says out loud when
    // that prescription was not followed, instead of leaving
    // JdbcSupport.runtimeRoleOwnsErasureTable
    // correct, tested and uncalled.
    if (JdbcSupport.runtimeRoleOwnsErasureTable(dataSource)) {
      log.warn(
          "shredding: the database role running this application owns shredding_erasure. That"
              + " role can ALTER TABLE ... DISABLE TRIGGER and remove the append-only protection"
              + " (control 8). Run with a role that has only INSERT and SELECT on"
              + " shredding_erasure, shredding_erasure_anchor and shredding_erased_subject.");
    }
    log.info(
        "shredding: {} shredded field(s) across {} entity type(s), {} blind-index column(s),"
            + " data-key cache ttl {}, backup retention {}",
        model.fieldCount(),
        model.entityCount(),
        model.blindIndexFields().size(),
        properties.getDataKeyCache().getTtl(),
        properties.getErasure().getBackupRetention());
  }

  /**
   * S-6 (Cipher sixth pass). {@code ShreddingHibernateCustomizer} composes with whatever {@code
   * IntegratorProvider} another library or the application already installed, so this module's
   * listener is never silently discarded - but composing is a best effort, not a proof: nothing
   * checked, until now, that the composition actually reached Hibernate and that this module's
   * {@code POST_LOAD} listener is still the first one called. Run once, after the {@code
   * SessionFactory} is actually built (this bean depends on {@code EntityManagerFactory}, so Spring
   * has already finished building it by the time this runs), against the real, live {@code
   * EventListenerRegistry} rather than assumed from the customizer having run without an exception.
   */
  private void refuseIfVerifierNotRegisteredFirst() {
    var sessionFactory = entityManagerFactory.unwrap(SessionFactoryImplementor.class);
    EventListenerRegistry registry =
        sessionFactory.getServiceRegistry().getService(EventListenerRegistry.class);
    if (registry == null) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "shredding: Hibernate's EventListenerRegistry is unavailable. This module's write and"
              + " read-path checks are Hibernate event listeners; without a registry none of them"
              + " can be registered at all.");
    }
    refuseUnlessRegistered(registry, EventType.PRE_INSERT);
    refuseUnlessRegistered(registry, EventType.PRE_UPDATE);
    refuseUnlessRegistered(registry, EventType.POST_INSERT);
    refuseUnlessRegistered(registry, EventType.POST_UPDATE);
    refuseUnlessFirst(registry, EventType.POST_LOAD);
  }

  private <T> void refuseUnlessRegistered(EventListenerRegistry registry, EventType<T> type) {
    var group = registry.getEventListenerGroup(type);
    for (T candidate : group.listeners()) {
      if (candidate == shreddingEventListener) {
        return;
      }
    }
    throw new ShreddingException(
        ErrorCodes.CONFIG,
        "shredding: this module's listener is not registered on "
            + type.eventName()
            + ". A second HibernatePropertiesCustomizer that sets"
            + " hibernate.integrator_provider without composing with the one this module installs -"
            + " see ShreddingAutoConfiguration.shreddingHibernateCustomizer - replaces it instead of"
            + " adding to it, and every write and read-path check this module makes is silently"
            + " off.");
  }

  private <T> void refuseUnlessFirst(EventListenerRegistry registry, EventType<T> type) {
    var group = registry.getEventListenerGroup(type);
    T first = null;
    for (T candidate : group.listeners()) {
      first = candidate;
      break;
    }
    if (first == shreddingEventListener) {
      return;
    }
    throw new ShreddingException(
        ErrorCodes.CONFIG,
        "shredding: this module's listener is not first on "
            + type.eventName()
            + " ("
            + (first == null ? "no listener at all" : first.getClass().getName())
            + " is). It has to run before any other POST_LOAD listener - a user @PostLoad method, an"
            + " @EntityListeners bean, or another library's own integrator - or that listener sees"
            + " the read placeholder instead of the decrypted value (Cipher item 8). Another"
            + " integrator prepended after this module's own installed; see"
            + " ShreddingAutoConfiguration.shreddingHibernateCustomizer for how to compose instead"
            + " of prepending around it.");
  }
}
