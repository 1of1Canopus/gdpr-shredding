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
    // #26 (Cipher seventh pass): the write-verification ledger's hard cap, configured once at boot
    // the same way ShreddingRuntime is. S-16 (Cipher eighth pass): a cap below 1 boots cleanly and
    // then refuses the application's very first shredded write - checked here, before it is ever
    // handed to WriteVerification.
    refuseIfLedgerCapBelowOne();
    WriteVerification.configureMaxOutstanding(
        properties.getWriteVerification().getMaxOutstanding());
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
    // Design addendum 3, change 1/2 (applied §3.1): every @BlindIndex must have had its
    // tenantColumn resolved to the property the write path reads. The auto-configured model always
    // scans with the EntityManagerFactory and so always resolves; an application that supplies its
    // own ShreddedModel bean might not, and an index derived under a tenant nobody resolved is an
    // index no erasure can be shown to reach. Refused here rather than at the first indexed write.
    model
        .blindIndexFields()
        .forEach(
            index -> {
              if (index.column().tenantProperty().isEmpty()) {
                throw new ShreddingException(
                    ErrorCodes.CONFIG,
                    "@BlindIndex on "
                        + index.entityName()
                        + "."
                        + index.fieldName()
                        + " has no property resolved for tenantColumn=\""
                        + index.column().tenantColumn()
                        + "\". Build the ShreddedModel with ShreddedModel.scan(entities,"
                        + " allowSecondLevelCache, properties, entityManagerFactory) so the column"
                        + " the erasure matches on can be resolved to the property the write path"
                        + " derives the index under.");
              }
            });
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
   * S-16 (Cipher eighth pass). {@code shredding.write-verification.max-outstanding} below 1 boots
   * cleanly and then turns every write of a {@code @Shredded} entity into a refusal: {@code owe}
   * compares the ledger's size against the cap <em>before</em> adding a genuinely new debt, so a
   * cap of {@code 0} or negative is already exceeded before the first row. This module's own
   * definition of done - "misconfiguration fails fast at startup with a message naming the
   * property" - rules that shape out.
   */
  private void refuseIfLedgerCapBelowOne() {
    int max = properties.getWriteVerification().getMaxOutstanding();
    if (max < 1) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "shredding.write-verification.max-outstanding is "
              + max
              + ", but must be at least 1. A ledger cap below 1 is already exceeded before the"
              + " first row of any @Shredded entity is written, so every write in the application"
              + " would be refused with SHRED-UNVERIFIED-WRITE. The default is 50000.");
    }
  }

  /**
   * S-6 (Cipher sixth pass), widened by S-11 (Cipher seventh pass). {@code
   * ShreddingHibernateCustomizer} composes with whatever {@code IntegratorProvider} another library
   * or the application already installed, so this module's listener is never silently discarded -
   * but composing is a best effort, not a proof: nothing checked, until S-6, that the composition
   * actually reached Hibernate and that this module's {@code POST_LOAD} listener is still the first
   * one called. Run once, after the {@code SessionFactory} is actually built (this bean depends on
   * {@code EntityManagerFactory}, so Spring has already finished building it by the time this
   * runs), against the real, live {@code EventListenerRegistry} rather than assumed from the
   * customizer having run without an exception.
   *
   * <p><strong>S-11.</strong> S-6's check covered five of the seven event types {@link
   * ShreddingIntegrator} registers - {@code PRE_INSERT}, {@code PRE_UPDATE}, {@code POST_INSERT},
   * {@code POST_UPDATE} for presence only, {@code POST_LOAD} for presence and position - and left
   * {@code FLUSH}, {@code AUTO_FLUSH} and {@code POST_DELETE}, S-1's settlement machinery,
   * unchecked at all: another library's ordinary {@code registry.setListeners(EventType.FLUSH,
   * ...)} silently removes this module's settlement listener and the application starts. Presence
   * is also not the position the integrator registered for: {@code PRE_*} and {@code POST_LOAD} are
   * prepended because the scope must be pushed, and the verifier must install, before anything else
   * runs; {@code POST_INSERT}, {@code POST_UPDATE}, {@code POST_DELETE}, {@code FLUSH} and {@code
   * AUTO_FLUSH} are appended because each must see what already happened. One table, the same list
   * {@link ShreddingIntegrator#integrate} registers, so a type added there cannot silently go
   * unchecked here.
   *
   * <p><strong>What this check does and does not prove (S-11, accepted residual, Cipher eighth
   * pass).</strong> It proves, against the live {@code EventListenerRegistry} after the {@code
   * SessionFactory} is built, that this module's listener is registered on all eight event types
   * above and is in the position it registered for. It does not prove that the listeners Hibernate
   * itself seeded are still there. This module composes its integrator last on purpose, so an
   * integrator composed earlier can call {@code registry.setListeners(type, ...)} and replace a
   * group's prior contents - Hibernate's own {@code DefaultFlushEventListener} among them - before
   * this module registers at all; our listener is then added to the emptied group and measures as
   * correctly positioned, because position is measured against what remains. No check this module
   * can make from inside the same JVM closes that, and none of its own controls is removed by it:
   * this module's listener is always registered after the wipe and its presence is checked. What is
   * lost is Hibernate's own behaviour, which fails loudly. Integrators on the classpath are inside
   * the trust boundary; review them as you would any other code you run. See {@code
   * SECURITY-NOTES.md} for the full paragraph.
   */
  private static final java.util.List<TypeCheck<?>> REGISTERED_TYPES =
      java.util.List.of(
          TypeCheck.first(EventType.PRE_INSERT),
          TypeCheck.first(EventType.PRE_UPDATE),
          TypeCheck.first(EventType.POST_LOAD),
          TypeCheck.last(EventType.POST_INSERT),
          TypeCheck.last(EventType.POST_UPDATE),
          TypeCheck.last(EventType.POST_DELETE),
          TypeCheck.last(EventType.FLUSH),
          TypeCheck.last(EventType.AUTO_FLUSH));

  private record TypeCheck<T>(EventType<T> type, boolean mustBeFirst) {
    static <T> TypeCheck<T> first(EventType<T> type) {
      return new TypeCheck<>(type, true);
    }

    static <T> TypeCheck<T> last(EventType<T> type) {
      return new TypeCheck<>(type, false);
    }
  }

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
    for (TypeCheck<?> check : REGISTERED_TYPES) {
      refuseUnlessAtPosition(registry, check);
    }
  }

  private <T> void refuseUnlessAtPosition(EventListenerRegistry registry, TypeCheck<T> check) {
    var group = registry.getEventListenerGroup(check.type());
    T first = null;
    T last = null;
    boolean present = false;
    for (T candidate : group.listeners()) {
      if (first == null) {
        first = candidate;
      }
      last = candidate;
      if (candidate == shreddingEventListener) {
        present = true;
      }
    }
    if (!present) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "shredding: this module's listener is not registered on "
              + check.type().eventName()
              + ". A second HibernatePropertiesCustomizer that sets"
              + " hibernate.integrator_provider without composing with the one this module installs"
              + " - see ShreddingAutoConfiguration.shreddingHibernateCustomizer - or another"
              + " integrator's own registry.setListeners(...) replacing this module's listener"
              + " outright, removes it instead of adding to it, and every write and read-path check"
              + " this module makes is silently off.");
    }
    T expected = check.mustBeFirst() ? first : last;
    if (expected == shreddingEventListener) {
      return;
    }
    throw new ShreddingException(
        ErrorCodes.CONFIG,
        "shredding: this module's listener is registered on "
            + check.type().eventName()
            + " but is not "
            + (check.mustBeFirst() ? "first" : "last")
            + " ("
            + expected.getClass().getName()
            + " is). "
            + (check.mustBeFirst()
                ? "It has to run before any other listener on this type - a user @PostLoad method,"
                    + " an @EntityListeners bean, or another library's own integrator - or that"
                    + " listener sees the read placeholder instead of the decrypted value, or binds"
                    + " before the scope is pushed (Cipher item 8)."
                : "It has to run after every other listener on this type - the post-hoc header"
                    + " check and the settlement machinery must see what actually reached the"
                    + " database, after every other listener has had its turn.")
            + " Another integrator prepended or reordered after this module's own installed; see"
            + " ShreddingAutoConfiguration.shreddingHibernateCustomizer for how to compose instead"
            + " of displacing it.");
  }
}
