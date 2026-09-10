package com.housedevinci.shredding.autoconfigure;

import org.hibernate.boot.Metadata;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.integrator.spi.Integrator;

/**
 * Registers {@link ShreddingEventListener} with Hibernate. The listener has to be an event listener
 * and not a Spring bean because it must run inside the flush, between the state array being built
 * and the converters binding it.
 */
public final class ShreddingIntegrator implements Integrator {

  private final ShreddingEventListener listener;

  public ShreddingIntegrator(ShreddingEventListener listener) {
    this.listener = listener;
  }

  @Override
  public void integrate(
      Metadata metadata,
      org.hibernate.boot.spi.BootstrapContext bootstrapContext,
      SessionFactoryImplementor sessionFactory) {
    EventListenerRegistry registry =
        sessionFactory.getServiceRegistry().getService(EventListenerRegistry.class);
    if (registry == null) {
      throw new IllegalStateException("Hibernate EventListenerRegistry is unavailable");
    }
    // prependListeners: the scope must be pushed before anything else can trigger a bind.
    registry.prependListeners(EventType.PRE_INSERT, listener);
    registry.prependListeners(EventType.PRE_UPDATE, listener);
    // Cipher item 8. POST_LOAD is prepended, not appended: Hibernate's own
    // PostLoadEventListenerStandardImpl is what invokes a user's @PostLoad methods and
    // @EntityListeners beans, and while this listener ran after it every one of those callbacks saw
    // the read placeholder instead of the value. The verifier has to install first. This is also
    // why the framework matrix has a test for the ordering rather than a comment claiming it.
    registry.prependListeners(EventType.POST_LOAD, listener);
    // POST_INSERT and POST_UPDATE stay appended: the post-hoc header check (design §1.3) must see
    // what actually reached the database, after every other listener has had its turn.
    registry.appendListeners(EventType.POST_INSERT, listener);
    registry.appendListeners(EventType.POST_UPDATE, listener);
    // S-1, design addendum: the settlement points. FLUSH and AUTO_FLUSH are appended so this runs
    // after Hibernate's own flush listener, which is what executes the JDBC batch - the earliest
    // point at which a batched INSERT is readable. POST_DELETE discharges the debt of a row deleted
    // in the same transaction, which the insert-then-delete-in-one-flush ordering needs.
    registry.appendListeners(EventType.POST_DELETE, listener);
    registry.appendListeners(EventType.FLUSH, listener);
    registry.appendListeners(EventType.AUTO_FLUSH, listener);
  }

  @Override
  public void disintegrate(
      SessionFactoryImplementor sessionFactory,
      org.hibernate.service.spi.SessionFactoryServiceRegistry serviceRegistry) {
    // nothing to unwind
  }
}
