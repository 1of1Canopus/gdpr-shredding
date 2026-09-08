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
    registry.appendListeners(EventType.POST_INSERT, listener);
    registry.appendListeners(EventType.POST_UPDATE, listener);
    registry.appendListeners(EventType.POST_LOAD, listener);
  }

  @Override
  public void disintegrate(
      SessionFactoryImplementor sessionFactory,
      org.hibernate.service.spi.SessionFactoryServiceRegistry serviceRegistry) {
    // nothing to unwind
  }
}
