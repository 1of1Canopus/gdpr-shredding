package com.housedevinci.shredding.autoconfigure.copies.enversok;

import org.hibernate.boot.Metadata;
import org.hibernate.boot.spi.BootstrapContext;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.envers.boot.internal.EnversService;
import org.hibernate.envers.event.spi.EnversListenerDuplicationStrategy;
import org.hibernate.envers.event.spi.EnversPostCollectionRecreateEventListenerImpl;
import org.hibernate.envers.event.spi.EnversPostDeleteEventListenerImpl;
import org.hibernate.envers.event.spi.EnversPostInsertEventListenerImpl;
import org.hibernate.envers.event.spi.EnversPostUpdateEventListenerImpl;
import org.hibernate.envers.event.spi.EnversPreCollectionRemoveEventListenerImpl;
import org.hibernate.envers.event.spi.EnversPreCollectionUpdateEventListenerImpl;
import org.hibernate.envers.event.spi.EnversPreUpdateEventListenerImpl;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;

/**
 * Envers' documented manual registration ({@code hibernate.envers.autoRegisterListeners=false},
 * then register the listeners yourself), done through {@code hibernate.integrator_provider} so it
 * runs before the shredding integrator, which the module's customizer composes last.
 */
public class EnversFirstIntegrator implements Integrator {

  @Override
  public void integrate(
      Metadata metadata, BootstrapContext bootstrapContext, SessionFactoryImplementor sf) {
    var services = sf.getServiceRegistry();
    EnversService envers = services.getService(EnversService.class);
    EventListenerRegistry registry = services.getService(EventListenerRegistry.class);
    registry.addDuplicationStrategy(EnversListenerDuplicationStrategy.INSTANCE);
    if (envers.getEntitiesConfigurations().hasAuditedEntities()) {
      registry.appendListeners(
          EventType.POST_DELETE, new EnversPostDeleteEventListenerImpl(envers));
      registry.appendListeners(
          EventType.POST_INSERT, new EnversPostInsertEventListenerImpl(envers));
      registry.appendListeners(EventType.PRE_UPDATE, new EnversPreUpdateEventListenerImpl(envers));
      registry.appendListeners(
          EventType.POST_UPDATE, new EnversPostUpdateEventListenerImpl(envers));
      registry.appendListeners(
          EventType.POST_COLLECTION_RECREATE,
          new EnversPostCollectionRecreateEventListenerImpl(envers));
      registry.appendListeners(
          EventType.PRE_COLLECTION_REMOVE, new EnversPreCollectionRemoveEventListenerImpl(envers));
      registry.appendListeners(
          EventType.PRE_COLLECTION_UPDATE, new EnversPreCollectionUpdateEventListenerImpl(envers));
    }
  }

  @Override
  public void disintegrate(SessionFactoryImplementor sf, SessionFactoryServiceRegistry registry) {}
}
