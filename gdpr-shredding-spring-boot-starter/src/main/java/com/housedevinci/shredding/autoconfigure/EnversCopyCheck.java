package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.adapter.jdbc.CopySignatures;
import com.housedevinci.shredding.domain.ShreddingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.envers.boot.internal.EnversService;
import org.hibernate.metamodel.mapping.AttributeMapping;
import org.hibernate.persister.entity.EntityPersister;

/**
 * Hibernate Envers' part of the mapping leg (audit-table coverage design, rows 1-8, 13, 35). The
 * only class of this module that imports {@code org.hibernate.envers}; {@link HibernateCopyCheck}
 * calls it only when Envers is on the classpath, so an application without Envers loads none of it.
 *
 * <p>Envers maps every audit table as an entity of its own, so the audit persisters are in the same
 * metamodel as the application's entities. For each of them, each attribute is looked up by name on
 * the audited entity, and the columns that attribute maps there are compared with the admitted
 * blind-index columns. Exclusion is whatever Envers built: a {@code @NotAudited} attribute has no
 * audit attribute at all, so it never matches.
 */
final class EnversCopyCheck {

  private EnversCopyCheck() {}

  /** Whether {@code persister} is an Envers audit entity. False when Envers is absent or off. */
  static boolean isAuditPersister(
      SessionFactoryImplementor sessionFactory, EntityPersister persister, boolean enversPresent) {
    return enversPresent && auditedEntity(sessionFactory, persister.getEntityName()).isPresent();
  }

  /**
   * The entity an Envers audit entity audits, when {@code entityName} is one. Empty when Envers is
   * absent, disabled, or {@code entityName} is an ordinary entity.
   */
  static Optional<String> auditedEntity(
      SessionFactoryImplementor sessionFactory, String entityName) {
    return service(sessionFactory)
        .map(s -> s.getEntitiesConfigurations().getEntityNameForVersionsEntityName(entityName));
  }

  static void check(
      SessionFactoryImplementor sessionFactory,
      Map<String, HibernateCopyCheck.Admitted> admitted,
      Set<String> findings,
      List<CopySignatures.NamedCopy> named,
      List<CopySignatures.RevisionSignature> signatures) {
    Optional<EnversService> service = service(sessionFactory);
    if (service.isEmpty()) {
      return;
    }
    try {
      var config = service.get().getConfig();
      String rev = config.getRevisionFieldName();
      String type = config.getRevisionTypePropertyName();
      signatures.add(
          new CopySignatures.RevisionSignature(
              "Hibernate Envers",
              "audit",
              HibernateCopyCheck.stored(rev),
              HibernateCopyCheck.stored(type)));
      var entities = service.get().getEntitiesConfigurations();
      var metamodel = sessionFactory.getMappingMetamodel();
      var audits = new ArrayList<EntityPersister>();
      metamodel.forEachEntityDescriptor(
          p -> {
            if (entities.getEntityNameForVersionsEntityName(p.getEntityName()) != null) {
              audits.add(p);
            }
          });
      for (EntityPersister audit : audits) {
        String sourceName = entities.getEntityNameForVersionsEntityName(audit.getEntityName());
        EntityPersister source = metamodel.getEntityDescriptor(sourceName);
        String auditTable = audit.getMappedTableDetails().getTableName();
        String sourceTable = source.getMappedTableDetails().getTableName();
        for (HibernateCopyCheck.Admitted a : admitted.values()) {
          if (HibernateCopyCheck.key(a.table().toString(), "")
              .equals(HibernateCopyCheck.key(sourceTable, ""))) {
            named.add(
                new CopySignatures.NamedCopy(
                    a.table(), HibernateCopyCheck.table(auditTable), "Hibernate Envers", "audit"));
          }
        }
        audit.forEachAttributeMapping(
            attribute -> copied(audit, attribute, source, admitted, findings, auditTable));
      }
    } catch (ShreddingException e) {
      throw e;
    } catch (RuntimeException | LinkageError e) {
      throw HibernateCopyCheck.unverifiable("Hibernate Envers' audit configuration", e);
    }
  }

  private static void copied(
      EntityPersister audit,
      AttributeMapping attribute,
      EntityPersister source,
      Map<String, HibernateCopyCheck.Admitted> admitted,
      Set<String> findings,
      String auditTable) {
    AttributeMapping original = source.findAttributeMapping(attribute.getAttributeName());
    if (original == null) {
      return;
    }
    var auditColumns = new ArrayList<String>();
    attribute.forEachSelectable((i, s) -> auditColumns.add(s.getSelectionExpression()));
    String sourceEntity = ShreddedModel.simpleEntityName(source.getEntityName());
    original.forEachSelectable(
        (i, selectable) -> {
          HibernateCopyCheck.Admitted a = admitted.get(HibernateCopyCheck.key(selectable));
          if (a == null) {
            return;
          }
          String column =
              i < auditColumns.size() ? auditColumns.get(i) : selectable.getSelectionExpression();
          boolean sameEntity =
              sourceEntity.equals(a.entityName())
                  && attribute.getAttributeName().equals(a.fieldName());
          String attributeName = sourceEntity + "." + attribute.getAttributeName();
          findings.add(
              "shredding: Hibernate Envers copies the blind-index column "
                  + a.qualified()
                  + (sameEntity
                      ? " (" + a.label() + ")"
                      : " through entity "
                          + sourceEntity
                          + " (attribute "
                          + attribute.getAttributeName()
                          + "), which maps the same table,")
                  + " into its audit table "
                  + auditTable
                  + ". An erasure clears the index in "
                  + a.table()
                  + " only, so every audit row keeps the erased subject's index, matchable with the"
                  + " application's index secret. Mark "
                  + attributeName
                  + " @NotAudited, then clear the copies already written: "
                  + HibernateCopyCheck.clear(auditTable, column));
        });
  }

  private static Optional<EnversService> service(SessionFactoryImplementor sessionFactory) {
    try {
      EnversService service = sessionFactory.getServiceRegistry().getService(EnversService.class);
      if (service == null || !service.isEnabled() || !service.isInitialized()) {
        return Optional.empty();
      }
      return Optional.of(service);
    } catch (RuntimeException | LinkageError e) {
      throw HibernateCopyCheck.unverifiable("Hibernate Envers' service", e);
    }
  }
}
