package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Mapping admission at startup (name-resolution design, addendum section A.5): every
 * {@code @Shredded} entity's table is checked against the catalogue before the application serves a
 * request, and a table that is present and inadmissible stops the context with {@code
 * SHRED-SCHEMA-009}; a table whose blind-index column keeps planner statistics stops it with {@code
 * SHRED-SCHEMA-010} (audit-table coverage design, section 3b).
 *
 * <p>This is the early half of the control. The half that holds is the erasure's own check, inside
 * every erasure's transaction and under its lock, because a verdict taken here is undone by one
 * rename and one {@code CREATE VIEW} the runtime role may perform. This bean exists so that a
 * mapping nothing legitimate produces fails at deployment rather than at a data subject's request.
 *
 * <p><b>Lifecycle.</b> The work is in the constructor, like {@link ShreddingSchemaGate}'s:
 *
 * <ul>
 *   <li>it takes {@link ShreddedModel}, which takes the {@code EntityManagerFactory}, so
 *       Hibernate's {@code ddl-auto} and every initializer the factory depends on (Flyway,
 *       Liquibase) have run; the bean method also carries {@code @DependsOnDatabaseInitialization}
 *       for a {@code spring.sql.init} script that does not go through the factory;
 *   <li>it takes its {@code DataSource} from the gate, never by type, so the database checked is
 *       the one the erasure writes to;
 *   <li>it is excluded from lazy initialisation beside the gate: a startup control a property can
 *       move to request time is not a startup control.
 * </ul>
 *
 * <p><b>A table that does not exist yet is a WARN, not a refusal.</b> {@code
 * spring.jpa.defer-datasource-initialization=true}, a test that creates its schema after the
 * context refreshes, and a migration applied with the application already up are all honest
 * deployments. The erasure refuses on an absent table; startup tells the operator now.
 */
public final class MappingAdmissionCheck {

  private static final Logger log = LoggerFactory.getLogger(MappingAdmissionCheck.class);

  private final int checked;

  public MappingAdmissionCheck(ShreddedModel model, ShreddingSchemaGate gate) {
    Objects.requireNonNull(model, "model");
    Objects.requireNonNull(gate, "gate");
    List<MappingAdmission.Target> targets = model.admissionTargets();
    var refusals = new ArrayList<String>();
    var copies = new ArrayList<String>();
    try (Connection c = gate.dataSource().getConnection()) {
      for (MappingAdmission.Target target : targets) {
        switch (MappingAdmission.verdict(c, target, model.copySignatures())) {
          case MappingAdmission.Admitted admitted ->
              admitted.warnings().forEach(w -> log.warn("shredding: {}", w));
          case MappingAdmission.Absent absent ->
              log.warn(
                  "{} At startup this is a warning, because the table may be created after the"
                      + " application starts; every erasure that reaches it is refused with {}"
                      + " until it exists and is admissible.",
                  absent.message(),
                  ErrorCodes.MAPPING_INADMISSIBLE);
          case MappingAdmission.Refused refused -> refusals.add(refused.message());
          case MappingAdmission.Copied copied -> copies.add(copied.message());
        }
      }
    } catch (SQLException e) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "shredding: the @Shredded mappings could not be checked against the catalogue because"
              + " no connection could be obtained (SQLState "
              + e.getSQLState()
              + "). Unverifiable is not clean, so this is a refusal.",
          e);
    }
    if (!refusals.isEmpty()) {
      // A mapping that cannot be erased is the first thing to fix; a copy found on another table
      // is still named, so one deployment shows the operator every refusal it will meet.
      throw new ShreddingException(
          ErrorCodes.MAPPING_INADMISSIBLE,
          String.join(" ", refusals)
              + " See docs/upgrading-0.2.0.md, \"Every installation: what your entity tables must"
              + " be\"."
              + (copies.isEmpty()
                  ? ""
                  : " Also refused, with "
                      + ErrorCodes.BLIND_INDEX_COPIED
                      + ": "
                      + String.join(" ", copies)));
    }
    if (!copies.isEmpty()) {
      throw new ShreddingException(ErrorCodes.BLIND_INDEX_COPIED, String.join(" ", copies));
    }
    this.checked = targets.size();
  }

  /** How many {@code @Shredded} entities were checked at startup. */
  public int checked() {
    return checked;
  }
}
