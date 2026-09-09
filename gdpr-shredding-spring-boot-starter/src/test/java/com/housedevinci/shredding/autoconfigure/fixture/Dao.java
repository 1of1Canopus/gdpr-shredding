package com.housedevinci.shredding.autoconfigure.fixture;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import org.springframework.stereotype.Repository;

/** A hand-written DAO: a @Repository bean that is not a Spring Data {@code Repository}. */
@Repository
public class Dao {
  @PersistenceContext EntityManager em;

  public List<Doc> findByOwner(String ownerId) {
    return em.createQuery("select d from Doc d where d.ownerId = :id", Doc.class)
        .setParameter("id", ownerId)
        .getResultList();
  }
}
