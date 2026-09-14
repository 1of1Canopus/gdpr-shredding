package com.housedevinci.shredding.autoconfigure.fixture;

import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WidgetRepository extends JpaRepository<Widget, Long> {
  List<Widget> findByOwnerId(String ownerId);

  /**
   * Scoped to a specific set of owners, unlike {@link #findAll(Sort)}: several {@code
   * CipherProbeFrameTest} methods share one Testcontainers Postgres for the whole test class (no
   * per-method table reset), so an unscoped {@code findAll} would also decode - and, correctly,
   * refuse on - a moved-ciphertext row a *different* test method planted, not only the rows this
   * one owns. This is what {@code findAll(owner IN (...))} would compile to in an application with
   * a WHERE clause the test needs and the repository did not otherwise expose.
   */
  List<Widget> findByOwnerIdIn(Collection<String> ownerIds, Sort sort);
}
