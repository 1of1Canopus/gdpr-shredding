package com.housedevinci.shredding.sample;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerRepository extends JpaRepository<Customer, Long> {

  List<Customer> findByCustomerId(String customerId);

  /** L7: the tenant-scoped read the sample's own endpoint uses; control 15 makes it mandatory. */
  List<Customer> findByTenantIdAndCustomerId(String tenantId, String customerId);
}
