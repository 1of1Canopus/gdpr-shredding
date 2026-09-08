package com.housedevinci.shredding.sample;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CustomerRepository extends JpaRepository<Customer, Long> {

  List<Customer> findByCustomerId(String customerId);

  /** L7: the tenant-scoped read the sample's own endpoint uses; control 15 makes it mandatory. */
  List<Customer> findByTenantIdAndCustomerId(String tenantId, String customerId);

  /**
   * The blind-index prefilter. It returns candidates, never an answer: the index is truncated, so
   * the caller re-verifies by decrypting. {@link CustomerService#findByEmail} does that.
   */
  @Query("select c from Customer c where c.tenantId = :tenant and c.emailBidx = :index")
  List<Customer> findByEmailIndex(@Param("tenant") String tenant, @Param("index") byte[] index);
}
