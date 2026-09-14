package com.housedevinci.shredding.sample;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditRepository extends JpaRepository<CustomerAuditEvent, Long> {

  List<CustomerAuditEvent> findByCustomerId(String customerId);
}
