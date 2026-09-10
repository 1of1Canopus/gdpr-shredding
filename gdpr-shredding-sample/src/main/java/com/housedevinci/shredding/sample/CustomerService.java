package com.housedevinci.shredding.sample;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureResult;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.domain.ErasedValue;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.time.Clock;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** The application's own logic. No crypto here: the mapping does it. */
@Service
public class CustomerService {

  private final CustomerRepository customers;
  private final AuditRepository audit;
  private final ErasureService erasures;
  private final Clock clock;

  public CustomerService(
      CustomerRepository customers, AuditRepository audit, ErasureService erasures, Clock clock) {
    this.customers = customers;
    this.audit = audit;
    this.erasures = erasures;
    this.clock = clock;
  }

  @Transactional
  public Customer create(String tenantId, String customerId, String email, String phone) {
    Customer saved = customers.save(new Customer(tenantId, customerId, email, phone));
    audit.save(new CustomerAuditEvent(customerId, "created", clock.instant()));
    return saved;
  }

  @Transactional(readOnly = true)
  public List<Customer> byCustomerId(String customerId) {
    return customers.findByCustomerId(customerId);
  }

  /** L7: the tenant is mandatory on a read, the same as everywhere else in this module. */
  @Transactional(readOnly = true)
  public List<Customer> byTenantAndCustomerId(String tenantId, String customerId) {
    return customers.findByTenantIdAndCustomerId(tenantId, customerId);
  }

  @Transactional
  public ErasureResult erase(
      String tenantId, String customerId, String requestedBy, String reason) {
    // The customer row is not deleted, and neither is the audit trail. Only the key goes.
    ErasureResult result =
        erasures.erase(
            new ErasureRequest(
                TenantId.of(tenantId), SubjectId.of(customerId), requestedBy, reason));
    audit.save(new CustomerAuditEvent(customerId, "erased", clock.instant()));
    return result;
  }

  /** True when this row's email now reads as the erased sentinel. */
  public static boolean isErased(Customer customer) {
    return ErasedValue.isMarker(customer.getEmail());
  }
}
