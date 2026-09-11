package com.housedevinci.shredding.sample;

import com.housedevinci.shredding.api.Shredded;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A customer. {@code tenantId} and {@code customerId} stay in the clear: they are what the audit
 * table, the invoices and the foreign keys refer to, and they are exactly what an erasure must not
 * take away.
 *
 * <p>{@code email} and {@code phone} are encrypted under this customer's own data key. Erasing the
 * customer destroys that key; this row, and every row that points at {@code customerId}, survives.
 *
 * <p>Neither field carries a {@code @BlindIndex}. S-7 (the seventh pass): a {@code @BlindIndex}
 * whose {@code of} field declares its own {@code @Shredded(tenant=...)} is refused at startup - the
 * index would be derived under that declared tenant, but the erasure meant to destroy it matches
 * only the row's own {@code tenant_id} column, and the module cannot prove the two always agree
 * from a SpEL expression alone. This sample is genuinely multi-tenant per write, with no ambient
 * {@code TenantSupplier} configured, so every {@code @Shredded} field here has to declare its own
 * {@code tenant = "#{tenantId}"} - which rules a blind index out for it. See {@code README.md} and
 * {@code SECURITY-NOTES.md} for the equality-lookup feature on a single-ambient-tenant application.
 */
@Entity
@Table(name = "customer")
public class Customer {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "tenant_id", nullable = false)
  private String tenantId;

  @Column(name = "customer_id", nullable = false)
  private String customerId;

  @Shredded(subject = "#{customerId}", tenant = "#{tenantId}")
  @Convert(converter = CustomerEmailConverter.class)
  @Column(name = "email")
  private String email;

  @Shredded(subject = "#{customerId}", tenant = "#{tenantId}")
  @Convert(converter = CustomerPhoneConverter.class)
  @Column(name = "phone")
  private String phone;

  protected Customer() {}

  public Customer(String tenantId, String customerId, String email, String phone) {
    this.tenantId = tenantId;
    this.customerId = customerId;
    this.email = email;
    this.phone = phone;
  }

  public Long getId() {
    return id;
  }

  public String getTenantId() {
    return tenantId;
  }

  public String getCustomerId() {
    return customerId;
  }

  public void setCustomerId(String customerId) {
    this.customerId = customerId;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getPhone() {
    return phone;
  }

  /**
   * Identity only. A generated {@code toString} over every field is the most common way a decrypted
   * value ends up in a log line, and a log line outlives the erasure.
   */
  @Override
  public String toString() {
    return "Customer[" + tenantId + "/" + customerId + "]";
  }
}
