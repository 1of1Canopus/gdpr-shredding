package com.housedevinci.shredding.sample;

import com.housedevinci.shredding.api.BlindIndex;
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

  /** Prefilter for equality lookups on {@link #email}; nulled by an erasure. */
  @BlindIndex(of = "email", subjectColumn = "customer_id", tenantColumn = "tenant_id")
  @Column(name = "email_bidx")
  private byte[] emailBidx;

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

  public byte[] getEmailBidx() {
    return emailBidx == null ? null : emailBidx.clone();
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
