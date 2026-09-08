package com.housedevinci.shredding.sample;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * The row the regulator wants kept: who did what, when, against which customer id. Nothing here is
 * shredded, and nothing here is deleted by an erasure. That is the whole point of the technique.
 */
@Entity
@Table(name = "customer_audit")
public class CustomerAuditEvent {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "customer_id", nullable = false)
  private String customerId;

  @Column(name = "action", nullable = false)
  private String action;

  @Column(name = "at", nullable = false)
  private Instant at;

  protected CustomerAuditEvent() {}

  public CustomerAuditEvent(String customerId, String action, Instant at) {
    this.customerId = customerId;
    this.action = action;
    this.at = at;
  }

  public String getCustomerId() {
    return customerId;
  }

  public String getAction() {
    return action;
  }

  public Instant getAt() {
    return at;
  }
}
