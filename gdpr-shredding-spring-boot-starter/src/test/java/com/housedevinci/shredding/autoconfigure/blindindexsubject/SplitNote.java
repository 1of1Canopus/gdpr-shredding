package com.housedevinci.shredding.autoconfigure.blindindexsubject;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Cipher, ninth pass. Addendum 3 bound the tenant axis of a blind index to the row. The subject
 * axis is unbound: {@code subjectColumn} is never resolved, never read at write time and never
 * compared with the subject the data key is derived under.
 */
@Entity
@Table(name = "split_note")
public class SplitNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  /** What the blind index's {@code subjectColumn} names. */
  @Column(name = "owner_id", nullable = false)
  String ownerId;

  /** What {@code @Shredded(subject = ...)} evaluates to. */
  @Column(name = "customer_ref", nullable = false)
  String customerRef;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{customerRef}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected SplitNote() {}

  public SplitNote(String ownerId, String customerRef, String tenantId, String email) {
    this.ownerId = ownerId;
    this.customerRef = customerRef;
    this.tenantId = tenantId;
    this.email = email;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getCustomerRef() {
    return customerRef;
  }

  public String getTenantId() {
    return tenantId;
  }

  public String getEmail() {
    return email;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("SplitNote", "email");
    }
  }
}
