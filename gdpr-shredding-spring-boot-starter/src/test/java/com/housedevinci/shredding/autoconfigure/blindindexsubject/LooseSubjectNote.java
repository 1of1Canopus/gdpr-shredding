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
 * S-20, design addendum 3 change 8 (§3.8c). A nullable subject column, so the null and blank halves
 * of change 3 can be probed on the subject axis as they are on the tenant axis. The subject
 * expression reads a second property, so the write reaches the subject-column check with a subject
 * that resolves fine and a column that does not.
 */
@Entity
@Table(name = "loose_subject_note")
public class LooseSubjectNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "customer_ref")
  String customerRef;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "customer_ref", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected LooseSubjectNote() {}

  public LooseSubjectNote(String ownerId, String customerRef, String tenantId, String email) {
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

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("LooseSubjectNote", "email");
    }
  }
}
