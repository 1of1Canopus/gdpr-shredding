package com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.twoproperty;

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
 * Change 8: two properties over one column. The write path has to read one value out of the state
 * array for the column the erasure matches on, and two properties give it no single answer.
 */
@Entity
@Table(name = "two_property_subject_note")
public class TwoPropertySubjectNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "customer_ref")
  String customerRef;

  @Column(name = "customer_ref", insertable = false, updatable = false)
  String customerRefReadOnly;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{customerRef}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "customer_ref", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected TwoPropertySubjectNote() {}

  public String getCustomerRef() {
    return customerRef;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("TwoPropertySubjectNote", "email");
    }
  }
}
