package com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.camel;

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
 * Design addendum 3 change 8 (§3.8a), the regression it must not cause: {@code subjectColumn} is a
 * <em>column</em> name. The property here is {@code customerRef} with no {@code @Column} of its
 * own, so Hibernate's naming strategy maps it to {@code customer_ref} - what {@code subjectColumn}
 * names and what the erasure's {@code WHERE customer_ref = ?} matches on. A resolution that looked
 * the value up among property names would refuse this, the ordinary correct configuration.
 */
@Entity
@Table(name = "camel_subject_note")
public class CamelSubjectNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  String customerRef;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{customerRef}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "customer_ref", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected CamelSubjectNote() {}

  public String getCustomerRef() {
    return customerRef;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("CamelSubjectNote", "email");
    }
  }
}
