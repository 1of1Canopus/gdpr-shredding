package com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.embedded;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Change 8: the subject column is mapped only inside an {@code @Embeddable}. The write path reads
 * the subject out of the entity's own top-level state array, where the component sits as one object
 * and not as its columns, so the value the check would compare is not there.
 */
@Entity
@Table(name = "embedded_subject_note")
public class EmbeddedSubjectNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Embedded Customer customer;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "customer_ref", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected EmbeddedSubjectNote() {}

  public String getOwnerId() {
    return ownerId;
  }

  /** The subject, one level down. */
  @Embeddable
  public static class Customer {
    @Column(name = "customer_ref")
    String customerRef;

    public String getCustomerRef() {
      return customerRef;
    }
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("EmbeddedSubjectNote", "email");
    }
  }
}
