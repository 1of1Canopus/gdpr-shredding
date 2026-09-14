package com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.nonstring;

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
 * Change 8: a subject column of a type that is not {@code String}. A {@code SubjectId} is a string;
 * a {@code Long} in the column could not be compared with the subject an erasure was asked for
 * without a rendering nobody declared. Refused at startup rather than rendered by guesswork.
 */
@Entity
@Table(name = "non_string_subject_note")
public class NonStringSubjectNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "customer_ref")
  Long customerRef;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "customer_ref", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected NonStringSubjectNote() {}

  public String getOwnerId() {
    return ownerId;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("NonStringSubjectNote", "email");
    }
  }
}
