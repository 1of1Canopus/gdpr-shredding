package com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.unmapped;

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
 * Change 8: {@code subjectColumn} naming the <em>property</em> ({@code customerRef}) rather than
 * the column ({@code customer_ref}). No column of this table is called {@code customerref}, so the
 * erasure's {@code UPDATE} would fail on every erasure - the raw {@code SQLException} at runtime
 * that S-20 names as the mildest of the shapes this resolution exists to catch.
 */
@Entity
@Table(name = "unmapped_subject_note")
public class UnmappedSubjectNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "customer_ref", nullable = false)
  String customerRef;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{customerRef}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "customerref", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected UnmappedSubjectNote() {}

  public String getCustomerRef() {
    return customerRef;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("UnmappedSubjectNote", "email");
    }
  }
}
