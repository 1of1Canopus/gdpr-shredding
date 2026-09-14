package com.housedevinci.shredding.autoconfigure.columnid.transformersubject;

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
 * Design addendum 4: change 4: a @ColumnTransformer on the subject column. The identifier is
 * perfectly plain and the column stores something other than the value this module binds, so WHERE
 * owner_id = ? matches nothing - mis-addressed by value instead of by name, with the same recorded
 * COMPLETE.
 */
@Entity
@Table(name = "transformersubject_note")
public class TransformerSubjectNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  @org.hibernate.annotations.ColumnTransformer(read = "upper(owner_id)", write = "lower(?)")
  String ownerId;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected TransformerSubjectNote() {}

  public TransformerSubjectNote(String ownerId, String tenantId, String email) {
    this.ownerId = ownerId;
    this.tenantId = tenantId;
    this.email = email;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getTenantId() {
    return tenantId;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("TransformerSubjectNote", "email");
    }
  }
}
