package com.housedevinci.shredding.autoconfigure.eleventhpass.writetx;

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
 * Cipher, eleventh pass: a @ColumnTransformer that only rewrites the <em>write</em>. The existing
 * change-4 fixture sets both read and write, so a predicate that only looked at the read expression
 * would still refuse it. This one leaves the read plain: the column stores upper(value) while the
 * erasure binds the value as given, so WHERE owner_id = ? matches nothing.
 */
@Entity
@Table(name = "writetx_note")
public class WriteOnlyTxNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  @org.hibernate.annotations.ColumnTransformer(write = "upper(?)")
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

  protected WriteOnlyTxNote() {}

  public WriteOnlyTxNote(String ownerId, String tenantId, String email) {
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
      super("WriteOnlyTxNote", "email");
    }
  }
}
