package com.housedevinci.shredding.autoconfigure.columnid.transformerindex;

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
 * Design addendum 4, change 4, the second face: a {@code @ColumnTransformer} on the <em>index</em>
 * column. A write expression there means {@code SET email_idx = NULL} is not what Hibernate would
 * write, so the erasure's own clear is mis-addressed by value.
 */
@Entity
@Table(name = "transformerindex_note")
public class TransformerIndexNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  @org.hibernate.annotations.ColumnTransformer(read = "email_idx", write = "cast(? as bytea)")
  byte[] emailIndex;

  protected TransformerIndexNote() {}

  public TransformerIndexNote(String ownerId, String tenantId, String email) {
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
      super("TransformerIndexNote", "email");
    }
  }
}
