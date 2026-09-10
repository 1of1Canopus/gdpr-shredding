package com.housedevinci.shredding.autoconfigure.ninthpass.schema;

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
 * Cipher, ninth pass, K1 lesson: the blind-index table lives in a schema of its own. When this
 * fixture was written the erasure interpolated {@code BlindIndexColumn.table()} unqualified, so what
 * it updated - and what {@code verifyCleared} read back - depended on the connection's {@code
 * search_path}, and this mapping was refused at startup by accident, blaming a secondary table that
 * does not exist (S-21). Since design addendum 3 change 9 the table comes from the persister,
 * schema and all, and this mapping boots, writes and erases.
 */
@Entity
@Table(name = "schema_note", schema = "app2")
public class SchemaNote {

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
  byte[] emailIndex;

  protected SchemaNote() {}

  public SchemaNote(String ownerId, String tenantId, String email) {
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
      super("SchemaNote", "email");
    }
  }
}
