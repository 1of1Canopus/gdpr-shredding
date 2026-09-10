package com.housedevinci.shredding.autoconfigure.columnid.dot;

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
 * Design addendum 4: a quoted column name containing a dot. It is one identifier, not a qualified
 * pair, and must be addressed whole.
 */
@Entity
@Table(name = "dot_note")
public class DotNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "\"a.b\"", nullable = false)
  String ownerId;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "a.b", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected DotNote() {}

  public DotNote(String ownerId, String tenantId, String email) {
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
      super("DotNote", "email");
    }
  }
}
