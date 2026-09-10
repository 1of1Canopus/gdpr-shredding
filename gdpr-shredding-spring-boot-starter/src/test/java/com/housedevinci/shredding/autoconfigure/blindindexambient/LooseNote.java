package com.housedevinci.shredding.autoconfigure.blindindexambient;

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
 * Design addendum 3 change 3: a tenant column the application is free to leave null or blank. An
 * index derived under nothing is an index no {@code WHERE tenant_id = ?} can match, so the write is
 * refused rather than performed - the column is mapped {@code nullable = true} here precisely so
 * the refusal has to come from this module and not from a NOT NULL constraint.
 */
@Entity
@Table(name = "loose_note")
public class LooseNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id")
  String tenantId;

  @Shredded(subject = "#{ownerId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  public String getOwnerId() {
    return ownerId;
  }

  public String getTenantId() {
    return tenantId;
  }

  protected LooseNote() {}

  public LooseNote(String ownerId, String tenantId, String email) {
    this.ownerId = ownerId;
    this.tenantId = tenantId;
    this.email = email;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("LooseNote", "email");
    }
  }
}
