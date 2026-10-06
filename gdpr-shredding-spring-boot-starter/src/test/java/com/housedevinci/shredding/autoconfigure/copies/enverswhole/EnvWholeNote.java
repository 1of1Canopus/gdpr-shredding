package com.housedevinci.shredding.autoconfigure.copies.enverswhole;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Audit-table coverage fixture, E3. */
@Entity
@org.hibernate.envers.Audited
@Table(name = "env_whole_note", schema = "public")
public class EnvWholeNote {
  @Id Long id;

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

  protected EnvWholeNote() {}

  public EnvWholeNote(Long id, String ownerId, String tenantId, String email) {
    this.id = id;
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

  public String getEmail() {
    return email;
  }

  /** The field's converter. */
  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("EnvWholeNote", "email");
    }
  }
}
