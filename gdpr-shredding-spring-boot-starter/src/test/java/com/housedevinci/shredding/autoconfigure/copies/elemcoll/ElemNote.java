package com.housedevinci.shredding.autoconfigure.copies.elemcoll;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Audit-table coverage fixture, F3. */
@Entity
@Table(name = "elem_note", schema = "public")
public class ElemNote {
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

  @jakarta.persistence.ElementCollection
  @jakarta.persistence.CollectionTable(
      name = "elem_note_tag",
      schema = "public",
      joinColumns =
          @jakarta.persistence.JoinColumn(
              name = "note_email_idx",
              referencedColumnName = "email_idx"))
  @Column(name = "tag")
  java.util.Set<String> tags = new java.util.HashSet<>();

  protected ElemNote() {}

  public ElemNote(Long id, String ownerId, String tenantId, String email) {
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
      super("ElemNote", "email");
    }
  }
}
