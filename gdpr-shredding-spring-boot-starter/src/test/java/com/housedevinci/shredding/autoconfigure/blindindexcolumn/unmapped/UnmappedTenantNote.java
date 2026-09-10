package com.housedevinci.shredding.autoconfigure.blindindexcolumn.unmapped;

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
 * Change 1: {@code tenantColumn} naming the <em>property</em> ({@code tenantId}) rather than the
 * column ({@code tenant_id}). No column of this table is called {@code tenantid}, so the erasure's
 * {@code UPDATE} would fail on every erasure and the write path would have nothing to read. Refused
 * at startup.
 */
@Entity
@Table(name = "unmapped_tenant_note")
public class UnmappedTenantNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id")
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenantid")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected UnmappedTenantNote() {}

  public String getOwnerId() {
    return ownerId;
  }

  public String getTenantId() {
    return tenantId;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("UnmappedTenantNote", "email");
    }
  }
}
