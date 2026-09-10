package com.housedevinci.shredding.autoconfigure.blindindexcolumn.twoproperty;

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
 * Change 1: two properties over one column ({@code tenantId} writable, {@code tenantIdReadOnly}
 * mapped to the same column read-only). The write path has to read one value out of the state array
 * for the column the erasure matches on, and two properties give it no single answer. Refused at
 * startup, naming both.
 */
@Entity
@Table(name = "two_property_tenant_note")
public class TwoPropertyTenantNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id")
  String tenantId;

  @Column(name = "tenant_id", insertable = false, updatable = false)
  String tenantIdReadOnly;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected TwoPropertyTenantNote() {}

  public String getOwnerId() {
    return ownerId;
  }

  public String getTenantId() {
    return tenantId;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("TwoPropertyTenantNote", "email");
    }
  }
}
