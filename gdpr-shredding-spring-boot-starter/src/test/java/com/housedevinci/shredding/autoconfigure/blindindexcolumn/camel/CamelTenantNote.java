package com.housedevinci.shredding.autoconfigure.blindindexcolumn.camel;

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
 * Design addendum 3 change 1, the regression it exists to prevent: {@code tenantColumn} is a
 * <em>column</em> name. The property here is {@code tenantId} and nothing annotates it, so
 * Hibernate's naming strategy maps it to {@code tenant_id} - which is what {@code tenantColumn}
 * names, and what the erasure's {@code UPDATE ... WHERE tenant_id = ?} matches on. A resolution
 * that looked the value up among property names would refuse this, the ordinary correct
 * configuration; this entity must boot.
 */
@Entity
@Table(name = "camel_tenant_note")
public class CamelTenantNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected CamelTenantNote() {}

  public CamelTenantNote(String ownerId, String tenantId, String email) {
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
      super("CamelTenantNote", "email");
    }
  }
}
