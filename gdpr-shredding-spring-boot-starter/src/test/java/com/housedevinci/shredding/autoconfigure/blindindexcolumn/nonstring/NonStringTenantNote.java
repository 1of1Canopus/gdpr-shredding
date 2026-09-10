package com.housedevinci.shredding.autoconfigure.blindindexcolumn.nonstring;

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
 * Change 1 and change 3: a tenant column of a type that is not {@code String}. A {@code TenantId}
 * is a string; a {@code Long} in the column could not be compared with the tenant an erasure was
 * asked for without a conversion nobody declared. Refused at startup rather than converted by
 * guesswork.
 */
@Entity
@Table(name = "non_string_tenant_note")
public class NonStringTenantNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id")
  Long tenantId;

  @Shredded(subject = "#{ownerId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected NonStringTenantNote() {}

  public String getOwnerId() {
    return ownerId;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("NonStringTenantNote", "email");
    }
  }
}
