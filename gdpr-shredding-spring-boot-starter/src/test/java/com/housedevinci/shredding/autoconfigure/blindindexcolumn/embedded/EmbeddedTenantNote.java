package com.housedevinci.shredding.autoconfigure.blindindexcolumn.embedded;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Change 1: the tenant column is mapped only inside an {@code @Embeddable}. The write path reads
 * the tenant out of the entity's own top-level state array, where the component sits as one object
 * and not as its columns, so the value the index would be derived under is not there. Refused at
 * startup, naming the path it was found at.
 */
@Entity
@Table(name = "embedded_tenant_note")
public class EmbeddedTenantNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Embedded Ownership ownership;

  @Shredded(subject = "#{ownerId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected EmbeddedTenantNote() {}

  public String getOwnerId() {
    return ownerId;
  }

  /** The tenant, one level down. */
  @Embeddable
  public static class Ownership {
    @Column(name = "tenant_id")
    String tenantId;

    public String getTenantId() {
      return tenantId;
    }
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("EmbeddedTenantNote", "email");
    }
  }
}
