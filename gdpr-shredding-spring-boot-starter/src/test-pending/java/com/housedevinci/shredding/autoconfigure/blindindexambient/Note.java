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
 * S-7b, the general case: no field declares a tenant, so nothing the S-7 startup refusal looks at
 * is present, and the index is derived under the ambient {@code TenantSupplier} value - while the
 * erasure matches on whatever this row's {@code tenant_id} column happens to hold. The application
 * writes that column itself; here it holds the note's owning company ({@code org-b}) while the
 * request-scoped supplier yields the acting organisation ({@code org-a}). Nothing about this shape
 * is exotic and nothing in the module refuses it.
 */
@Entity
@Table(name = "ambient_note")
public class Note {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  /** Written by the application, matched on by the erasure. Not the ambient tenant. */
  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{ownerId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected Note() {}

  public Note(String ownerId, String tenantId, String email) {
    this.ownerId = ownerId;
    this.tenantId = tenantId;
    this.email = email;
  }

  public Long getId() {
    return id;
  }

  public String getOwnerId() {
    return ownerId;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("Note", "email");
    }
  }
}
