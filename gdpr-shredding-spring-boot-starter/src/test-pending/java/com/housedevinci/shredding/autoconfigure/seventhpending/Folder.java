package com.housedevinci.shredding.autoconfigure.seventhpending;

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
 * S-2's supported shape - two {@code @Shredded} fields of one entity declaring different tenant
 * expressions - combined with the other feature that names a tenant: a {@code @BlindIndex}, whose
 * erasure matches on the row's own {@code tenantColumn}.
 */
@Entity
@Table(name = "folder")
public class Folder {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  /** What the erasure's blind-index UPDATE matches on. Holds this row's primary tenant. */
  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'org-a'}")
  @Convert(converter = TitleConverter.class)
  @Column(name = "title")
  String title;

  @Shredded(subject = "#{ownerId}", tenant = "#{'org-b'}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected Folder() {}

  public Folder(String ownerId, String tenantId, String title, String email) {
    this.ownerId = ownerId;
    this.tenantId = tenantId;
    this.title = title;
    this.email = email;
  }

  public Long getId() {
    return id;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getTenantId() {
    return tenantId;
  }

  public String getTitle() {
    return title;
  }

  public String getEmail() {
    return email;
  }

  @jakarta.persistence.Converter
  public static class TitleConverter extends ShreddedStringConverter {
    public TitleConverter() {
      super("Folder", "title");
    }
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("Folder", "email");
    }
  }
}
