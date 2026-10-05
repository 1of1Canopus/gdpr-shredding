package com.housedevinci.shredding.autoconfigure.cipherprobe19.tpc;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/** The TABLE_PER_CLASS leaf that declares every shredded and blind-indexed column itself. */
@Entity
@Table(name = "c19_tpc_leaf", schema = "public")
public class C19TpcLeaf extends C19TpcRoot {

  @Column(name = "owner_id")
  String ownerId;

  @Column(name = "tenant_id")
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected C19TpcLeaf() {}

  public C19TpcLeaf(Long id, String ownerId, String tenantId, String email) {
    super(id);
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

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("C19TpcLeaf", "email");
    }
  }
}
