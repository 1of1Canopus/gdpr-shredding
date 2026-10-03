package com.housedevinci.shredding.autoconfigure.admission.single;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;

/** The SINGLE_TABLE subclass declaring the shredded columns, stored in the root table. */
@Entity
@jakarta.persistence.DiscriminatorValue("leaf")
public class B2SingleLeaf extends B2SingleRoot {

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

  protected B2SingleLeaf() {}

  public B2SingleLeaf(String ownerId, String tenantId, String email) {
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
      super("B2SingleLeaf", "email");
    }
  }
}
