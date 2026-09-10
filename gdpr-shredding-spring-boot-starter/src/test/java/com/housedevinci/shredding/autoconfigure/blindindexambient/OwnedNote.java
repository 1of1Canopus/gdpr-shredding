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
 * S-13, the shape design addendum 3 change 4 says an application with an acting organisation
 * distinct from an owning one must use: the {@code @Shredded} tenant is declared as the owning one,
 * which is what the tenant column holds. The data key, the ciphertext and the blind index are then
 * all under {@code tenant_id}'s value, and one erasure request reaches all three.
 *
 * <p>The seventh pass refused this at startup (a {@code @BlindIndex(of = ...)} field may not
 * declare its own tenant); change 4 replaces that guess with a per-row equality check on the write,
 * which is what makes the shape usable again.
 *
 * <p>Note the property/column split the resolution has to get right: the property is {@code
 * tenantId}, the column is {@code tenant_id}, and {@code tenantColumn} names the column.
 */
@Entity
@Table(name = "owned_note")
public class OwnedNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

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

  protected OwnedNote() {}

  public OwnedNote(String ownerId, String tenantId, String email) {
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

  public String getTenantId() {
    return tenantId;
  }

  public String getEmail() {
    return email;
  }

  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("OwnedNote", "email");
    }
  }
}
