package com.housedevinci.shredding.cipherrc.aud3;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.envers.Audited;
import org.hibernate.envers.NotAudited;

/**
 * Release-candidate probe fixture: the shape a developer reaches after the module refuses an
 * audited ciphertext column. The {@code @Shredded} field is {@code @NotAudited}; the blind index is
 * an ordinary {@code byte[]} column, so Envers mirrors it into {@code public.rc_composed_note_aud}
 * with no converter the module can see.
 */
@Entity
@Audited
@Table(name = "rc_composed_note", schema = "public")
public class RcComposedNote {

  @Id Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @NotAudited
  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected RcComposedNote() {}

  public RcComposedNote(Long id, String ownerId, String tenantId, String email) {
    this.id = id;
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

  public void setEmail(String email) {
    this.email = email;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("RcComposedNote", "email");
    }
  }
}
