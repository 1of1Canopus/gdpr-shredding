package com.housedevinci.shredding.cipherrc2.order;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Converter;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.envers.Audited;
import org.hibernate.envers.NotAudited;

/**
 * The shape a running 0.1.1 install with Envers has: 0.1.1 already refused an audited
 * {@code @Shredded} field and Envers' auto-registered listeners, so the ciphertext is
 * {@code @NotAudited} and Envers is composed manually; the blind index is audited and the table
 * names no schema, as 0.1.1 allowed.
 */
@Entity
@Audited
@Table(name = "rc2_order_note")
public class RcOrderNote {

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

  protected RcOrderNote() {}

  public String getOwnerId() {
    return ownerId;
  }

  public String getTenantId() {
    return tenantId;
  }

  public String getEmail() {
    return email;
  }

  /** The converter for {@link #email}. */
  @Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("RcOrderNote", "email");
    }
  }
}
