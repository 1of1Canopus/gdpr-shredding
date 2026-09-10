package com.housedevinci.shredding.autoconfigure.ninthpass.twoindex;

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

/** Cipher, ninth pass: two blind indexes on one entity, over two different {@code of} fields. */
@Entity
@Table(name = "two_index_note")
public class TwoIndexNote {

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

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = PhoneConverter.class)
  @Column(name = "phone")
  String phone;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  @BlindIndex(of = "phone", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "phone_idx")
  byte[] phoneIndex;

  protected TwoIndexNote() {}

  public TwoIndexNote(String ownerId, String tenantId, String email, String phone) {
    this.ownerId = ownerId;
    this.tenantId = tenantId;
    this.email = email;
    this.phone = phone;
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
      super("TwoIndexNote", "email");
    }
  }

  @jakarta.persistence.Converter
  public static class PhoneConverter extends ShreddedStringConverter {
    public PhoneConverter() {
      super("TwoIndexNote", "phone");
    }
  }
}
