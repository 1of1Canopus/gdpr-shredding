package com.housedevinci.shredding.autoconfigure.twelfthpass.secondaryidx;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrimaryKeyJoinColumn;
import jakarta.persistence.SecondaryTable;
import jakarta.persistence.Table;

/**
 * Cipher, twelfth pass: the one axis with no {@code @SecondaryTable} refusal. The {@code @Shredded}
 * column and both index axes stay on the primary table - only the {@code @BlindIndex} byte[] moves
 * to the secondary one, which {@code resolveIndexColumns} never compares against {@code
 * primaryTable(persister)}.
 */
@Entity
@Table(name = "secidx_note")
@SecondaryTable(name = "secidx_note_ext", pkJoinColumns = @PrimaryKeyJoinColumn(name = "id"))
public class SecondaryIdxNote {

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
  @Column(name = "email_idx", table = "secidx_note_ext")
  byte[] emailIndex;

  protected SecondaryIdxNote() {}

  public SecondaryIdxNote(String ownerId, String tenantId, String email) {
    this.ownerId = ownerId;
    this.tenantId = tenantId;
    this.email = email;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getEmail() {
    return email;
  }

  public String getTenantId() {
    return tenantId;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("SecondaryIdxNote", "email");
    }
  }
}
