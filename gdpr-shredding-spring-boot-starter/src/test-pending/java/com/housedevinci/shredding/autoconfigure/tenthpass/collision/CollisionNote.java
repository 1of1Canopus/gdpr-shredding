package com.housedevinci.shredding.autoconfigure.tenthpass.collision;

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
 * Cipher, tenth pass: two columns whose names differ only in case - the quoted {@code "Owner"} the
 * subject lives in, and the plain {@code owner} beside it. {@code ShreddedModel.unquote} folds the
 * first to the second before it compares, and the erasure interpolates the folded form unquoted.
 */
@Entity
@Table(name = "collision_note")
public class CollisionNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  /** The real subject column. */
  @Column(name = "\"Owner\"", nullable = false)
  String ownerId;

  /** An unrelated column that folds to the same name. */
  @Column(name = "owner")
  String label;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected CollisionNote() {}

  public CollisionNote(String ownerId, String label, String tenantId, String email) {
    this.ownerId = ownerId;
    this.label = label;
    this.tenantId = tenantId;
    this.email = email;
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
      super("CollisionNote", "email");
    }
  }
}
