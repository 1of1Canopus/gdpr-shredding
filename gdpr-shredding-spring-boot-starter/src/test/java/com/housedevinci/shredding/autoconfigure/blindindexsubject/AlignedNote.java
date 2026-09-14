package com.housedevinci.shredding.autoconfigure.blindindexsubject;

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
 * S-20, design addendum 3 change 8 (§3.8d): {@link SplitNote}'s application shape declared
 * correctly. The subject expression and {@code subjectColumn} name one value - the customer
 * reference - so the data key, the ciphertext and the index are all under the subject one erasure
 * request names, and that request reaches all three.
 *
 * <p>The property/column split is here too, and the resolution has to get it right: the property is
 * {@code customerRef}, the column is {@code customer_ref}, and {@code subjectColumn} names the
 * column, exactly as {@code tenantColumn} names {@code tenant_id} over {@code tenantId}.
 */
@Entity
@Table(name = "aligned_note")
public class AlignedNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  /** Not the subject: an ordinary reference this probe looks rows up by. */
  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "customer_ref", nullable = false)
  String customerRef;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{customerRef}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "customer_ref", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected AlignedNote() {}

  public AlignedNote(String ownerId, String customerRef, String tenantId, String email) {
    this.ownerId = ownerId;
    this.customerRef = customerRef;
    this.tenantId = tenantId;
    this.email = email;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getCustomerRef() {
    return customerRef;
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
      super("AlignedNote", "email");
    }
  }
}
