package com.housedevinci.shredding.autoconfigure.columnid.assocsubject;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/**
 * Design addendum 4, change 6: {@code subjectColumn} names a column that <em>is</em> mapped - by a
 * {@code @JoinColumn}. It resolves to a {@code ToOneAttributeMapping}, not to a {@code
 * BasicValuedModelPart}, so before change 6 it fell into "no property of this entity maps to that
 * column, here are the ones I map", which is false and sends the developer looking for a typo.
 */
@Entity
@Table(name = "assocsubject_note")
public class AssocSubjectNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @ManyToOne
  @JoinColumn(name = "owner_id", nullable = false)
  SubjectOwner owner;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{owner.id}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected AssocSubjectNote() {}

  public AssocSubjectNote(SubjectOwner owner, String tenantId, String email) {
    this.owner = owner;
    this.tenantId = tenantId;
    this.email = email;
  }

  public SubjectOwner getOwner() {
    return owner;
  }

  public String getTenantId() {
    return tenantId;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("AssocSubjectNote", "email");
    }
  }
}
