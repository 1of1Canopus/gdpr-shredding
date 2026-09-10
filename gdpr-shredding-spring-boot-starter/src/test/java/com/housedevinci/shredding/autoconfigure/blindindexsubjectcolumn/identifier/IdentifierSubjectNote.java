package com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.identifier;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Change 8, the case Cipher left open and §3.8a decides: {@code subjectColumn} naming the entity's
 * identifier column. It is refused, explicitly, and the message says why - the identifier is not in
 * the state array the write path reads, under {@code GenerationType.IDENTITY} it does not exist at
 * all when {@code onPreInsert} derives the index, and a {@code SubjectId} is a string while an
 * identifier is a {@code Long} here, so the equality change 8 exists to make would need a rendering
 * this module would have to invent.
 */
@Entity
@Table(name = "identifier_subject_note")
public class IdentifierSubjectNote {

  @Id
  @Column(name = "id")
  Long id;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{id}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected IdentifierSubjectNote() {}

  public Long getId() {
    return id;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("IdentifierSubjectNote", "email");
    }
  }
}
