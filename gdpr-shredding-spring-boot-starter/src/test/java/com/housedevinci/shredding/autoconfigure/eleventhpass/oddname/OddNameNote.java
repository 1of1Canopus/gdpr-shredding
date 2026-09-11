package com.housedevinci.shredding.autoconfigure.eleventhpass.oddname;

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
 * The eleventh pass: the two identifier shapes Hibernate's IdentifierHelper quotes beyond what the
 * mapping says and ColumnRef's own pattern admits unquoted - a leading underscore and a dollar
 * sign. Both are legal unquoted PostgreSQL identifiers.
 */
@Entity
@Table(name = "oddname_note")
public class OddNameNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "_owner", nullable = false)
  String ownerId;

  @Column(name = "t$x", nullable = false)
  String tenantId;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "_owner", tenantColumn = "t$x")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected OddNameNote() {}

  public OddNameNote(String ownerId, String tenantId, String email) {
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

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("OddNameNote", "email");
    }
  }
}
