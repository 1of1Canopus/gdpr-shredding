package com.housedevinci.shredding.autoconfigure.cipherprobe19b.idsubject;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;

/**
 * Second pass of the PR 19 review: the subject of the blind index is the entity's own identifier,
 * a {@code uuid} column, reached through a read-only String property over that same column (the
 * direct form, {@code subjectColumn} naming the identifier with no property over it, is refused by
 * the model).
 */
@Entity
@Table(name = "c19b_owner", schema = "public")
public class C19bOwner {

  @Id
  @Column(name = "id")
  UUID id;

  /** The identifier's text, mapped read-only over the identifier column itself. */
  @Column(name = "id", insertable = false, updatable = false)
  String subject;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @Shredded(subject = "#{subject}", tenant = "#{tenantId}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  @BlindIndex(of = "email", subjectColumn = "id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;

  protected C19bOwner() {}

  public C19bOwner(UUID id, String tenantId, String email) {
    this.id = id;
    this.subject = id.toString();
    this.tenantId = tenantId;
    this.email = email;
  }

  public String getSubject() {
    return subject;
  }

  public String getTenantId() {
    return tenantId;
  }

  public String getEmail() {
    return email;
  }

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("C19bOwner", "email");
    }
  }
}
