package com.housedevinci.shredding.autoconfigure.twotenant;

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
 * One entity, two {@code @Shredded} fields, two <em>different</em> tenant expressions. The subject
 * expressions agree, so {@code resolveSubject}'s cross-check passes; nothing anywhere cross-checks
 * the tenant.
 */
@Entity
@Table(name = "dossier")
public class Dossier {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'org-a'}")
  @Convert(converter = NoteConverter.class)
  @Column(name = "note")
  String note;

  @Shredded(subject = "#{ownerId}", tenant = "#{'org-b'}")
  @Convert(converter = MemoConverter.class)
  @Column(name = "memo")
  String memo;

  protected Dossier() {}

  public Dossier(String ownerId, String note, String memo) {
    this.ownerId = ownerId;
    this.note = note;
    this.memo = memo;
  }

  public Long getId() {
    return id;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getNote() {
    return note;
  }

  public String getMemo() {
    return memo;
  }

  @jakarta.persistence.Converter
  public static class NoteConverter extends ShreddedStringConverter {
    public NoteConverter() {
      super("Dossier", "note");
    }
  }

  @jakarta.persistence.Converter
  public static class MemoConverter extends ShreddedStringConverter {
    public MemoConverter() {
      super("Dossier", "memo");
    }
  }
}
