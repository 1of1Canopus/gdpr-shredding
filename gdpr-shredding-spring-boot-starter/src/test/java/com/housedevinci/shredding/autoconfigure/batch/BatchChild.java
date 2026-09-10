package com.housedevinci.shredding.autoconfigure.batch;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;

/** A shredded row that only ever reaches the database through its parent's cascade. */
@Entity
@Table(name = "batch_child")
public class BatchChild {

  @Id
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "batch_child_gen")
  @SequenceGenerator(
      name = "batch_child_gen",
      sequenceName = "batch_child_id_seq",
      allocationSize = 50)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = BatchChildNoteConverter.class)
  @Column(name = "note")
  String note;

  protected BatchChild() {}

  public BatchChild(String ownerId, String note) {
    this.ownerId = ownerId;
    this.note = note;
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

  public void setNote(String note) {
    this.note = note;
  }

  @Override
  public String toString() {
    return "BatchChild[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class BatchChildNoteConverter extends ShreddedStringConverter {
    public BatchChildNoteConverter() {
      super("BatchChild", "note");
    }
  }
}
