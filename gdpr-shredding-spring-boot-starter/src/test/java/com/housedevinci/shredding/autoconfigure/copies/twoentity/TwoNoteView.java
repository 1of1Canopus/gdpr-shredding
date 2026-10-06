package com.housedevinci.shredding.autoconfigure.copies.twoentity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.envers.Audited;

/** Audit-table coverage fixture, E14: a second entity on the same table, audited. */
@Entity
@Audited
@Table(name = "two_note", schema = "public")
public class TwoNoteView {
  @Id Long id;

  @Column(name = "email_idx")
  byte[] emailIndex;

  protected TwoNoteView() {}
}
