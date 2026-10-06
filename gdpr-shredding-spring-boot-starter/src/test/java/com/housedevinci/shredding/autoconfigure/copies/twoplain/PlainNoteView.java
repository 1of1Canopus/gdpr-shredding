package com.housedevinci.shredding.autoconfigure.copies.twoplain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Audit-table coverage fixture, E16: a second, unaudited entity on the same table. */
@Entity
@Table(name = "plain_note", schema = "public")
public class PlainNoteView {
  @Id Long id;

  @Column(name = "email_idx", insertable = false, updatable = false)
  byte[] emailIndex;

  protected PlainNoteView() {}
}
