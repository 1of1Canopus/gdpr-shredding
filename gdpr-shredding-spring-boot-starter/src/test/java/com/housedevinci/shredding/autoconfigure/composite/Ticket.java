package com.housedevinci.shredding.autoconfigure.composite;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;

/**
 * The fifth pass: a shredded entity with a composite identifier. Both {@code refuseIfSubjectMoved}
 * and {@code onPostLoad} skip their check outright when {@code getIdentifierColumnNames().length !=
 * 1}, which is recorded as "undemonstrated rather than proven safe". This entity demonstrates it.
 */
@Entity
@Table(name = "ticket")
@IdClass(Ticket.Key.class)
public class Ticket {
  @Id
  @Column(name = "owner_id")
  String ownerId;

  @Id
  @Column(name = "seq")
  Long seq;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = TicketNoteConverter.class)
  @Column(name = "note")
  String note;

  protected Ticket() {}

  public Ticket(String ownerId, Long seq, String note) {
    this.ownerId = ownerId;
    this.seq = seq;
    this.note = note;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public Long getSeq() {
    return seq;
  }

  public String getNote() {
    return note;
  }

  public void setOwnerId(String ownerId) {
    this.ownerId = ownerId;
  }

  public static class Key implements Serializable {
    private static final long serialVersionUID = 1L;
    String ownerId;
    Long seq;

    public Key() {}

    public Key(String ownerId, Long seq) {
      this.ownerId = ownerId;
      this.seq = seq;
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof Key k && Objects.equals(ownerId, k.ownerId) && Objects.equals(seq, k.seq);
    }

    @Override
    public int hashCode() {
      return Objects.hash(ownerId, seq);
    }
  }

  @jakarta.persistence.Converter
  public static class TicketNoteConverter extends ShreddedStringConverter {
    public TicketNoteConverter() {
      super("Ticket", "note");
    }
  }
}
