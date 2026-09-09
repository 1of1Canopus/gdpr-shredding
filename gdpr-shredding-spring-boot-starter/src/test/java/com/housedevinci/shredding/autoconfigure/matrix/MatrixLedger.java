package com.housedevinci.shredding.autoconfigure.matrix;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedBigDecimalConverter;
import com.housedevinci.shredding.jpa.ShreddedLocalDateConverter;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * The framework matrix's fixture (design §2). Deliberately carries the two types that have no
 * erased sentinel - {@code BigDecimal} and {@code LocalDate} - because those are the ones Cipher's
 * item 2 is about: with a {@code null} placeholder, an entity whose install never ran wrote {@code
 * NULL} over their live ciphertext on the next UPDATE, unseen.
 *
 * <p>It also carries a JPA {@code @PostLoad} callback that records what it was handed, which is
 * item 8's test: while the module's listener was appended rather than prepended, this callback saw
 * the placeholder.
 */
@Entity
@Table(name = "matrix_ledger")
public class MatrixLedger {

  /** What the last {@code @PostLoad} callback on this JVM was handed. Never a real application. */
  public static volatile String lastPostLoadSawNote;

  public static volatile BigDecimal lastPostLoadSawAmount;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = NoteConverter.class)
  @Column(name = "note")
  String note;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = AmountConverter.class)
  @Column(name = "amount")
  BigDecimal amount;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = DueConverter.class)
  @Column(name = "due")
  LocalDate due;

  protected MatrixLedger() {}

  public MatrixLedger(String ownerId, String note, BigDecimal amount, LocalDate due) {
    this.ownerId = ownerId;
    this.note = note;
    this.amount = amount;
    this.due = due;
  }

  @PostLoad
  void recordWhatTheCallbackSaw() {
    lastPostLoadSawNote = note;
    lastPostLoadSawAmount = amount;
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

  public BigDecimal getAmount() {
    return amount;
  }

  public LocalDate getDue() {
    return due;
  }

  @Override
  public String toString() {
    return "MatrixLedger[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class NoteConverter extends ShreddedStringConverter {
    public NoteConverter() {
      super("MatrixLedger", "note");
    }
  }

  @jakarta.persistence.Converter
  public static class AmountConverter extends ShreddedBigDecimalConverter {
    public AmountConverter() {
      super("MatrixLedger", "amount");
    }
  }

  @jakarta.persistence.Converter
  public static class DueConverter extends ShreddedLocalDateConverter {
    public DueConverter() {
      super("MatrixLedger", "due");
    }
  }
}
