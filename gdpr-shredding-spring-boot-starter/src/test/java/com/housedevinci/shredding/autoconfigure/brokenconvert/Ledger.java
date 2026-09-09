package com.housedevinci.shredding.autoconfigure.brokenconvert;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Converts;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * C-19's repro: {@code note} is a properly declared {@code @Shredded} field; {@code secret} is
 * mapped by the same kind of {@code ShreddedConverter} through a class-level
 * {@code @Convert(attributeName=...)} and carries no {@code @Shredded} annotation at all. {@code
 * ShreddedModel.scan}'s forward pass only ever looks at field-level {@code @Shredded}, so {@code
 * secret} used to be invisible to the model - fully encrypted, never verified on read.
 *
 * <p>Deliberately kept out of the {@code ...autoconfigure.fixture} package and off its
 * {@code @EntityScan(basePackageClasses = Widget.class)}: once the C-19 fix is in place, an
 * application whose metamodel includes this entity refuses to start at all (that is the point of
 * the fix), so this fixture must not be reachable by the entity scan any other integration test in
 * this module shares, or it would take every one of them down with it. See {@code
 * CipherProbeReverseScanTest}, which is the only test that boots a context containing this entity,
 * and boots it expecting exactly that refusal.
 */
@Entity
@Table(name = "ledger")
@Converts({@Convert(attributeName = "secret", converter = Ledger.LedgerSecretConverter.class)})
public class Ledger {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = LedgerNoteConverter.class)
  @Column(name = "note")
  String note;

  @Column(name = "secret")
  String secret;

  protected Ledger() {}

  public Ledger(String ownerId, String note, String secret) {
    this.ownerId = ownerId;
    this.note = note;
    this.secret = secret;
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

  public String getSecret() {
    return secret;
  }

  @Override
  public String toString() {
    return "Ledger[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class LedgerNoteConverter extends ShreddedStringConverter {
    public LedgerNoteConverter() {
      super("Ledger", "note");
    }
  }

  @jakarta.persistence.Converter
  public static class LedgerSecretConverter extends ShreddedStringConverter {
    public LedgerSecretConverter() {
      super("Ledger", "secret");
    }
  }
}
