package com.housedevinci.shredding.autoconfigure.hostile.naturalid;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.NaturalId;

/**
 * finding item 10 / D4: a {@code @Shredded} column that is also part of the natural id. Natural-id
 * resolution reads the column through the converter outside any load event, so it sees the read
 * placeholder - and a natural id that is personal data cannot be an index key in the first place.
 */
@Entity
@Table(name = "hostile_natural_id")
public class NaturalIdRow {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @NaturalId
  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = EmailConverter.class)
  @Column(name = "email")
  String email;

  protected NaturalIdRow() {}

  @jakarta.persistence.Converter
  public static class EmailConverter extends ShreddedStringConverter {
    public EmailConverter() {
      super("NaturalIdRow", "email");
    }
  }
}
