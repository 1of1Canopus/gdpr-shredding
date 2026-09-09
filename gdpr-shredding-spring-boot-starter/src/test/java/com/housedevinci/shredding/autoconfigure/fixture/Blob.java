package com.housedevinci.shredding.autoconfigure.fixture;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedBytesConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.Immutable;

/**
 * CIPHER-16 / QUESTIONS #15: a {@code byte[]} {@code @Shredded} field under
 * {@code @GeneratedValue(IDENTITY)}. {@code @Immutable} is what stops {@code
 * AttributeConverterMutabilityPlan} deep-copying the converted value (a second, out-of-bracket call
 * to the converter) to build the dirty-checking snapshot. Top-level, not nested: a nested
 * {@code @Entity} makes {@code ShreddingEventListener.entityName} (which strips only up to the last
 * {@code '.'}) and {@code ShreddedModel.entityName} (which uses {@code Class.getSimpleName()})
 * disagree on the entity's name for a {@code $}-qualified persister name, which is a different,
 * uninteresting bug that has nothing to do with this fixture's actual purpose.
 */
@Entity
@Table(name = "blob")
public class Blob {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = PayloadConverter.class)
  @Immutable
  @Column(name = "payload")
  byte[] payload;

  protected Blob() {}

  public Blob(String ownerId, byte[] payload) {
    this.ownerId = ownerId;
    this.payload = payload;
  }

  public Long getId() {
    return id;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public byte[] getPayload() {
    return payload;
  }

  @Override
  public String toString() {
    return "Blob[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class PayloadConverter extends ShreddedBytesConverter {
    public PayloadConverter() {
      super("Blob", "payload");
    }
  }
}
