package com.housedevinci.shredding.autoconfigure.fixture;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedBytesConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import org.hibernate.annotations.Immutable;

/**
 * {@link Blob}'s field, mapped under {@code SEQUENCE} instead of {@code IDENTITY} (QUESTIONS #15).
 */
@Entity
@Table(name = "blob_seq")
public class BlobSeq {
  @Id
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "blob_seq_gen")
  @SequenceGenerator(name = "blob_seq_gen", sequenceName = "blob_seq_id_seq", allocationSize = 1)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = PayloadConverter.class)
  @Immutable
  @Column(name = "payload")
  byte[] payload;

  protected BlobSeq() {}

  public BlobSeq(String ownerId, byte[] payload) {
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
    return "BlobSeq[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class PayloadConverter extends ShreddedBytesConverter {
    public PayloadConverter() {
      super("BlobSeq", "payload");
    }
  }
}
