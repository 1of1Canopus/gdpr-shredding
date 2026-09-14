package com.housedevinci.shredding.autoconfigure.batch;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** The IDENTITY half of the matrix: the strategy design 3.1 rebinds, under a batch size. */
@Entity
@Table(name = "batch_identity")
public class BatchIdentity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = BatchIdentityNameConverter.class)
  @Column(name = "name")
  String name;

  protected BatchIdentity() {}

  public BatchIdentity(String ownerId, String name) {
    this.ownerId = ownerId;
    this.name = name;
  }

  public Long getId() {
    return id;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getName() {
    return name;
  }

  @Override
  public String toString() {
    return "BatchIdentity[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class BatchIdentityNameConverter extends ShreddedStringConverter {
    public BatchIdentityNameConverter() {
      super("BatchIdentity", "name");
    }
  }
}
