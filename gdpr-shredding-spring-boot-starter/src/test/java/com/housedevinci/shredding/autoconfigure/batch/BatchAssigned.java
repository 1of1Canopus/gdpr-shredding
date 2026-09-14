package com.housedevinci.shredding.autoconfigure.batch;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** An assigned String identifier: RowId tag 0x03, and no generator to make the id known early. */
@Entity
@Table(name = "batch_assigned")
public class BatchAssigned {

  @Id
  @Column(name = "id")
  String id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = BatchAssignedNameConverter.class)
  @Column(name = "name")
  String name;

  protected BatchAssigned() {}

  public BatchAssigned(String id, String ownerId, String name) {
    this.id = id;
    this.ownerId = ownerId;
    this.name = name;
  }

  public String getId() {
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
    return "BatchAssigned[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class BatchAssignedNameConverter extends ShreddedStringConverter {
    public BatchAssignedNameConverter() {
      super("BatchAssigned", "name");
    }
  }
}
