package com.housedevinci.shredding.autoconfigure.batch;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;

/**
 * A UUID primary key: RowId tag 0x02, generated before the insert, so Hibernate batches it - the
 * most common shape in which an application meets S-1 in production. The identifier also comes back
 * from JDBC as a {@code UUID} rather than a number, which the settlement query has to match on.
 */
@Entity
@Table(name = "batch_uuid")
public class BatchUuid {

  @Id @GeneratedValue UUID id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = BatchUuidNameConverter.class)
  @Column(name = "name")
  String name;

  protected BatchUuid() {}

  public BatchUuid(String ownerId, String name) {
    this.ownerId = ownerId;
    this.name = name;
  }

  public UUID getId() {
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
    return "BatchUuid[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class BatchUuidNameConverter extends ShreddedStringConverter {
    public BatchUuidNameConverter() {
      super("BatchUuid", "name");
    }
  }
}
