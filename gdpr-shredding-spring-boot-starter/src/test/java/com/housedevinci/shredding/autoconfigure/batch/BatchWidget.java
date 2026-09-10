package com.housedevinci.shredding.autoconfigure.batch;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;

/**
 * A SEQUENCE-identified shredded entity: the id strategy that lets Hibernate batch inserts, which
 * is the configuration S-1 lives in.
 */
@Entity
@Table(name = "batch_widget")
public class BatchWidget {

  @Id
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "batch_widget_gen")
  @SequenceGenerator(
      name = "batch_widget_gen",
      sequenceName = "batch_widget_id_seq",
      allocationSize = 50)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = BatchWidgetNameConverter.class)
  @Column(name = "name")
  String name;

  protected BatchWidget() {}

  public BatchWidget(String ownerId, String name) {
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

  public void setName(String name) {
    this.name = name;
  }

  @Override
  public String toString() {
    return "BatchWidget[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class BatchWidgetNameConverter extends ShreddedStringConverter {
    public BatchWidgetNameConverter() {
      super("BatchWidget", "name");
    }
  }
}
