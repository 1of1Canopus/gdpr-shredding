package com.housedevinci.shredding.autoconfigure.fixture;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A minimal shredded entity for {@code ShreddingIntegrationTest}, kept in its own package so
 * {@code @EntityScan} does not also pick up unrelated {@code @Entity} test fixtures declared
 * elsewhere in this module's test sources (such as {@code CipherProbeStartupTest}'s).
 */
@Entity
@Table(name = "widget")
public class Widget {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = WidgetNameConverter.class)
  @Column(name = "name")
  String name;

  protected Widget() {}

  public Widget(String ownerId, String name) {
    this.ownerId = ownerId;
    this.name = name;
  }

  public Long getId() {
    return id;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public void setOwnerId(String ownerId) {
    this.ownerId = ownerId;
  }

  public String getName() {
    return name;
  }

  @Override
  public String toString() {
    return "Widget[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class WidgetNameConverter extends ShreddedStringConverter {
    public WidgetNameConverter() {
      super("Widget", "name");
    }
  }
}
