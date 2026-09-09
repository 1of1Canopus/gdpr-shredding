package com.housedevinci.shredding.autoconfigure.propaccess;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A shredded entity mapped with {@code @Access(AccessType.PROPERTY)} - the mapping annotations on
 * the getters, {@code @Shredded} and {@code @Convert} where this module's startup scan looks for
 * them, on the field. Hibernate ignores field-level mapping annotations under property access, so
 * the {@code @Convert} is never applied.
 */
@Entity
@Table(name = "prop_widget")
@Access(AccessType.PROPERTY)
public class PropWidget {

  private Long id;

  private String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = PropWidgetNameConverter.class)
  private String name;

  protected PropWidget() {}

  public PropWidget(String ownerId, String name) {
    this.ownerId = ownerId;
    this.name = name;
  }

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  @Column(name = "owner_id", nullable = false)
  public String getOwnerId() {
    return ownerId;
  }

  public void setOwnerId(String ownerId) {
    this.ownerId = ownerId;
  }

  @Column(name = "name")
  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @jakarta.persistence.Converter
  public static class PropWidgetNameConverter extends ShreddedStringConverter {
    public PropWidgetNameConverter() {
      super("PropWidget", "name");
    }
  }
}
