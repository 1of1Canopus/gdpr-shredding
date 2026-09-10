package com.housedevinci.shredding.autoconfigure.ninthpass.elements;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;

/** The element: a shredded value and a blind index of it, both inside a component. */
@Embeddable
public class Tag {

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = ValueConverter.class)
  @Column(name = "tag_value")
  String value;

  @BlindIndex(of = "value", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "tag_value_idx")
  byte[] valueIndex;

  protected Tag() {}

  public Tag(String value) {
    this.value = value;
  }

  public String getValue() {
    return value;
  }

  @jakarta.persistence.Converter
  public static class ValueConverter extends ShreddedStringConverter {
    public ValueConverter() {
      super("Tag", "value");
    }
  }
}
