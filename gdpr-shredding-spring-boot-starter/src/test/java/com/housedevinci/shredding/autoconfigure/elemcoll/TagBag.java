package com.housedevinci.shredding.autoconfigure.elemcoll;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;

/**
 * Cipher fifth pass: an {@code @ElementCollection} of <em>basic</em> values carrying the shredded
 * converter directly, not of {@code @Embeddable}s. {@code VaultWithNotes} covers the embeddable
 * shape; here {@code PluralAttributeMapping.getElementDescriptor()} is itself the {@code
 * BasicValuedModelPart} that holds the converter.
 */
@Entity
@Table(name = "tag_bag")
public class TagBag {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @ElementCollection
  @CollectionTable(name = "tag_bag_tag", joinColumns = @JoinColumn(name = "bag_id"))
  @Column(name = "tag")
  @Convert(converter = TagConverter.class)
  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  List<String> tags = new ArrayList<>();

  protected TagBag() {}

  public TagBag(String ownerId, String tag) {
    this.ownerId = ownerId;
    this.tags.add(tag);
  }

  @jakarta.persistence.Converter
  public static class TagConverter extends ShreddedStringConverter {
    public TagConverter() {
      super("TagBag", "tags");
    }
  }
}
