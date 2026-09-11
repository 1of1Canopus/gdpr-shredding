package com.housedevinci.shredding.autoconfigure.hostile.embeddedid;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.io.Serializable;

/**
 * finding item 7: a <em>single-column</em> {@code @EmbeddedId}. It passes C-38's column count check
 * - there is exactly one identifier column - but it is not a basic value, so its Java value is a
 * component object with no canonical byte form {@code RowId} could bind to. A guessed row binding
 * is no binding, so the mapping is refused at startup.
 */
@Entity
@Table(name = "hostile_embedded_id")
public class EmbeddedIdRow {

  @EmbeddedId Key key;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = SecretConverter.class)
  @Column(name = "secret")
  String secret;

  protected EmbeddedIdRow() {}

  @Embeddable
  public static class Key implements Serializable {
    private static final long serialVersionUID = 1L;

    @Column(name = "reference")
    String reference;

    protected Key() {}
  }

  @jakarta.persistence.Converter
  public static class SecretConverter extends ShreddedStringConverter {
    public SecretConverter() {
      super("EmbeddedIdRow", "secret");
    }
  }
}
