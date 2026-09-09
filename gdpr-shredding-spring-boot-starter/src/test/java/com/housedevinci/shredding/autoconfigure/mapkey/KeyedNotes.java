package com.housedevinci.shredding.autoconfigure.mapkey;

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
import jakarta.persistence.MapKeyColumn;
import jakarta.persistence.Table;
import java.util.HashMap;
import java.util.Map;

/**
 * Cipher fifth pass: the shredded converter on the <em>map key</em> of an
 * {@code @ElementCollection}. {@code ShreddedModel.scanAttribute} handles a {@code
 * PluralAttributeMapping} by walking {@code getElementDescriptor()} only; {@code
 * getIndexDescriptor()} - the map key, and the list index of an {@code @OrderColumn} - is never
 * walked, so a {@code ShreddedConverter} reached this way is neither modelled by the forward field
 * scan nor refused by the reverse one.
 */
@Entity
@Table(name = "keyed_notes")
public class KeyedNotes {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @ElementCollection
  @CollectionTable(name = "keyed_note", joinColumns = @JoinColumn(name = "notes_id"))
  @MapKeyColumn(name = "k")
  @Convert(attributeName = "key", converter = NoteKeyConverter.class)
  @Column(name = "v")
  Map<String, String> notes = new HashMap<>();

  protected KeyedNotes() {}

  public Long getId() {
    return id;
  }

  public Map<String, String> getNotes() {
    return notes;
  }

  public KeyedNotes(String ownerId, String key, String value) {
    this.ownerId = ownerId;
    this.notes.put(key, value);
  }

  @jakarta.persistence.Converter
  public static class NoteKeyConverter extends ShreddedStringConverter {
    public NoteKeyConverter() {
      super("KeyedNotes", "notesKey");
    }
  }
}
