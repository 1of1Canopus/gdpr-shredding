package com.housedevinci.shredding.autoconfigure.embedcollection;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;

/**
 * The maintainers' mandated companion to {@code CipherProbeEmbeddableScanTest}'s {@code Vault}
 * (C-29): a {@code @Shredded} field declared inside an {@code @Embeddable} reached through an
 * {@code @ElementCollection}, not a plain {@code @Embedded} singular component - so {@code
 * refuseUnmodelledShreddedConverters} has to recurse through a {@code PluralAttributeMapping} whose
 * element descriptor is itself embeddable-valued, not just an {@code EmbeddableValuedModelPart}
 * directly on the entity. In its own package, deliberately: {@code @EntityScan(basePackageClasses =
 * ...)} scans the whole package, and this entity must not share one with {@code Vault} - which
 * already, and independently, fails startup for its own {@code @Embedded} violation - or a probe
 * built to isolate this shape would silently exercise that one instead.
 */
@Entity
@Table(name = "vault_with_notes")
public class VaultWithNotes {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @ElementCollection
  @CollectionTable(name = "vault_note", joinColumns = @JoinColumn(name = "vault_id"))
  List<Note> notes = new ArrayList<>();

  protected VaultWithNotes() {}

  public VaultWithNotes(String ownerId, String token) {
    this.ownerId = ownerId;
    this.notes.add(new Note(token));
  }

  public String getOwnerId() {
    return ownerId;
  }

  public List<Note> getNotes() {
    return notes;
  }

  @Embeddable
  public static class Note {
    @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
    @Convert(converter = NoteTokenConverter.class)
    @Column(name = "token")
    String token;

    protected Note() {}

    public Note(String token) {
      this.token = token;
    }

    public String getToken() {
      return token;
    }
  }

  @jakarta.persistence.Converter
  public static class NoteTokenConverter extends ShreddedStringConverter {
    public NoteTokenConverter() {
      super("VaultWithNotes", "token");
    }
  }
}
