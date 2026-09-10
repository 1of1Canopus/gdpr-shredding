package com.housedevinci.shredding.autoconfigure.ninthpass.elements;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;

/**
 * Cipher, ninth pass: an {@code @ElementCollection} whose element carries a {@code @Shredded} value
 * and its {@code @BlindIndex}. The forward field scan walks entity classes, so it never sees either
 * annotation; the index would live in the collection table, which no {@code BlindIndexColumn}
 * names.
 */
@Entity
@Table(name = "tagged_note")
public class TaggedNote {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id", nullable = false)
  String tenantId;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "tagged_note_tag", joinColumns = @JoinColumn(name = "note_id"))
  List<Tag> tags = new ArrayList<>();

  protected TaggedNote() {}

  public TaggedNote(String ownerId, String tenantId, String tagValue) {
    this.ownerId = ownerId;
    this.tenantId = tenantId;
    this.tags.add(new Tag(tagValue));
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getTenantId() {
    return tenantId;
  }

  public List<Tag> getTags() {
    return tags;
  }
}
