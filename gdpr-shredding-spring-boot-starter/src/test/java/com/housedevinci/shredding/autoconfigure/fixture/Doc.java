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
 * Two shredded fields ({@code title}, {@code body}), each nullable independently - for CIPHER-11
 * (projections), CIPHER-12 (a nulled subject source) and CIPHER-14 (the update check skipping the
 * first shredded column when it happens to be null).
 */
@Entity
@Table(name = "doc")
public class Doc {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id")
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = DocTitleConverter.class)
  @Column(name = "title")
  String title;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = DocBodyConverter.class)
  @Column(name = "body")
  String body;

  protected Doc() {}

  public Doc(String ownerId, String title, String body) {
    this.ownerId = ownerId;
    this.title = title;
    this.body = body;
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

  public String getTitle() {
    return title;
  }

  public void setTitle(String title) {
    this.title = title;
  }

  public String getBody() {
    return body;
  }

  @Override
  public String toString() {
    return "Doc[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class DocTitleConverter extends ShreddedStringConverter {
    public DocTitleConverter() {
      super("Doc", "title");
    }
  }

  @jakarta.persistence.Converter
  public static class DocBodyConverter extends ShreddedStringConverter {
    public DocBodyConverter() {
      super("Doc", "body");
    }
  }
}
