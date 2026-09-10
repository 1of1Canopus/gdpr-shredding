package com.housedevinci.shredding.autoconfigure.fixture;

import com.housedevinci.shredding.api.BlindIndex;
import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedBigDecimalConverter;
import com.housedevinci.shredding.jpa.ShreddedJsonConverter;
import com.housedevinci.shredding.jpa.ShreddedLocalDateConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * L2. Exercises three more {@code Shredded*Converter} base classes ({@code
 * ShreddedBigDecimalConverter}, {@code ShreddedLocalDateConverter}, {@code ShreddedJsonConverter})
 * and a {@code @BlindIndex} column - none of which {@code fixture.Widget} touches - through a real
 * Hibernate round trip.
 *
 * <p>{@code ShreddedBytesConverter} is deliberately not exercised here: wiring it into this fixture
 * surfaced a real, previously-untested failure (an entity with a {@code byte[]} {@code @Shredded}
 * field and {@code @GeneratedValue(IDENTITY)} refuses its own first insert with {@code
 * SHRED-CONTEXT-001}, because Hibernate deep-copies a mutable attribute's value - calling the
 * converter again - to build the entity's dirty-checking snapshot, outside the
 * onPreInsert/onPostInsert bracket). That is out of scope for this remediation pass (not one of
 * Cipher's findings) and is flagged instead in {@code QUESTIONS.md} for the next review.
 */
@Entity
@Table(name = "gadget")
public class Gadget {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Column(name = "tenant_id", nullable = false)
  String tenantId = "default";

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = BalanceConverter.class)
  @Column(name = "balance")
  BigDecimal balance;

  @Shredded(subject = "#{ownerId}", tenant = "#{tenantId}")
  @Convert(converter = InstalledOnConverter.class)
  @Column(name = "installed_on")
  LocalDate installedOn;

  // S-7 (Cipher seventh pass): no explicit tenant expression here, deliberately - the field a
  // @BlindIndex names in of= may not declare its own @Shredded(tenant=...), because
  // writeBlindIndexes would derive the index under that declared tenant while the erasure that is
  // meant to destroy it matches on this row's own tenant_id column value, and startup now refuses
  // that shape (SHRED-CONFIG-001). Falls back to the row's primary tenant, i.e. balance's - which
  // is tenant_id, the same column the erasure matches on.
  @Shredded(subject = "#{ownerId}")
  @Convert(converter = MetadataConverter.class)
  @Column(name = "metadata")
  String metadata;

  @BlindIndex(of = "metadata", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "metadata_bidx")
  byte[] metadataBidx;

  protected Gadget() {}

  public Gadget(String ownerId, BigDecimal balance, LocalDate installedOn, String metadata) {
    this.ownerId = ownerId;
    this.balance = balance;
    this.installedOn = installedOn;
    this.metadata = metadata;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getTenantId() {
    return tenantId;
  }

  public BigDecimal getBalance() {
    return balance;
  }

  public LocalDate getInstalledOn() {
    return installedOn;
  }

  public String getMetadata() {
    return metadata;
  }

  @Override
  public String toString() {
    return "Gadget[" + ownerId + "]";
  }

  @jakarta.persistence.Converter
  public static class BalanceConverter extends ShreddedBigDecimalConverter {
    public BalanceConverter() {
      super("Gadget", "balance");
    }
  }

  @jakarta.persistence.Converter
  public static class InstalledOnConverter extends ShreddedLocalDateConverter {
    public InstalledOnConverter() {
      super("Gadget", "installedOn");
    }
  }

  @jakarta.persistence.Converter
  public static class MetadataConverter extends ShreddedJsonConverter {
    public MetadataConverter() {
      super("Gadget", "metadata");
    }
  }
}
