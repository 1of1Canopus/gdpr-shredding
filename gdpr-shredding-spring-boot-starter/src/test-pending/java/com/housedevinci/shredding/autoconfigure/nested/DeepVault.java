package com.housedevinci.shredding.autoconfigure.nested;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Cipher fifth pass: C-29's reverse-scan recursion at depth two. {@code Vault} proves one level of
 * {@code @Embedded}; this entity puts the {@code @Shredded} field inside an {@code @Embeddable}
 * nested inside another {@code @Embeddable}, so {@code scanAttribute} has to recurse through two
 * {@code EmbeddableValuedModelPart}s before it reaches the {@code BasicValuedModelPart}.
 */
@Entity
@Table(name = "deep_vault")
public class DeepVault {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Embedded Outer outer;

  protected DeepVault() {}

  public DeepVault(String ownerId, String token) {
    this.ownerId = ownerId;
    this.outer = new Outer(token);
  }

  @Embeddable
  public static class Outer {
    @Embedded Inner inner;

    protected Outer() {}

    Outer(String token) {
      this.inner = new Inner(token);
    }
  }

  @Embeddable
  public static class Inner {
    @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
    @Convert(converter = DeepTokenConverter.class)
    @Column(name = "token")
    String token;

    protected Inner() {}

    Inner(String token) {
      this.token = token;
    }

    public String getToken() {
      return token;
    }
  }

  @jakarta.persistence.Converter
  public static class DeepTokenConverter extends ShreddedStringConverter {
    public DeepTokenConverter() {
      super("DeepVault", "token");
    }
  }
}
