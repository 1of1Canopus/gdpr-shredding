package com.housedevinci.shredding.autoconfigure.embed;

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
 * The fourth pass: a @Shredded field declared inside an @Embeddable component. The forward field
 * scan walks the entity class and its superclasses only; the reverse metamodel scan looks at
 * BasicValuedModelPart attributes of the entity persister only, and an @Embedded component is an
 * EmbeddableValuedModelPart. Neither sees `secrets.token`.
 */
@Entity
@Table(name = "vault")
public class Vault {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = VaultLabelConverter.class)
  @Column(name = "label")
  String label;

  @Embedded Secrets secrets;

  protected Vault() {}

  public Vault(String ownerId, String label, String token) {
    this.ownerId = ownerId;
    this.label = label;
    this.secrets = new Secrets(token);
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getLabel() {
    return label;
  }

  public Secrets getSecrets() {
    return secrets;
  }

  @Embeddable
  public static class Secrets {
    @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
    @Convert(converter = VaultTokenConverter.class)
    @Column(name = "token")
    String token;

    protected Secrets() {}

    Secrets(String token) {
      this.token = token;
    }

    public String getToken() {
      return token;
    }
  }

  @jakarta.persistence.Converter
  public static class VaultLabelConverter extends ShreddedStringConverter {
    public VaultLabelConverter() {
      super("Vault", "label");
    }
  }

  @jakarta.persistence.Converter
  public static class VaultTokenConverter extends ShreddedStringConverter {
    public VaultTokenConverter() {
      super("Vault", "token");
    }
  }
}
