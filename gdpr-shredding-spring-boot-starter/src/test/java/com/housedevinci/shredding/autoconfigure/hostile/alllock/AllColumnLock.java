package com.housedevinci.shredding.autoconfigure.hostile.alllock;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.OptimisticLockType;
import org.hibernate.annotations.OptimisticLocking;

/**
 * finding item 10 / D4: all-column optimistic locking. The UPDATE's {@code WHERE} clause is built
 * from the persistence context's loaded state, into which {@code onPostLoad} installs the verified
 * plaintext - so it would carry the plaintext against a column holding ciphertext, and no update
 * would ever match its row.
 */
@Entity
@Table(name = "hostile_all_lock")
@OptimisticLocking(type = OptimisticLockType.ALL)
@DynamicUpdate
public class AllColumnLock {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = SecretConverter.class)
  @Column(name = "secret")
  String secret;

  protected AllColumnLock() {}

  @jakarta.persistence.Converter
  public static class SecretConverter extends ShreddedStringConverter {
    public SecretConverter() {
      super("AllColumnLock", "secret");
    }
  }
}
