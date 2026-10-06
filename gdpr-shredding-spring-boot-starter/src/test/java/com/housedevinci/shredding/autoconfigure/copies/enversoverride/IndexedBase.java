package com.housedevinci.shredding.autoconfigure.copies.enversoverride;

import com.housedevinci.shredding.api.BlindIndex;
import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;

/** Audit-table coverage fixture, E5: the blind index declared on a mapped superclass. */
@MappedSuperclass
public abstract class IndexedBase {
  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "email_idx")
  byte[] emailIndex;
}
