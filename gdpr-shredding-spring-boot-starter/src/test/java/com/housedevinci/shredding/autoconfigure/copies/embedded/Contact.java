package com.housedevinci.shredding.autoconfigure.copies.embedded;

import com.housedevinci.shredding.api.BlindIndex;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

/** Audit-table coverage fixture, E11: a blind index inside an embeddable. */
@Embeddable
public class Contact {
  @BlindIndex(of = "email", subjectColumn = "owner_id", tenantColumn = "tenant_id")
  @Column(name = "phone_idx")
  byte[] phoneIndex;
}
