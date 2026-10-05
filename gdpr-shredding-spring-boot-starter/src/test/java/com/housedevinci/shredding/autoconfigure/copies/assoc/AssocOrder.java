package com.housedevinci.shredding.autoconfigure.copies.assoc;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/** Audit-table coverage fixture, F2: a reference by the blind-index value, no database key. */
@Entity
@Table(name = "assoc_order", schema = "public")
public class AssocOrder {
  @Id Long id;

  @ManyToOne
  @JoinColumn(
      name = "customer_email_idx",
      referencedColumnName = "email_idx",
      foreignKey =
          @jakarta.persistence.ForeignKey(jakarta.persistence.ConstraintMode.NO_CONSTRAINT))
  AssocNote customer;

  protected AssocOrder() {}
}
