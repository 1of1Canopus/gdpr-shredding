package com.housedevinci.shredding.autoconfigure.copies.nativesecexcl;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrimaryKeyJoinColumn;
import jakarta.persistence.SecondaryTable;
import jakarta.persistence.Table;

/** Audit-table coverage fixture, N5: the admitted table as another entity's secondary table. */
@Entity
@org.hibernate.annotations.Audited
@org.hibernate.annotations.Audited.SecondaryTable(
    secondaryTableName = "nativesecexcl_note",
    secondaryAuditTableName = "nativesecexcl_trail")
@Table(name = "nativesecexcl_view", schema = "public")
@SecondaryTable(
    name = "nativesecexcl_note",
    schema = "public",
    pkJoinColumns = @PrimaryKeyJoinColumn(name = "id"))
public class SecView {
  @Id Long id;

  @org.hibernate.annotations.Audited.Excluded
  @Column(name = "email_idx", table = "nativesecexcl_note")
  byte[] emailIndex;

  protected SecView() {}
}
