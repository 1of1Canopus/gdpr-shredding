package com.housedevinci.shredding.autoconfigure.copies.nativesec;

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
    secondaryTableName = "nativesec_note",
    secondaryAuditTableName = "nativesec_trail")
@Table(name = "nativesec_view", schema = "public")
@SecondaryTable(
    name = "nativesec_note",
    schema = "public",
    pkJoinColumns = @PrimaryKeyJoinColumn(name = "id"))
public class SecView {
  @Id Long id;

  @Column(name = "email_idx", table = "nativesec_note")
  byte[] emailIndex;

  protected SecView() {}
}
