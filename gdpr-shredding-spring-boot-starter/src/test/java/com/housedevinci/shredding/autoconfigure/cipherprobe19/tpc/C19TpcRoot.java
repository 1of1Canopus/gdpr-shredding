package com.housedevinci.shredding.autoconfigure.cipherprobe19.tpc;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;
import jakarta.persistence.Table;

/** A concrete TABLE_PER_CLASS root with a table of its own and no shredded field. */
@Entity
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
@Table(name = "c19_tpc_root", schema = "public")
public class C19TpcRoot {
  @Id Long id;

  String label;

  protected C19TpcRoot() {}

  protected C19TpcRoot(Long id) {
    this.id = id;
  }
}
