package com.housedevinci.shredding.autoconfigure.admission.single;

import jakarta.persistence.DiscriminatorColumn;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;
import jakarta.persistence.Table;

/** A SINGLE_TABLE root: the subclass's shredded columns live in this one table. */
@Entity
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "kind")
@Table(name = "b2_single", schema = "public")
public class B2SingleRoot {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;
}
