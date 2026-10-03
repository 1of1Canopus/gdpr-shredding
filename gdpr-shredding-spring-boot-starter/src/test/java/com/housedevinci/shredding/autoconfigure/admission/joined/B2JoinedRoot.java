package com.housedevinci.shredding.autoconfigure.admission.joined;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;
import jakarta.persistence.Table;

/**
 * A JOINED root whose table names no schema (finding C-18-1's shape). No module statement addresses
 * it, so mapping admission does not check it.
 */
@Entity
@Inheritance(strategy = InheritanceType.JOINED)
@Table(name = "b2_joined_root")
public class B2JoinedRoot {

  @Id
  @GeneratedValue(strategy = GenerationType.SEQUENCE)
  Long id;

  String label;
}
