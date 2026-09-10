package com.housedevinci.shredding.autoconfigure.columnid.assocsubject;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** The far side of the association {@link AssocSubjectNote}'s subjectColumn names. */
@Entity
@Table(name = "assoc_subject_owner")
public class SubjectOwner {

  @Id
  @Column(name = "id")
  String id;

  protected SubjectOwner() {}

  public SubjectOwner(String id) {
    this.id = id;
  }

  public String getId() {
    return id;
  }
}
