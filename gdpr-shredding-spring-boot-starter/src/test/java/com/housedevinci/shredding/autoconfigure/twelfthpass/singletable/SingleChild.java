package com.housedevinci.shredding.autoconfigure.twelfthpass.singletable;

import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;

/** The subclass: same table, same columns, a second entity name over all of them. */
@Entity
@DiscriminatorValue("child")
public class SingleChild extends SingleBase {

  @Column(name = "note")
  String note;

  protected SingleChild() {}

  public SingleChild(String ownerId, String tenantId, String email, String note) {
    super(ownerId, tenantId, email);
    this.note = note;
  }
}
