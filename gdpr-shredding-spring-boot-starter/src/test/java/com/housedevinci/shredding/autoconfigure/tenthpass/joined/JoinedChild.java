package com.housedevinci.shredding.autoconfigure.tenthpass.joined;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/** The joined subclass: its own table, the root's @Shredded column on the root's table. */
@Entity
@Table(name = "joined_child")
public class JoinedChild extends JoinedBase {

  @Column(name = "note")
  String note;

  protected JoinedChild() {}

  public JoinedChild(String ownerId, String tenantId, String email, String note) {
    super(ownerId, tenantId, email);
    this.note = note;
  }
}
