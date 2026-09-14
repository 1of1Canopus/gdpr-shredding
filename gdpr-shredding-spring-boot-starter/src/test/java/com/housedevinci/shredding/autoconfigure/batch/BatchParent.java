package com.housedevinci.shredding.autoconfigure.batch;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;

/**
 * The cascade and {@code @BatchSize} rows of the matrix: the children are shredded and are inserted
 * only because the parent is, so nothing in the application ever calls save on them.
 */
@Entity
@Table(name = "batch_parent")
public class BatchParent {

  @Id
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "batch_parent_gen")
  @SequenceGenerator(
      name = "batch_parent_gen",
      sequenceName = "batch_parent_id_seq",
      allocationSize = 50)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
  @jakarta.persistence.JoinColumn(name = "parent_id")
  @org.hibernate.annotations.BatchSize(size = 10)
  List<BatchChild> children = new ArrayList<>();

  protected BatchParent() {}

  public BatchParent(String ownerId) {
    this.ownerId = ownerId;
  }

  public Long getId() {
    return id;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public List<BatchChild> getChildren() {
    return children;
  }

  public BatchParent with(BatchChild child) {
    children.add(child);
    return this;
  }

  @Override
  public String toString() {
    return "BatchParent[" + ownerId + "]";
  }
}
