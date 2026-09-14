package com.housedevinci.shredding.autoconfigure.assoc;

import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/**
 * The fifth pass, C-36: an ordinary, non-shredded entity holding a reference to a shredded one.
 * {@code ShreddingEventListener.refuseLoad} evicts the refused {@code Widget} from the persistence
 * context, but eviction removes the session's own entry - it cannot reach into another managed
 * instance that already holds a Java reference to the same, fully decrypted object.
 */
@Entity
@Table(name = "holder")
public class Holder {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  String label;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "widget_id")
  Widget widget;

  protected Holder() {}

  public Holder(String label, Widget widget) {
    this.label = label;
    this.widget = widget;
  }

  public Long getId() {
    return id;
  }

  public String getLabel() {
    return label;
  }

  public Widget getWidget() {
    return widget;
  }
}
