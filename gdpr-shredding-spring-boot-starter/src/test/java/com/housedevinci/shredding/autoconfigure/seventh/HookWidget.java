package com.housedevinci.shredding.autoconfigure.seventh;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PostPersist;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;

/**
 * A shredded entity with an ordinary JPA {@code @PostPersist} callback. Hibernate invokes JPA
 * entity callbacks from {@code PostInsertEventListenerStandardImpl}, which is registered before
 * this module's own appended {@code POST_INSERT} listener - so the callback is a supported,
 * documented place from which an application touches the row after its {@code INSERT} has executed
 * and before this module reads it back. The probe uses it as the injection point for a corruption
 * that could equally come from a database trigger, a second application or a bug.
 */
@Entity
@Table(name = "hook_widget")
public class HookWidget {

  /** Set by the probe; run once, from the {@code @PostPersist} of the next insert. */
  public static volatile Runnable afterInsert = null;

  @Id
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "hook_widget_gen")
  @SequenceGenerator(
      name = "hook_widget_gen",
      sequenceName = "hook_widget_id_seq",
      allocationSize = 50)
  Long id;

  @Column(name = "owner_id", nullable = false)
  String ownerId;

  @Shredded(subject = "#{ownerId}", tenant = "#{'default'}")
  @Convert(converter = HookWidgetNameConverter.class)
  @Column(name = "name")
  String name;

  protected HookWidget() {}

  public HookWidget(String ownerId, String name) {
    this.ownerId = ownerId;
    this.name = name;
  }

  public Long getId() {
    return id;
  }

  public String getOwnerId() {
    return ownerId;
  }

  public String getName() {
    return name;
  }

  @PostPersist
  void postPersist() {
    Runnable hook = afterInsert;
    if (hook != null) {
      afterInsert = null;
      hook.run();
    }
  }

  @jakarta.persistence.Converter
  public static class HookWidgetNameConverter extends ShreddedStringConverter {
    public HookWidgetNameConverter() {
      super("HookWidget", "name");
    }
  }
}
