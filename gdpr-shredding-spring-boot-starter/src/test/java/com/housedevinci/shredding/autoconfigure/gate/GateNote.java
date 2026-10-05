package com.housedevinci.shredding.autoconfigure.gate;

import com.housedevinci.shredding.api.Shredded;
import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Converter;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** One ordinary shredded entity, so the gate's tests exercise a real mapping and a real write. */
@Entity
@Table(name = "gate_note")
public class GateNote {

  @Converter
  public static class BodyConverter extends ShreddedStringConverter {
    public BodyConverter() {
      super("GateNote", "body");
    }
  }

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "tenant_id", nullable = false)
  private String tenantId;

  @Column(name = "subject_id", nullable = false)
  private String subjectId;

  @Shredded(subject = "#{subjectId}")
  @Convert(converter = BodyConverter.class)
  @Column(name = "body")
  private String body;

  public Long getId() {
    return id;
  }

  public String getTenantId() {
    return tenantId;
  }

  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }

  public String getSubjectId() {
    return subjectId;
  }

  public void setSubjectId(String subjectId) {
    this.subjectId = subjectId;
  }

  public String getBody() {
    return body;
  }

  public void setBody(String body) {
    this.body = body;
  }
}
