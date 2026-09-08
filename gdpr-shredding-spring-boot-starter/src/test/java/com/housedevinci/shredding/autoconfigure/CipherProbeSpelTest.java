package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ShreddingException;
import org.junit.jupiter.api.Test;

/** Cipher probe: the subject expression is a field path, not a scripting hook (control 14). */
class CipherProbeSpelTest {

  public static class Owner {
    private final String id;

    public Owner(String id) {
      this.id = id;
    }

    public String getId() {
      return id;
    }
  }

  public static class Doc {
    private final Owner owner = new Owner("s-1");

    public Owner getOwner() {
      return owner;
    }

    public String wipeEverything() {
      return "pwned";
    }
  }

  /**
   * An entity is often built straight from request data, so its subject expression must not be able
   * to reach a bean, a static type or a method. {@code T(java.lang.Runtime)} in a subject
   * expression is remote code execution with extra steps.
   */
  @Test
  void probe_spel_expression_reaches_a_bean_or_a_static_type() {
    var typeRef = new SubjectExpression("Doc.x", "#{T(java.lang.System).getProperty('user.name')}");
    assertThatThrownBy(() -> typeRef.evaluate(new Doc()))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("Only property reads are permitted");

    var beanRef = new SubjectExpression("Doc.x", "#{@someBean.id}");
    assertThatThrownBy(() -> beanRef.evaluate(new Doc())).isInstanceOf(ShreddingException.class);

    var methodCall = new SubjectExpression("Doc.x", "#{wipeEverything()}");
    assertThatThrownBy(() -> methodCall.evaluate(new Doc())).isInstanceOf(ShreddingException.class);

    var constructor = new SubjectExpression("Doc.x", "#{new java.lang.String('x')}");
    assertThatThrownBy(() -> constructor.evaluate(new Doc()))
        .isInstanceOf(ShreddingException.class);
  }

  @Test
  void a_property_path_resolves() {
    assertThat(new SubjectExpression("Doc.x", "#{owner.id}").evaluate(new Doc())).isEqualTo("s-1");
  }

  @Test
  void an_unparseable_expression_fails_at_construction_not_at_the_first_write() {
    assertThatThrownBy(() -> new SubjectExpression("Doc.x", "#{owner."))
        .isInstanceOf(ShreddingException.class);
    assertThatThrownBy(() -> new SubjectExpression("Doc.x", "  "))
        .isInstanceOf(ShreddingException.class);
  }

  @Test
  void a_null_subject_is_refused_rather_than_encrypted_under_the_string_null() {
    var expression = new SubjectExpression("Doc.x", "#{owner.missing}");
    assertThatThrownBy(() -> expression.evaluate(new Doc())).isInstanceOf(ShreddingException.class);
  }
}
