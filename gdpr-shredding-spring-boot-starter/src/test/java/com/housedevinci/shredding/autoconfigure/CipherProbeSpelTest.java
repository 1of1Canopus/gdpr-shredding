package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ShreddingException;
import org.junit.jupiter.api.Test;

/**
 * The security review's probe: the subject expression is a field path, not a scripting hook
 * (control 14).
 */
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

  /**
   * L12: {@code #{#this}} and {@code #{#root}} are permitted by {@code
   * SimpleEvaluationContext.forReadOnlyDataBinding()} - it only restricts property navigation, not
   * which root object a bare reference resolves to - and both hand back the entity itself. {@code
   * String.valueOf(entity)} is then {@code Object}'s default {@code "ClassName@identityHashCode"}:
   * a different value for every instance and every JVM run. The row would be encrypted under a key
   * nobody could ever ask an erasure for again, silently.
   */
  @Test
  void probe_a_subject_expression_resolving_to_an_identity_hash_is_refused() {
    var thisRef = new SubjectExpression("Doc.x", "#{#this}");
    assertThatThrownBy(() -> thisRef.evaluate(new Doc())).isInstanceOf(ShreddingException.class);

    var rootRef = new SubjectExpression("Doc.x", "#{#root}");
    assertThatThrownBy(() -> rootRef.evaluate(new Doc())).isInstanceOf(ShreddingException.class);

    // Also refused: a resolved value of a permitted scalar type whose own toString() happens to
    // have the exact "ClassName@identityHashCode" shape.
    var identityShaped = new SubjectExpression("Doc.x", "#{identityShaped}");
    assertThatThrownBy(() -> identityShaped.evaluate(new IdentityShaped()))
        .isInstanceOf(ShreddingException.class);
  }

  public static class IdentityShaped {
    public CharSequence getIdentityShaped() {
      return "com.example.Widget@1a2b3c4d";
    }
  }
}
