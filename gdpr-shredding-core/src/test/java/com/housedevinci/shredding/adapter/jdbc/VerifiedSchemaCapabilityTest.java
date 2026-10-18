package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

/**
 * C-PR-1, P11 and R1, R6: {@link VerifiedSchema} is a capability that only {@code
 * SchemaVerification} can mint, it always carries the pool it was verified on, and equality follows
 * that pool by identity. No database needed.
 */
class VerifiedSchemaCapabilityTest {

  private static final DatabaseIdentity ID =
      new DatabaseIdentity(7_000_000_000_000_000_001L, 16384, "app", 2200, "app_role", "app_role");
  private static final DatabaseIdentity OTHER_DATABASE =
      new DatabaseIdentity(
          7_000_000_000_000_000_001L, 16385, "other", 2200, "app_role", "app_role");

  @Test
  void verified_schema_has_no_public_constructor_or_factory() {
    for (Constructor<?> c : VerifiedSchema.class.getDeclaredConstructors()) {
      assertThat(Modifier.isPublic(c.getModifiers()) || Modifier.isProtected(c.getModifiers()))
          .describedAs("constructor %s", c)
          .isFalse();
    }
    List<Method> factories =
        Arrays.stream(VerifiedSchema.class.getDeclaredMethods())
            .filter(m -> Modifier.isStatic(m.getModifiers()))
            .filter(m -> m.getReturnType() == VerifiedSchema.class)
            .filter(
                m -> Modifier.isPublic(m.getModifiers()) || Modifier.isProtected(m.getModifiers()))
            .toList();
    assertThat(factories).describedAs("public or protected factories").isEmpty();
    assertThat(Modifier.isFinal(VerifiedSchema.class.getModifiers())).isTrue();
    assertThat(Serializable.class.isAssignableFrom(VerifiedSchema.class))
        .describedAs("a serialised capability could be replayed into another process")
        .isFalse();
    assertThat(Cloneable.class.isAssignableFrom(VerifiedSchema.class)).isFalse();
  }

  @Test
  void verified_schema_has_exactly_one_constructor_and_it_refuses_a_null_pool() throws Exception {
    Constructor<?>[] all = VerifiedSchema.class.getDeclaredConstructors();
    assertThat(all).hasSize(1);
    Constructor<?> only = all[0];
    assertThat(only.getParameterTypes())
        .containsExactly(String.class, DataSource.class, DatabaseIdentity.class);
    assertThat(Modifier.isPrivate(only.getModifiers())).isFalse();
    assertThat(Modifier.isPublic(only.getModifiers())).isFalse();

    assertThatThrownBy(() -> invoke(only, "public", null, ID))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("dataSource");
    assertThatThrownBy(() -> invoke(only, null, stub("x"), ID))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("name");
    assertThatThrownBy(() -> invoke(only, "public", stub("x"), null))
        .describedAs("C-PR-1b: no capability without the database identity it was verified on")
        .isInstanceOf(NullPointerException.class)
        .hasMessage("identity");
    assertThat(new VerifiedSchema("public", stub("x"), ID).name()).isEqualTo("public");
  }

  @Test
  void equals_compares_pool_identity_and_toString_is_the_name_only() {
    DataSource a = stub("jdbc:postgresql://db-a/app?user=secret-user");
    DataSource b = stub("jdbc:postgresql://db-a/app?user=secret-user");
    DataSource claimsEqual = stubEqualToEverything();

    var onA = new VerifiedSchema("public", a, ID);
    var onAagain = new VerifiedSchema("public", a, ID);
    var onB = new VerifiedSchema("public", b, ID);

    assertThat(onA).isEqualTo(onAagain).hasSameHashCodeAs(onAagain);
    assertThat(onA).isNotEqualTo(onB);
    assertThat(onA).isNotEqualTo(new VerifiedSchema("other", a, ID));
    assertThat(onA).isNotEqualTo(new VerifiedSchema("public", claimsEqual, ID));
    assertThat(new VerifiedSchema("public", claimsEqual, ID)).isNotEqualTo(onA);
    assertThat(onA)
        .describedAs("C-PR-1b: same pool, another database identity")
        .isNotEqualTo(new VerifiedSchema("public", a, OTHER_DATABASE));
    assertThat(onA.toString()).isEqualTo("public");
    assertThat(onA.toString()).doesNotContain("jdbc").doesNotContain("secret");
  }

  @Test
  void schema_verdict_equality_follows_the_pool() {
    DataSource a = stub("a");
    DataSource b = stub("b");
    var onA =
        new SchemaVerdict(new VerifiedSchema("public", a, ID), "app", "db", List.of(), List.of());
    var onAagain =
        new SchemaVerdict(new VerifiedSchema("public", a, ID), "app", "db", List.of(), List.of());
    var onB =
        new SchemaVerdict(new VerifiedSchema("public", b, ID), "app", "db", List.of(), List.of());

    assertThat(onA).isEqualTo(onAagain).hasSameHashCodeAs(onAagain);
    assertThat(onA)
        .describedAs("same name, role and database, two DataSource objects: not equal since 0.2.1")
        .isNotEqualTo(onB);
  }

  private static Object invoke(Constructor<?> c, Object... args) throws Throwable {
    try {
      return c.newInstance(args);
    } catch (InvocationTargetException e) {
      throw e.getCause();
    }
  }

  /** A DataSource that does nothing; its toString stands for a pool that prints its URL. */
  private static DataSource stub(String printed) {
    return (DataSource)
        Proxy.newProxyInstance(
            DataSource.class.getClassLoader(),
            new Class<?>[] {DataSource.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "toString" -> printed;
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> throw new UnsupportedOperationException(method.getName());
                });
  }

  private static DataSource stubEqualToEverything() {
    return (DataSource)
        Proxy.newProxyInstance(
            DataSource.class.getClassLoader(),
            new Class<?>[] {DataSource.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "toString" -> "claims-equal";
                  case "hashCode" -> 0;
                  case "equals" -> true;
                  default -> throw new UnsupportedOperationException(method.getName());
                });
  }
}
