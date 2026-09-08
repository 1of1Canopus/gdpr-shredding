package com.housedevinci.shredding.jpa;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Objects;
import java.util.Optional;

/**
 * Who the row being written belongs to, for the few microseconds in which Hibernate binds it.
 *
 * <p>A Hibernate {@code AttributeConverter} is handed nothing but the value: no entity, no session,
 * no attribute name. The write path therefore brackets the binding: the module's {@code
 * PreInsertEventListener} and {@code PreUpdateEventListener} push the resolved tenant and subject
 * immediately before {@code EntityInsertAction} / {@code EntityUpdateAction} bind the state array,
 * and the matching {@code PostInsert} / {@code PostUpdate} listeners pop.
 *
 * <p>The read path needs none of this: tenant and subject travel inside the stored blob.
 *
 * <p>Missing context is a typed error, never a default. A converter reached from a bulk JPQL
 * update, a criteria parameter or a detached use has no idea whose key to encrypt under, and
 * guessing would put a row under the wrong subject's erasure scope.
 */
public final class ShreddingContext {

  /** Tenant and subject of the entity instance currently being bound. */
  public record Scope(TenantId tenant, SubjectId subject, String entityName) {
    public Scope {
      Objects.requireNonNull(tenant, "tenant");
      Objects.requireNonNull(subject, "subject");
      Objects.requireNonNull(entityName, "entityName");
    }
  }

  private static final ThreadLocal<Deque<Scope>> SCOPES = ThreadLocal.withInitial(ArrayDeque::new);

  private ShreddingContext() {}

  public static void push(Scope scope) {
    SCOPES.get().push(scope);
  }

  public static void pop() {
    Deque<Scope> stack = SCOPES.get();
    if (!stack.isEmpty()) {
      stack.pop();
    }
    if (stack.isEmpty()) {
      SCOPES.remove();
    }
  }

  public static Optional<Scope> current() {
    Deque<Scope> stack = SCOPES.get();
    return stack.isEmpty() ? Optional.empty() : Optional.of(stack.peek());
  }

  public static Scope require(String entity, String field) {
    return current()
        .orElseThrow(
            () ->
                new ShreddingException(
                    ErrorCodes.NO_CONTEXT,
                    "no shredding context while writing "
                        + entity
                        + "."
                        + field
                        + ". A @Shredded field can only be written through a managed entity, so"
                        + " that its data subject is known. Bulk JPQL updates, criteria parameters"
                        + " and detached writes to a shredded column are refused rather than"
                        + " encrypted under a guessed subject."));
  }

  /** Runs {@code body} with a scope pushed; for tests and for the erasure endpoint. */
  public static <T> T with(Scope scope, java.util.function.Supplier<T> body) {
    push(scope);
    try {
      return body.get();
    } finally {
      pop();
    }
  }
}
