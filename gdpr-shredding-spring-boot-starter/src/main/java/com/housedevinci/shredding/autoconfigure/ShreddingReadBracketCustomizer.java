package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.ShreddingContext;
import jakarta.persistence.EntityManagerFactory;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.data.repository.Repository;
import org.springframework.util.ClassUtils;

/**
 * CIPHER-11: opens {@link ShreddingContext}'s read bracket around every Spring Data JPA repository
 * method call, so an ordinary {@code repository.findByX(...)} keeps working exactly as before -
 * {@code ShreddedConverter.convertToEntityAttribute} sees the bracket open and defers verification
 * to {@code ShreddingEventListener.onPostLoad}/{@code refuseIfSubjectMoved}, the same as today.
 *
 * <p>This is the mechanism that makes the entity-load path "the relaxation, not the mechanism" (the
 * security review's fix text): Hibernate itself gives no hook earlier than the converter for any
 * load, so the bracket is opened one layer up, at the point the application actually asked for a
 * read.
 *
 * <p>A {@code BeanPostProcessor} rather than a {@code RepositoryFactoryCustomizer}: the latter is
 * the documented Spring Data extension point for exactly this, but registering it as a plain
 * {@code @Bean} does not reliably reach every {@code @EnableJpaRepositories}-declared repository
 * factory in this Spring Boot generation - verified by a failing probe here before this class was
 * written this way, not assumed (see {@code QUESTIONS.md} #16). A {@code BeanPostProcessor}
 * wrapping every {@link Repository} bean in a decorating {@link Proxy} is the same idea one layer
 * further out, using a Spring SPI every bean in the context goes through unconditionally.
 *
 * <p>A read that reaches a shredded converter through neither a repository call nor an explicit
 * {@code ShreddingContext.withRead(...)}, most notably a bare JPQL projection run straight off an
 * {@code EntityManager}, has the bracket closed and is refused ({@code SHRED-READ-UNSCOPED}).
 *
 * <p><strong>Third pass (C-17/C-18/C-20/C-22).</strong> the security review's re-verification found
 * that the bracket as first written was an unconditional permission granted by the caller's
 * identity ("you are inside a repository call"), not a proof that a verifier would run: a
 * repository {@code @Query} projection, a Spring Data interface projection, and a repository bound
 * to a second, uninstrumented {@code EntityManagerFactory} all decrypted with the bracket open and
 * nothing ever draining the decode. {@link ShreddingContext#popReadBracket()} now owes a debt
 * rather than granting a permission - see its javadoc - and this class is what makes that debt
 * actually get checked before the repository method's result reaches its caller (below). The second
 * half of C-20 - a bracket cannot vouch for a session it does not know is instrumented - is closed
 * by {@link #afterSingletonsInstantiated()}: with more than one {@code EntityManagerFactory} bean
 * in the context, there is no reliable, version-independent way for this processor to tell which
 * factory an arbitrary repository bean is bound to (C-20), so every repository is refused at
 * startup rather than bracketed on the chance it belongs to the wrong one.
 */
public final class ShreddingReadBracketCustomizer
    implements BeanPostProcessor, Ordered, SmartInitializingSingleton {

  private final ObjectProvider<EntityManagerFactory> entityManagerFactories;

  public ShreddingReadBracketCustomizer(
      ObjectProvider<EntityManagerFactory> entityManagerFactories) {
    this.entityManagerFactories = entityManagerFactories;
  }

  /**
   * C-25: {@code LOWEST_PRECEDENCE} rather than an arbitrary number, to document that this
   * processor has no opinion about its order relative to any *other* {@code Repository}-wrapping
   * post-processor a user's own configuration might register - it only needs to run after the ones
   * Spring Boot itself registers by default (transactional proxying among them, which uses values
   * well below {@code LOWEST_PRECEDENCE}), so that the bracket observes the exact call the
   * application makes rather than one already rewritten by an earlier wrapper, and so that this
   * proxy is the innermost layer, closest to the real repository, with every other concern already
   * applied outside it.
   */
  @Override
  public int getOrder() {
    return Ordered.LOWEST_PRECEDENCE;
  }

  @Override
  public Object postProcessAfterInitialization(Object bean, String beanName) {
    if (!(bean instanceof Repository)) {
      return bean;
    }
    Class<?> beanClass = bean.getClass();
    Class<?>[] interfaces = ClassUtils.getAllInterfacesForClass(beanClass);
    if (interfaces.length == 0) {
      return bean;
    }
    return Proxy.newProxyInstance(beanClass.getClassLoader(), interfaces, new Bracket(bean));
  }

  /**
   * C-20, second half - defence in depth. Runs once, after every singleton in the context has been
   * created. Coarser than "only the repositories actually bound to the other factory" - it refuses
   * the whole application rather than resolving, bean by bean, which factory backs which repository
   * - and, per C-20, could not be exercised by its own dedicated integration test: a second {@code
   * EntityManagerFactory}-typed bean registered the ordinary Spring way trips Spring Boot's own
   * {@code @ConditionalOnMissingBean({LocalContainerEntityManagerFactoryBean.class,
   * EntityManagerFactory.class})} on {@code HibernateJpaConfiguration}, which suppresses the
   * auto-configured (and therefore instrumented) factory entirely rather than letting both coexist,
   * so the exact shape this check is written for cannot be constructed through ordinary
   * auto-configuration at all. The check is kept as a cheap, sound safety rail for whatever unusual
   * wiring does produce two factory beans; the actual attack C-20 demonstrated - a hand-built
   * {@code LocalContainerEntityManagerFactoryBean} used directly, entirely outside the Spring
   * context, the same shape a real multi-datasource application would reach for - is closed by the
   * read-bracket frame accounting above, independent of this check, and that is what {@code
   * CipherProbeMatrix2Test} verifies.
   */
  @Override
  public void afterSingletonsInstantiated() {
    List<EntityManagerFactory> factories = entityManagerFactories.orderedStream().toList();
    if (factories.size() > 1) {
      throw new ShreddingException(
          ErrorCodes.EMF_UNINSTRUMENTED,
          "this application declares "
              + factories.size()
              + " EntityManagerFactory beans. ShreddingReadBracketCustomizer brackets every Spring"
              + " Data JPA repository call so its converters can defer verification to"
              + " onPostLoad, but that relaxation is sound only for the one EntityManagerFactory"
              + " ShreddingIntegrator is registered against (the one Spring Boot auto-configures)."
              + " A repository bound to any other factory would be bracketed with no listener and"
              + " no startup scan behind it, and this processor has no reliable way to tell, for an"
              + " arbitrary repository bean, which factory backs it. Reduce this application to one"
              + " EntityManagerFactory, or keep every repository touching a @Shredded entity off"
              + " the additional one(s).");
    }
  }

  private record Bracket(Object target) implements InvocationHandler {
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if (method.getDeclaringClass() == Object.class) {
        // C-25: toString/equals/hashCode never reach a shredded converter. Bracketing them only
        // widened every repository bean's exposure to SHRED-READ-UNVERIFIED for no reason, and
        // wrapped identity-sensitive methods that callers (including Spring's own machinery) may
        // reasonably expect to behave like the target's own.
        return method.invoke(target, args);
      }
      // enterRegion, not openRegion: this is one of the module's two bracketed entries, and the
      // only kind of region that may serve a decode is one an entry opened (design addendum 2). A
      // region opened any other way - including by a user @PostLoad method or an @EntityListeners
      // bean calling openRegion() from inside this very call - carries no entry epoch and is
      // refused by every access.
      long token = ShreddingContext.enterRegion();
      Object result;
      try {
        result = method.invoke(target, args);
      } catch (InvocationTargetException e) {
        // The region still unwinds - a pooled thread must never carry a stale one into the next,
        // unrelated call - but an unverified decode is not the failure worth reporting here; the
        // exception the repository method itself threw is.
        ShreddingContext.discardRegion(token);
        throw e.getCause() != null ? e.getCause() : e;
      } catch (Throwable t) {
        ShreddingContext.discardRegion(token);
        throw t;
      }
      // C-17/C-18/C-20/C-22: verified before the value is handed back, not merely before this
      // method returns. closeRegion() throws SHRED-READ-UNVERIFIED here, replacing the normal
      // return below, whenever the call decrypted something no verifier ever installed. The token
      // is the region this invocation opened, so an inner region left behind by an Error cannot be
      // mistaken for it.
      ShreddingContext.closeRegion(token);
      return result;
    }
  }
}
