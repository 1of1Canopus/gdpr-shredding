package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.jpa.ShreddingContext;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.data.repository.Repository;
import org.springframework.util.ClassUtils;

/**
 * CIPHER-11: opens {@link ShreddingContext}'s read bracket around every Spring Data JPA repository
 * method call, so an ordinary {@code repository.findByX(...)} keeps working exactly as before -
 * {@code ShreddedConverter.convertToEntityAttribute} sees the bracket open and defers verification
 * to {@code ShreddingEventListener.onPostLoad}/{@code refuseIfSubjectMoved}, the same as today.
 *
 * <p>This is the mechanism that makes the entity-load path "the relaxation, not the mechanism"
 * (Cipher's fix text): Hibernate itself gives no hook earlier than the converter for any load, so
 * the bracket is opened one layer up, at the point the application actually asked for a read.
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
 */
public final class ShreddingReadBracketCustomizer implements BeanPostProcessor {

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

  private record Bracket(Object target) implements InvocationHandler {
    @Override
    public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args)
        throws Throwable {
      ShreddingContext.pushReadBracket();
      try {
        return method.invoke(target, args);
      } catch (InvocationTargetException e) {
        throw e.getCause() != null ? e.getCause() : e;
      } finally {
        ShreddingContext.popReadBracket();
      }
    }
  }
}
