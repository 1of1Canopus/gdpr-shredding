package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.application.FieldCipher;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * Publishes the runtime the converters read, and says out loud, at <em>every</em> startup, which
 * weaker modes are on. Not once, not on the first request: an operator who reads one boot log a
 * month must see it in that log.
 */
public final class ShreddingStartupCheck implements InitializingBean {

  private static final Logger log = LoggerFactory.getLogger(ShreddingStartupCheck.class);

  private final ShreddingProperties properties;
  private final FieldCipher cipher;
  private final ShreddedModel model;

  public ShreddingStartupCheck(
      ShreddingProperties properties, FieldCipher cipher, ShreddedModel model) {
    this.properties = properties;
    this.cipher = cipher;
    this.model = model;
  }

  @Override
  public void afterPropertiesSet() {
    ShreddingRuntime.set(new ShreddingRuntime(cipher, properties.getErasedValue().getPolicy()));

    if (properties.isDevMode()) {
      log.warn(
          "shredding: shredding.dev-mode=true. Data keys may be held in memory and lost on"
              + " restart, which erases every subject at once. Never in production.");
    }
    if (properties.isAllowSecondLevelCache()) {
      log.warn(
          "shredding: shredding.allow-second-level-cache=true. A cached @Shredded entity keeps"
              + " serving the decrypted value after the subject's key is destroyed, so an erasure"
              + " is invisible until the cache region is evicted.");
    }
    if (properties.getErasedValue().getPolicy() == ErasedValuePolicy.NULL) {
      log.warn(
          "shredding: shredding.erased-value.policy=null. An erased field is then indistinguishable"
              + " from one that was never filled in, and application code cannot tell the"
              + " difference. Prefer sentinel or exception.");
    }
    if (properties.getErasedValue().getPolicy() == ErasedValuePolicy.SENTINEL
        && !model.fieldsWithoutSentinel().isEmpty()) {
      // Dollar's ruling on QUESTIONS #5: no fake sentinel values, but nobody should discover this
      // from a null pointer at three in the morning.
      log.warn(
          "shredding: shredding.erased-value.policy=sentinel, but these field(s) have a type with"
              + " no value that can stand for \"erased\" and will read as null once their subject"
              + " is erased: {}. Set shredding.erased-value.policy=exception if the application"
              + " cannot tell an erased value from one that was never filled in.",
          String.join(", ", model.fieldsWithoutSentinel()));
    }
    if (properties.getErasureLog().isUnkeyed()) {
      log.warn(
          "shredding: shredding.erasure-log.unkeyed=true. The erasure log's integrity rests only on"
              + " database privilege separation.");
    }
    log.info(
        "shredding: {} shredded field(s) across {} entity type(s), {} blind-index column(s),"
            + " data-key cache ttl {}, backup retention {}",
        model.fieldCount(),
        model.entityCount(),
        model.blindIndexFields().size(),
        properties.getDataKeyCache().getTtl(),
        properties.getErasure().getBackupRetention());
  }
}
