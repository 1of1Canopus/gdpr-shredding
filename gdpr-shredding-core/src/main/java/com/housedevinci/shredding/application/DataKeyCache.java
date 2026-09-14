package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.Aes256Gcm;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A bounded, short-lived cache of unwrapped data keys (control 7).
 *
 * <p>Bounded because an unbounded cache of key material is a heap dump waiting to happen; short
 * because an erasure on one node cannot reach into another node's memory. An erasure evicts locally
 * and publishes an invalidation, but a peer may still hold the key for up to the TTL - that window
 * is documented and it appears in the proof of erasure. It is not closed by this cache and it is
 * not pretended away.
 *
 * <p>Access-ordered LRU with an explicit expiry check on every read; entries are wiped on eviction.
 */
public final class DataKeyCache {

  public static final Duration DEFAULT_TTL = Duration.ofSeconds(60);
  public static final int DEFAULT_MAX_SIZE = 10_000;

  private record Entry(byte[] key, int version, Instant expiresAt) {}

  private final Duration ttl;
  private final int maxSize;
  private final Clock clock;
  private final Map<String, Entry> entries;

  public DataKeyCache(Duration ttl, int maxSize, Clock clock) {
    this.ttl = Objects.requireNonNull(ttl, "ttl");
    this.maxSize = maxSize;
    this.clock = Objects.requireNonNull(clock, "clock");
    if (ttl.isNegative() || ttl.toMillis() == 0) {
      throw new IllegalArgumentException("shredding.data-key-cache.ttl must be positive");
    }
    if (maxSize < 1) {
      throw new IllegalArgumentException("shredding.data-key-cache.max-size must be at least 1");
    }
    this.entries =
        new LinkedHashMap<>(16, 0.75f, true) {
          private static final long serialVersionUID = 1L;

          @Override
          protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {
            if (size() > DataKeyCache.this.maxSize) {
              Aes256Gcm.wipe(eldest.getValue().key());
              return true;
            }
            return false;
          }
        };
  }

  public synchronized Optional<byte[]> get(TenantId tenant, SubjectId subject, int version) {
    Entry e = entries.get(key(tenant, subject, version));
    if (e == null) {
      return Optional.empty();
    }
    if (!clock.instant().isBefore(e.expiresAt())) {
      evict(tenant, subject, version);
      return Optional.empty();
    }
    return Optional.of(e.key().clone());
  }

  public synchronized void put(TenantId tenant, SubjectId subject, int version, byte[] material) {
    entries.put(
        key(tenant, subject, version),
        new Entry(material.clone(), version, clock.instant().plus(ttl)));
  }

  public synchronized void evict(TenantId tenant, SubjectId subject, int version) {
    Entry removed = entries.remove(key(tenant, subject, version));
    if (removed != null) {
      Aes256Gcm.wipe(removed.key());
    }
  }

  /** Evicts every version for one subject; what an erasure calls locally. */
  public synchronized void evictSubject(TenantId tenant, SubjectId subject) {
    String prefix = key(tenant, subject, -1);
    prefix = prefix.substring(0, prefix.lastIndexOf('|') + 1);
    for (Iterator<Map.Entry<String, Entry>> it = entries.entrySet().iterator(); it.hasNext(); ) {
      Map.Entry<String, Entry> e = it.next();
      if (e.getKey().startsWith(prefix)) {
        Aes256Gcm.wipe(e.getValue().key());
        it.remove();
      }
    }
  }

  public synchronized int size() {
    return entries.size();
  }

  public Duration ttl() {
    return ttl;
  }

  private static String key(TenantId tenant, SubjectId subject, int version) {
    return tenant.value().length()
        + ":"
        + tenant.value()
        + "|"
        + subject.value().length()
        + ":"
        + subject.value()
        + "|"
        + version;
  }
}
