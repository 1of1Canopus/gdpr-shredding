package com.housedevinci.shredding.adapter.memory;

import com.housedevinci.shredding.application.KeyProvider;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.KeyState;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Data keys in a {@link java.util.Map}. For tests and for a local development run only: keys vanish
 * on restart, which is an erasure of every subject at once.
 *
 * <p>It refuses to start unless {@code shredding.dev-mode=true} (default {@code false}), and the
 * starter WARNs at every startup while that is on (control 1).
 */
public final class InMemoryKeyProvider implements KeyProvider {

  private static final Logger log = LoggerFactory.getLogger(InMemoryKeyProvider.class);

  private record Id(String tenant, String subject, int version) {}

  private final Map<Id, byte[]> keys = new ConcurrentHashMap<>();
  private final Map<Id, KeyState> states = new ConcurrentHashMap<>();
  private final Map<Id, AtomicLong> counts = new ConcurrentHashMap<>();
  private final Map<String, Integer> latest = new ConcurrentHashMap<>();
  private final RandomSource random;
  private final java.util.Set<String> erased = java.util.concurrent.ConcurrentHashMap.newKeySet();
  private volatile boolean available = true;

  /**
   * @param devMode must be {@code true}; the parameter exists so the refusal is impossible to skip
   */
  public InMemoryKeyProvider(RandomSource random, boolean devMode) {
    this.random = Objects.requireNonNull(random, "random");
    if (!devMode) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "InMemoryKeyProvider keeps data keys in the heap and loses them on restart. It refuses to"
              + " start unless shredding.dev-mode=true. Use JdbcKeyProvider, or a Pro KMS adapter,"
              + " for anything that holds real personal data.");
    }
    log.warn(
        "shredding: shredding.dev-mode=true, data keys are held in memory and are lost on restart."
            + " Never run this against real personal data.");
  }

  /** Simulates a key-store outage, for the probe that a KMS outage must not read as an erasure. */
  public void setAvailable(boolean available) {
    this.available = available;
  }

  @Override
  public Unwrapped currentForWrite(TenantId tenant, SubjectId subject) {
    requireAvailable();
    String subjectKey = subjectKey(tenant, subject);
    Integer version = latest.get(subjectKey);
    if (version == null) {
      return mint(tenant, subject, 1);
    }
    Id id = new Id(tenant.value(), subject.value(), version);
    KeyState state = states.getOrDefault(id, KeyState.DESTROYED);
    if (!state.usable()) {
      throw new ShreddingException(ErrorCodes.ERASED, "the data key for this subject is " + state);
    }
    return new Unwrapped(keys.get(id), version, state);
  }

  @Override
  public Optional<Unwrapped> forRead(TenantId tenant, SubjectId subject, int version) {
    requireAvailable();
    Id id = new Id(tenant.value(), subject.value(), version);
    byte[] material = keys.get(id);
    if (material == null) {
      return Optional.empty();
    }
    return Optional.of(
        new Unwrapped(material, version, states.getOrDefault(id, KeyState.DESTROYED)));
  }

  @Override
  public long recordEncryptions(TenantId tenant, SubjectId subject, int version, int count) {
    requireAvailable();
    return counts
        .computeIfAbsent(new Id(tenant.value(), subject.value(), version), k -> new AtomicLong())
        .addAndGet(count);
  }

  @Override
  public Unwrapped rotate(TenantId tenant, SubjectId subject) {
    requireAvailable();
    int next = latest.getOrDefault(subjectKey(tenant, subject), 0) + 1;
    return mint(tenant, subject, next);
  }

  @Override
  public boolean healthy() {
    return available;
  }

  /** Destroys every version for a subject, the way an erasure does. */
  public int destroy(TenantId tenant, SubjectId subject) {
    int destroyed = 0;
    for (Id id : Map.copyOf(keys).keySet()) {
      if (id.tenant().equals(tenant.value()) && id.subject().equals(subject.value())) {
        keys.remove(id);
        states.remove(id);
        counts.remove(id);
        destroyed++;
      }
    }
    latest.remove(subjectKey(tenant, subject));
    erased.add(subjectKey(tenant, subject));
    return destroyed;
  }

  /** Sets an existing subject's keys to DESTROYING, for the concurrent-write probe. */
  public void markDestroying(TenantId tenant, SubjectId subject) {
    states.replaceAll(
        (id, state) ->
            id.tenant().equals(tenant.value()) && id.subject().equals(subject.value())
                ? KeyState.DESTROYING
                : state);
  }

  /** Restores a previously exported key row, for the wrapped-key-resurrection probe. */
  public void restore(TenantId tenant, SubjectId subject, int version, byte[] material) {
    Id id = new Id(tenant.value(), subject.value(), version);
    keys.put(id, material.clone());
    states.put(id, KeyState.ACTIVE);
    latest.merge(subjectKey(tenant, subject), version, Math::max);
    erased.remove(subjectKey(tenant, subject));
  }

  public Optional<byte[]> export(TenantId tenant, SubjectId subject, int version) {
    return Optional.ofNullable(keys.get(new Id(tenant.value(), subject.value(), version)))
        .map(byte[]::clone);
  }

  private Unwrapped mint(TenantId tenant, SubjectId subject, int version) {
    if (erased.contains(subjectKey(tenant, subject))) {
      throw new ShreddingException(
          ErrorCodes.ERASED,
          "this data subject has been erased; a new data key is never minted for an erased subject");
    }
    byte[] material = random.dataKey();
    Id id = new Id(tenant.value(), subject.value(), version);
    keys.put(id, material);
    states.put(id, KeyState.ACTIVE);
    latest.put(subjectKey(tenant, subject), version);
    return new Unwrapped(material, version, KeyState.ACTIVE);
  }

  private void requireAvailable() {
    if (!available) {
      throw new com.housedevinci.shredding.domain.KeyUnavailableException(
          "the in-memory key store is marked unavailable");
    }
  }

  private static String subjectKey(TenantId tenant, SubjectId subject) {
    return tenant.value() + "|" + subject.value();
  }
}
