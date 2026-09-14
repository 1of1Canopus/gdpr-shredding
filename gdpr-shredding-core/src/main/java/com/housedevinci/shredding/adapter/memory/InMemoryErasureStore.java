package com.housedevinci.shredding.adapter.memory;

import com.housedevinci.shredding.application.ErasureReader;
import com.housedevinci.shredding.application.ErasureStore;
import com.housedevinci.shredding.domain.ErasureAnchor;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;

/**
 * An erasure store in memory, for unit tests. The transactional guarantee the JDBC store provides
 * is simulated by doing both halves inside one synchronized block.
 */
public final class InMemoryErasureStore implements ErasureStore, ErasureReader, ErasureAnchor {

  private final List<ErasureRecord> records = new ArrayList<>();
  private final ErasureChain chain;
  private final BiFunction<TenantId, SubjectId, int[]> destroyer;
  private String head = ErasureChain.GENESIS;
  private Boolean keyed;
  private boolean anchorPresent;

  /**
   * @param destroyer performs the key destruction and returns {@code {keysDestroyed,
   *     blindIndexColumnsCleared}}
   */
  public InMemoryErasureStore(
      ErasureChain chain, BiFunction<TenantId, SubjectId, int[]> destroyer) {
    this.chain = Objects.requireNonNull(chain, "chain");
    this.destroyer = Objects.requireNonNull(destroyer, "destroyer");
  }

  @Override
  public synchronized Outcome erase(TenantId tenant, SubjectId subject, RecordFactory factory) {
    int[] result = destroyer.apply(tenant, subject);
    if (result[0] == 0) {
      return new Outcome(true, 0, 0, null);
    }
    return new Outcome(
        false, result[0], result[1], appendLocked(factory.create(result[0], result[1])));
  }

  @Override
  public synchronized ErasureRecord append(ErasureRecord record) {
    return appendLocked(record);
  }

  private ErasureRecord appendLocked(ErasureRecord record) {
    ErasureRecord linked = chain.link(record, head).withSequence(records.size() + 1L);
    records.add(linked);
    head = linked.hash();
    if (keyed == null) {
      keyed = chain.isKeyed();
    }
    anchorPresent = true;
    return linked;
  }

  @Override
  public synchronized List<ErasureRecord> readAfter(long afterSequence, int limit) {
    return records.stream().filter(r -> r.sequence() > afterSequence).limit(limit).toList();
  }

  @Override
  public synchronized Optional<ErasureRecord> latestForSubject(
      TenantId tenant, String subjectPseudonym) {
    ErasureRecord latest = null;
    for (ErasureRecord r : records) {
      if (r.tenant().equals(tenant) && r.subjectPseudonym().equals(subjectPseudonym)) {
        if (latest == null || r.timestamp().isAfter(latest.timestamp())) {
          latest = r;
        }
      }
    }
    return Optional.ofNullable(latest);
  }

  @Override
  public synchronized Optional<Anchor> anchor() {
    return anchorPresent && keyed != null
        ? Optional.of(new Anchor(head, records.size(), keyed))
        : Optional.empty();
  }

  /** Simulates an anchor row lost to a restore or removed by a privileged attacker. */
  public synchronized void dropAnchor() {
    anchorPresent = false;
  }

  /** Replaces one stored record, the way a table-owning attacker would. */
  public synchronized void replace(int index, ErasureRecord record) {
    records.set(index, record);
  }

  public synchronized List<ErasureRecord> all() {
    return List.copyOf(records);
  }
}
