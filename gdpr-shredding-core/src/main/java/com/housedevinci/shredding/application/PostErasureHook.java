package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;

/**
 * Work that has to happen outside the database once a key is destroyed: anonymise a search index,
 * purge a cache, tell a downstream system.
 *
 * <p>Hooks run <em>after</em> the key destruction commits, so they cannot be part of its
 * transaction and they need retry state of their own. A hook that throws makes the erasure {@link
 * com.housedevinci.shredding.domain.ErasureOutcome#PARTIAL}, never {@code COMPLETE} (control 19),
 * and the proof of erasure refuses to render "complete" while one is outstanding.
 *
 * <p>A hook must be idempotent: a retried erasure runs it again.
 */
public interface PostErasureHook {

  /** A short, stable name. It goes into the erasure record, so it must contain no personal data. */
  String name();

  void afterErasure(TenantId tenant, SubjectId subject);
}
