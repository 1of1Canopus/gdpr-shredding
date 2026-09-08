package com.housedevinci.shredding.domain;

/**
 * What the application sees when it reads a field whose key has been destroyed (control 13).
 *
 * <p>One policy per application: not per read, not per call. A per-call choice is a per-call
 * mistake.
 */
public enum ErasedValuePolicy {
  /** The default: {@link ErasedValue#MARKER}. The rest of the application keeps working. */
  SENTINEL,
  /** A typed {@link KeyDestroyedException}. For applications that would rather fail loudly. */
  EXCEPTION,
  /**
   * {@code null}. A silent-failure mode: the application cannot tell an erased field from one that
   * was never filled in. Requires the property to be set explicitly and WARNs at every startup.
   */
  NULL
}
