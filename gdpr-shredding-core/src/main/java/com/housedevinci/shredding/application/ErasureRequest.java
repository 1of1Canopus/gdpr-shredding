package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.Objects;

/**
 * One erasure request.
 *
 * @param tenant mandatory; there is no default tenant (control 15)
 * @param subject the data subject to erase
 * @param requestedBy the operator identity that asked, for the record
 * @param reason short free text, bounded, kept in the record
 */
public record ErasureRequest(
    TenantId tenant, SubjectId subject, String requestedBy, String reason) {

  public static final int MAX_TEXT = 1000;

  public ErasureRequest {
    Objects.requireNonNull(tenant, "tenant");
    Objects.requireNonNull(subject, "subject");
    requestedBy = bounded("requestedBy", requestedBy);
    reason = bounded("reason", reason);
  }

  private static String bounded(String what, String value) {
    String v = value == null ? "" : value;
    if (v.length() > MAX_TEXT) {
      throw new ShreddingException(
          ErrorCodes.INVALID, what + " is " + v.length() + " characters, max " + MAX_TEXT);
    }
    return v;
  }
}
