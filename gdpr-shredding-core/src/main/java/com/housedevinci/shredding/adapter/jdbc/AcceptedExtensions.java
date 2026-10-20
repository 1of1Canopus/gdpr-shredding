package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.application.LogText;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.util.ArrayList;
import java.util.List;

/**
 * The operator's list of third-party extensions whose native functions are trusted as shipped
 * (C-PR45-3, revision 4, rule R5b (ii), limit L20). Absent means empty, and empty is bound as
 * {@code '{}'}, never SQL NULL. Each entry is trimmed; a blank entry refuses. A name the pinned
 * manifest records refuses at verification ({@link PinnedCatalogue#refuseInstallableNames}).
 */
final class AcceptedExtensions {

  private AcceptedExtensions() {}

  static List<String> normalise(List<String> names) {
    if (names == null) {
      return List.of();
    }
    var out = new ArrayList<String>();
    for (int i = 0; i < names.size(); i++) {
      String name = names.get(i) == null ? "" : names.get(i).strip();
      if (name.isEmpty()) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            FunctionGrantMessages.PROPERTY
                + " entry "
                + i
                + " is blank. Every entry names one extension; remove the blank entry.");
      }
      out.add(name);
    }
    return List.copyOf(out);
  }

  /** The WARN printed at every verification while the list is not empty. */
  static String warning(List<String> accepted) {
    String names = LogText.escape(String.join(", ", accepted));
    return "shredding: third-party extensions "
        + names
        + " accepted as shipped ("
        + FunctionGrantMessages.PROPERTY
        + "): every native function of "
        + names
        + " is trusted as shipped, including one an admin re-creates or adds later (limit L20)."
        + " Native SECURITY DEFINER code and the code of withheld functions are still refused.";
  }
}
