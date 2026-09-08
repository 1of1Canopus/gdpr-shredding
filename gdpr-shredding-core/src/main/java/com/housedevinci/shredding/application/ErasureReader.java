package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.ErasureRecord;
import java.util.List;

/** Pages through the erasure trail in sequence order, for the verifier and for the DPO view. */
public interface ErasureReader {

  List<ErasureRecord> readAfter(long afterSequence, int limit);
}
