package com.housedevinci.shredding.autoconfigure.matrix;

import java.util.List;
import java.util.stream.Stream;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MatrixLedgerRepository extends JpaRepository<MatrixLedger, Long> {
  List<MatrixLedger> findByOwnerId(String ownerId);

  /** Design §2 row 7: the region closes with the call, not with the stream. */
  Stream<MatrixLedger> streamByOwnerId(String ownerId);
}
