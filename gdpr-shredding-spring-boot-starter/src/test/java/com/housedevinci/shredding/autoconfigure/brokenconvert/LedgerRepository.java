package com.housedevinci.shredding.autoconfigure.brokenconvert;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LedgerRepository extends JpaRepository<Ledger, Long> {
  List<Ledger> findByOwnerId(String ownerId);
}
