package com.housedevinci.shredding.autoconfigure.fixture;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BlobSeqRepository extends JpaRepository<BlobSeq, Long> {
  List<BlobSeq> findByOwnerId(String ownerId);
}
