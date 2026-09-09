package com.housedevinci.shredding.autoconfigure.fixture;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BlobRepository extends JpaRepository<Blob, Long> {
  List<Blob> findByOwnerId(String ownerId);
}
