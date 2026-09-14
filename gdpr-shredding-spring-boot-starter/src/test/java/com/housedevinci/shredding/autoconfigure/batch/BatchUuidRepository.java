package com.housedevinci.shredding.autoconfigure.batch;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BatchUuidRepository extends JpaRepository<BatchUuid, UUID> {
  List<BatchUuid> findByOwnerId(String ownerId);
}
