package com.housedevinci.shredding.autoconfigure.batch;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BatchIdentityRepository extends JpaRepository<BatchIdentity, Long> {
  List<BatchIdentity> findByOwnerId(String ownerId);
}
