package com.housedevinci.shredding.autoconfigure.batch;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BatchParentRepository extends JpaRepository<BatchParent, Long> {
  List<BatchParent> findByOwnerId(String ownerId);
}
