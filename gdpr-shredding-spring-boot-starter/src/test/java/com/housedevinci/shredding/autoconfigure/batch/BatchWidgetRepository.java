package com.housedevinci.shredding.autoconfigure.batch;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BatchWidgetRepository extends JpaRepository<BatchWidget, Long> {
  List<BatchWidget> findByOwnerId(String ownerId);
}
