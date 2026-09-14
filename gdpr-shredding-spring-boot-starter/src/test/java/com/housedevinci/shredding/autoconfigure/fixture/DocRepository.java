package com.housedevinci.shredding.autoconfigure.fixture;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DocRepository extends JpaRepository<Doc, Long> {
  List<Doc> findByOwnerId(String ownerId);
}
