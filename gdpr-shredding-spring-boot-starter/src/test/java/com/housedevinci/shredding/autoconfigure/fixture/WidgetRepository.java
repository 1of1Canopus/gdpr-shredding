package com.housedevinci.shredding.autoconfigure.fixture;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WidgetRepository extends JpaRepository<Widget, Long> {
  List<Widget> findByOwnerId(String ownerId);
}
