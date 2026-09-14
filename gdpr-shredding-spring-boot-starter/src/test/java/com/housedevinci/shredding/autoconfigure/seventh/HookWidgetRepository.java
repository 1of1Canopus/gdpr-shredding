package com.housedevinci.shredding.autoconfigure.seventh;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface HookWidgetRepository extends JpaRepository<HookWidget, Long> {
  List<HookWidget> findByOwnerId(String ownerId);
}
