package com.housedevinci.shredding.autoconfigure.assoc;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface HolderRepository extends JpaRepository<Holder, Long> {
  List<Holder> findByLabel(String label);
}
