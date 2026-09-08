package com.housedevinci.shredding.autoconfigure.fixture;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GadgetRepository extends JpaRepository<Gadget, Long> {
  List<Gadget> findByOwnerId(String ownerId);
}
