package com.housedevinci.shredding.autoconfigure.embed;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VaultRepository extends JpaRepository<Vault, Long> {
  List<Vault> findByOwnerId(String ownerId);
}
