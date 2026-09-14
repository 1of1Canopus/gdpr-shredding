package com.housedevinci.shredding.autoconfigure.nested;

import org.springframework.data.jpa.repository.JpaRepository;

public interface DeepVaultRepository extends JpaRepository<DeepVault, Long> {}
