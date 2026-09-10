package com.housedevinci.shredding.autoconfigure.twotenant;

import org.springframework.data.jpa.repository.JpaRepository;

public interface DossierRepository extends JpaRepository<Dossier, Long> {}
