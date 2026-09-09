package com.housedevinci.shredding.autoconfigure.embedcollection;

import org.springframework.data.jpa.repository.JpaRepository;

public interface VaultWithNotesRepository extends JpaRepository<VaultWithNotes, Long> {}
