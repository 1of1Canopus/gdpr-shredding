package com.housedevinci.shredding.autoconfigure.mapkey;

import org.springframework.data.jpa.repository.JpaRepository;

public interface KeyedNotesRepository extends JpaRepository<KeyedNotes, Long> {}
