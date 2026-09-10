package com.housedevinci.shredding.autoconfigure.blindindexambient;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnedNoteRepository extends JpaRepository<OwnedNote, Long> {}
