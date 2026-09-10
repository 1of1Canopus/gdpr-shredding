package com.housedevinci.shredding.autoconfigure.ninthpass.elements;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TaggedNoteRepository extends JpaRepository<TaggedNote, Long> {}
