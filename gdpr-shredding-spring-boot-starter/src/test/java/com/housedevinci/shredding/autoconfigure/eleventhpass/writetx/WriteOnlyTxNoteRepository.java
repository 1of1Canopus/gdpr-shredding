package com.housedevinci.shredding.autoconfigure.eleventhpass.writetx;

import org.springframework.data.jpa.repository.JpaRepository;

/** Repository for {@link WriteOnlyTxNote}. */
public interface WriteOnlyTxNoteRepository extends JpaRepository<WriteOnlyTxNote, Long> {}
