package com.housedevinci.shredding.autoconfigure.columnid.caseonly;

import org.springframework.data.jpa.repository.JpaRepository;

/** Repository for {@link CaseOnlyNote}. */
public interface CaseOnlyNoteRepository extends JpaRepository<CaseOnlyNote, Long> {}
