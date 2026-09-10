package com.housedevinci.shredding.autoconfigure.twelfthpass.singletable;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SingleChildRepository extends JpaRepository<SingleChild, Long> {}
