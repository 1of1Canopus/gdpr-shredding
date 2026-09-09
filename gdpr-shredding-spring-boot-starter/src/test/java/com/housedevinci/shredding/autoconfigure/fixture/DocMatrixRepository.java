package com.housedevinci.shredding.autoconfigure.fixture;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.util.Streamable;

public interface DocMatrixRepository
    extends JpaRepository<Doc, Long>, JpaSpecificationExecutor<Doc> {

  Page<Doc> findPageByOwnerId(String ownerId, Pageable pageable);

  Slice<Doc> findSliceByOwnerId(String ownerId, Pageable pageable);

  Streamable<Doc> findStreamableByOwnerId(String ownerId);

  @Query(value = "select title from doc where owner_id = :id", nativeQuery = true)
  List<byte[]> rawTitles(@Param("id") String id);
}
