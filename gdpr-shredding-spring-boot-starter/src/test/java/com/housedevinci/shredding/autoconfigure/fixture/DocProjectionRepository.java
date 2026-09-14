package com.housedevinci.shredding.autoconfigure.fixture;

import java.util.List;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** The third pass: the same projections CIPHER-11 refuses, declared on a repository instead. */
public interface DocProjectionRepository extends Repository<Doc, Long> {

  @Query("select d.title from Doc d where d.ownerId = :id")
  List<String> titlesOf(@Param("id") String id);

  @Query("select d from Doc d where d.ownerId in :ids order by d.ownerId asc")
  List<Doc> byOwnersOrdered(@Param("ids") List<String> ids);

  @Query("select d from Doc d where d.ownerId = :id")
  java.util.stream.Stream<Doc> streamByOwner(@Param("id") String id);

  List<TitleView> findByOwnerId(String id);

  /** A Spring Data interface projection over a shredded column. */
  interface TitleView {
    String getTitle();
  }
}
