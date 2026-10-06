package com.housedevinci.shredding.adapter.jdbc;

/**
 * The statistics paths on PostgreSQL 17, whose default target is stored as {@code NULL}: NULL is
 * the default and is not 0 (design S-7).
 */
class PlannerStatisticsPg17Test extends PlannerStatisticsPostgresTest {
  PlannerStatisticsPg17Test() {
    super(
        "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24",
        "its statistics target is the default (NULL), so the next ANALYZE samples it");
  }
}
