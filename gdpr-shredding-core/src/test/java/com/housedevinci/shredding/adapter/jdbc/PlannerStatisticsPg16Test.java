package com.housedevinci.shredding.adapter.jdbc;

/** The statistics paths on PostgreSQL 16, whose default target is {@code -1}. */
class PlannerStatisticsPg16Test extends PlannerStatisticsPostgresTest {
  PlannerStatisticsPg16Test() {
    super(
        "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777",
        "its statistics target is -1 (the default), so the next ANALYZE samples it");
  }
}
