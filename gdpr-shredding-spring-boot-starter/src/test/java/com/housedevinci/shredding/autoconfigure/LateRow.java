package com.housedevinci.shredding.autoconfigure;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * A row committed for the subject after the erasure's {@code UPDATE} has taken its snapshot and
 * before the erasure's read-backs run, made without a trigger.
 *
 * <p>Earlier probes paused the erasure with a {@code pg_sleep} trigger on the table, or kept the
 * index with a {@code BEFORE UPDATE} trigger. Since audit-table coverage (0.2.0) admission refuses
 * any enabled trigger on a blind-indexed table with {@code SHRED-SCHEMA-010} before the first
 * statement, so those fixtures no longer reach the read-backs. A row lock does the pausing instead:
 * another session holds {@code FOR UPDATE} on the subject's rows, the erasure's {@code UPDATE}
 * waits on it, a late row commits, and the lock is released. The late row is outside the {@code
 * UPDATE}'s snapshot and visible to the read-backs that follow, which is the residue they exist
 * for, and no catalogue check can see it.
 */
final class LateRow {

  private LateRow() {}

  static <T> T during(
      String url,
      String user,
      String password,
      String lockRows,
      String insertLate,
      Supplier<T> erasure)
      throws Exception {
    try (Connection holder = DriverManager.getConnection(url, user, password)) {
      holder.setAutoCommit(false);
      try (Statement st = holder.createStatement()) {
        st.execute(lockRows);
      }
      CompletableFuture<T> running = CompletableFuture.supplyAsync(erasure);
      try {
        Thread.sleep(700);
        try (Connection late = DriverManager.getConnection(url, user, password);
            Statement st = late.createStatement()) {
          st.execute(insertLate);
        }
      } finally {
        holder.rollback();
      }
      return running.get(30, TimeUnit.SECONDS);
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }
}
