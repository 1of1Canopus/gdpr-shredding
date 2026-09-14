package com.housedevinci.shredding.domain;

import java.util.Objects;

/**
 * The result of one {@link com.housedevinci.shredding.application.PostErasureHook}, recorded in the
 * erasure record so a DPO can see exactly what is outstanding (control 19).
 *
 * @param hook the hook's name
 * @param succeeded whether it completed
 * @param detail a short, non-personal note; never an exception with a value in it
 */
public record HookOutcome(String hook, boolean succeeded, String detail) {

  public HookOutcome {
    Objects.requireNonNull(hook, "hook");
    detail = detail == null ? "" : detail;
  }

  public static HookOutcome ok(String hook) {
    return new HookOutcome(hook, true, "");
  }

  public static HookOutcome failed(String hook, String detail) {
    return new HookOutcome(hook, false, detail);
  }
}
