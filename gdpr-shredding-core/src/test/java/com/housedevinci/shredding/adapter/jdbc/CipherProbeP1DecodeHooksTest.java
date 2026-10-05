package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.domain.HookOutcome;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * P-1 (Cipher delta review of the audit-table design, rev 2, 2026-10-05). An honest hook outcome
 * whose hook name holds a character outside the BMP is written in canonical form by
 * ErasureChain.hookMaterial (UTF-8 byte length) and read back by decodeHooks counting one UTF-16
 * char at a time, so the field boundary is lost and the row decodes as INVALID: the verifier then
 * reports an untampered chain BROKEN. Reachable today: PostErasureHook.name() is caller chosen.
 * Fails on b132f0b; passes once decodeHooks counts by code point.
 */
class CipherProbeP1DecodeHooksTest {

  private static String field(String v) {
    return "|" + v.getBytes(StandardCharsets.UTF_8).length + ":" + v;
  }

  @Test
  void probe_non_bmp_hook_name_breaks_the_chain() {
    String name = "scrub🔒";
    String material =
        field(name) + field("true") + field("") + field("b") + field("false") + field("x");

    List<HookOutcome> decoded = JdbcErasureStore.decodeHooks(material);

    assertThat(decoded)
        .containsExactly(new HookOutcome(name, true, ""), new HookOutcome("b", false, "x"));
  }
}
