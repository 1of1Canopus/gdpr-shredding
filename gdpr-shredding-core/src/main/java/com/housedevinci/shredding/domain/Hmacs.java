package com.housedevinci.shredding.domain;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/** HMAC-SHA-256 over UTF-8 text, plus a constant-time comparison. */
public final class Hmacs {

  private Hmacs() {}

  public static byte[] hmacSha256(byte[] key, String message) {
    return Hkdf.mac(key, message.getBytes(StandardCharsets.UTF_8));
  }

  public static String hmacSha256Hex(byte[] key, String message) {
    return HexFormat.of().formatHex(hmacSha256(key, message));
  }

  /** Length-independent only in the sense that unequal lengths return early; use on MACs. */
  public static boolean constantTimeEquals(byte[] a, byte[] b) {
    return java.security.MessageDigest.isEqual(a, b);
  }
}
