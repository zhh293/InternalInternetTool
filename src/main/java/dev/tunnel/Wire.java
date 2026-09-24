package dev.tunnel;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;

final class Wire {
  static final int PROTOCOL_VERSION = 2;
  static final int WORK_HEADER_BYTES = 48;
  private static final SecureRandom RANDOM = new SecureRandom();

  static void validateName(String name) {
    if (!name.matches("[A-Za-z0-9_-]{1,48}")) {
      throw new IllegalArgumentException("Invalid name: " + name);
    }
  }

  static void send(Channel channel, String line) {
    channel.writeAndFlush(Unpooled.copiedBuffer(line + "\n", StandardCharsets.UTF_8));
  }

  static void sendError(Channel channel, String code, String detail) {
    String safeDetail = detail == null ? "" : detail.replaceAll("[\\r\\n ]+", "_");
    send(channel, "ERROR " + code + (safeDetail.isEmpty() ? "" : " " + safeDetail));
  }

  static String readLine(ByteBuf message) {
    return message.toString(StandardCharsets.UTF_8).trim();
  }

  static byte[] randomToken() {
    byte[] token = new byte[32];
    RANDOM.nextBytes(token);
    return token;
  }

  static String hex(byte[] bytes) {
    StringBuilder text = new StringBuilder(bytes.length * 2);
    for (byte value : bytes)
      text.append(Character.forDigit((value >>> 4) & 15, 16))
          .append(Character.forDigit(value & 15, 16));
    return text.toString();
  }

  static byte[] unhex(String text) {
    if (text.length() != 64) throw new IllegalArgumentException("Invalid token length");
    byte[] bytes = new byte[32];
    for (int i = 0; i < bytes.length; i++) {
      int high = Character.digit(text.charAt(i * 2), 16);
      int low = Character.digit(text.charAt(i * 2 + 1), 16);
      if (high < 0 || low < 0) throw new IllegalArgumentException("Invalid token hex");
      bytes[i] = (byte) ((high << 4) | low);
    }
    return bytes;
  }

  static ByteBuf workHeader(UUID id, byte[] token) {
    ByteBuf out = Unpooled.buffer(WORK_HEADER_BYTES);
    out.writeLong(id.getMostSignificantBits())
        .writeLong(id.getLeastSignificantBits())
        .writeBytes(token);
    return out;
  }

  private Wire() {}
}
