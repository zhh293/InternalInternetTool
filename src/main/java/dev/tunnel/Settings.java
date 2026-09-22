package dev.tunnel;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

final class Settings {
  static final class Rule {
    enum Kind {
      TCP,
      UDP,
      HTTP
    }

    final String name;
    final Kind kind;
    final int remotePort;
    final String localHost;
    final int localPort;
    final List<String> hosts;
    final List<String> locations;
    final String hostRewrite;
    final String basicUser;
    final String basicPassword;
    final String balanceGroup;
    final String balanceKey;
    final int bandwidthBytesPerSecond;
    final HealthCheck healthCheck;

    static final class HealthCheck {
      final String type;
      final int timeoutSeconds;
      final int maxFailed;
      final int intervalSeconds;

      HealthCheck(String type, int timeoutSeconds, int maxFailed, int intervalSeconds) {
        this.type = type;
        this.timeoutSeconds = timeoutSeconds;
        this.maxFailed = maxFailed;
        this.intervalSeconds = intervalSeconds;
      }
    }

    Rule(
        String name,
        Kind kind,
        int remotePort,
        String localHost,
        int localPort,
        List<String> hosts,
        List<String> locations,
        String hostRewrite,
        String basicUser,
        String basicPassword,
        String balanceGroup,
        String balanceKey,
        int bandwidthBytesPerSecond,
        HealthCheck healthCheck) {
      this.name = name;
      this.kind = kind;
      this.remotePort = remotePort;
      this.localHost = localHost;
      this.localPort = localPort;
      this.hosts = Collections.unmodifiableList(new ArrayList<>(hosts));
      this.locations = Collections.unmodifiableList(new ArrayList<>(locations));
      this.hostRewrite = hostRewrite;
      this.basicUser = basicUser;
      this.basicPassword = basicPassword;
      this.balanceGroup = balanceGroup;
      this.balanceKey = balanceKey;
      this.bandwidthBytesPerSecond = bandwidthBytesPerSecond;
      this.healthCheck = healthCheck;
    }
  }

  private final Properties values;

  private Settings(Properties values) {
    this.values = values;
  }

  static Settings load(String filename) throws IOException {
    Properties values = new Properties();
    try (InputStream input = Files.newInputStream(Path.of(filename))) {
      values.load(input);
    }
    return new Settings(values);
  }

  String required(String key) {
    String value = values.getProperty(key);
    if (value == null || value.trim().isEmpty()) {
      throw new IllegalArgumentException("Missing setting: " + key);
    }
    return value.trim();
  }

  String optional(String key, String fallback) {
    return values.getProperty(key, fallback).trim();
  }

  int port(String key) {
    return parsePort(required(key), key);
  }

  int optionalPort(String key, int fallback) {
    String value = values.getProperty(key);
    if (value == null || value.trim().isEmpty()) return fallback;
    int port = Integer.parseInt(value.trim());
    if (port < 0 || port > 65535)
      throw new IllegalArgumentException("Port out of range for " + key);
    return port;
  }

  int optionalPositive(String key, int fallback, int minimum, int maximum) {
    String value = values.getProperty(key);
    if (value == null || value.trim().isEmpty()) return fallback;
    try {
      int number = Integer.parseInt(value.trim());
      if (number < minimum || number > maximum)
        throw new IllegalArgumentException("Value out of range for " + key);
      return number;
    } catch (NumberFormatException error) {
      throw new IllegalArgumentException("Invalid value for " + key, error);
    }
  }

  static int parsePort(String text, String key) {
    int port;
    try {
      port = Integer.parseInt(text);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Invalid port for " + key, e);
    }
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("Port out of range for " + key);
    }
    return port;
  }

  String secret(String key) throws IOException {
    return readSecretFile(required(key));
  }

  static String readSecretFile(String filename) throws IOException {
    String secret = Files.readString(Path.of(filename), StandardCharsets.UTF_8).trim();
    validateSecret(secret);
    return secret;
  }

  private static void validateSecret(String secret) {
    if (secret.length() < 24
        || secret.length() > 256
        || secret.chars().anyMatch(Character::isWhitespace)) {
      throw new IllegalArgumentException("Secret must contain 24-256 non-space characters");
    }
  }

  static Map<String, byte[]> loadCredentials(String filename) throws IOException {
    Properties values = new Properties();
    try (InputStream input = Files.newInputStream(Path.of(filename))) {
      values.load(input);
    }
    Map<String, byte[]> result = new LinkedHashMap<>();
    for (String clientId : values.stringPropertyNames()) {
      Wire.validateName(clientId);
      String token = values.getProperty(clientId, "").trim();
      validateSecret(token);
      if (result.put(clientId, token.getBytes(StandardCharsets.UTF_8)) != null) {
        throw new IllegalArgumentException("Duplicate client credential: " + clientId);
      }
    }
    if (result.isEmpty())
      throw new IllegalArgumentException("At least one client credential is required");
    return Collections.unmodifiableMap(result);
  }

  Map<String, Rule> rules() {
    Map<String, Rule> result = new LinkedHashMap<>();
    for (String key : values.stringPropertyNames()) {
      if (!key.startsWith("map.") && !key.startsWith("udp.") && !key.startsWith("http.")) continue;
      String name = key.substring(key.indexOf('.') + 1);
      if (name.indexOf('.') >= 0) continue;
      Wire.validateName(name);
      if (result.containsKey(name))
        throw new IllegalArgumentException("Duplicate rule name: " + name);
      String value = required(key);
      String[] parts = value.split(",", -1);
      String prefix = key.substring(0, key.indexOf('.'));
      if ("http".equals(prefix)) {
        if (parts.length != 3 || parts[0].trim().isEmpty() || parts[1].trim().isEmpty()) {
          throw new IllegalArgumentException("Expected host|host,localHost,localPort for " + key);
        }
        List<String> hosts = new ArrayList<>();
        for (String host : parts[0].split("\\|")) {
          String normalized = normalizeHost(host);
          if (normalized.isEmpty())
            throw new IllegalArgumentException("Invalid HTTP host for " + key);
          hosts.add(normalized);
        }
        result.put(
            name,
            rule(name, Rule.Kind.HTTP, 0, parts[1].trim(), parsePort(parts[2].trim(), key), hosts));
      } else {
        if (parts.length != 3 || parts[1].trim().isEmpty()) {
          throw new IllegalArgumentException("Expected remotePort,localHost,localPort for " + key);
        }
        Rule.Kind kind = "udp".equals(prefix) ? Rule.Kind.UDP : Rule.Kind.TCP;
        result.put(
            name,
            rule(
                name,
                kind,
                parsePort(parts[0].trim(), key),
                parts[1].trim(),
                parsePort(parts[2].trim(), key),
                Collections.emptyList()));
      }
    }
    if (result.isEmpty())
      throw new IllegalArgumentException("At least one map.*, udp.* or http.* rule is required");
    return Collections.unmodifiableMap(result);
  }

  private Rule rule(
      String name,
      Rule.Kind kind,
      int remotePort,
      String localHost,
      int localPort,
      List<String> hosts) {
    List<String> locations =
        list(optional(kind == Rule.Kind.HTTP ? "http." + name + ".locations" : "", ""));
    String hostRewrite =
        optional(kind == Rule.Kind.HTTP ? "http." + name + ".hostRewrite" : "", "");
    String basicUser = optional(kind == Rule.Kind.HTTP ? "http." + name + ".basicUser" : "", "");
    String basicPassword =
        optional(kind == Rule.Kind.HTTP ? "http." + name + ".basicPassword" : "", "");
    String balance = optional("balance." + name, "");
    String balanceGroup = "";
    String balanceKey = "";
    if (!balance.isEmpty()) {
      String[] parts = balance.split(",", -1);
      if (parts.length != 2 || parts[0].trim().isEmpty() || parts[1].trim().isEmpty())
        throw new IllegalArgumentException("Expected balance group,key for " + name);
      balanceGroup = parts[0].trim();
      balanceKey = parts[1].trim();
    }
    int bandwidth = parseBandwidth(optional("bandwidth." + name, ""), "bandwidth." + name);
    Rule.HealthCheck health = parseHealth(optional("health." + name, ""), "health." + name);
    return new Rule(
        name,
        kind,
        remotePort,
        localHost,
        localPort,
        hosts,
        locations,
        hostRewrite,
        basicUser,
        basicPassword,
        balanceGroup,
        balanceKey,
        bandwidth,
        health);
  }

  private static List<String> list(String value) {
    if (value == null || value.trim().isEmpty()) return Collections.emptyList();
    List<String> result = new ArrayList<>();
    for (String item : value.split("\\|")) if (!item.trim().isEmpty()) result.add(item.trim());
    return result;
  }

  private static int parseBandwidth(String value, String key) {
    if (value == null || value.trim().isEmpty()) return 0;
    String text = value.trim().toUpperCase();
    long multiplier = 1;
    if (text.endsWith("KB")) {
      multiplier = 1024;
      text = text.substring(0, text.length() - 2);
    } else if (text.endsWith("MB")) {
      multiplier = 1024 * 1024;
      text = text.substring(0, text.length() - 2);
    }
    try {
      long result = Long.parseLong(text.trim()) * multiplier;
      if (result < 1 || result > Integer.MAX_VALUE)
        throw new IllegalArgumentException("Bandwidth out of range for " + key);
      return (int) result;
    } catch (NumberFormatException error) {
      throw new IllegalArgumentException("Invalid bandwidth for " + key, error);
    }
  }

  static int parseBandwidthSpec(String value, String key) {
    return parseBandwidth(value, key);
  }

  private static Rule.HealthCheck parseHealth(String value, String key) {
    if (value == null || value.trim().isEmpty()) return null;
    String[] parts = value.split(",", -1);
    if (parts.length != 4)
      throw new IllegalArgumentException("Expected type,timeout,maxFailed,interval for " + key);
    String type = parts[0].trim().toLowerCase();
    if (!"tcp".equals(type) && !"http".equals(type))
      throw new IllegalArgumentException("Health type must be tcp or http for " + key);
    int timeout = positive(parts[1], key);
    int maxFailed = positive(parts[2], key);
    int interval = positive(parts[3], key);
    return new Rule.HealthCheck(type, timeout, maxFailed, interval);
  }

  static Rule.HealthCheck parseHealthSpec(String value, String key) {
    if (value == null || value.isEmpty() || "-".equals(value)) return null;
    return parseHealth(value, key);
  }

  private static int positive(String value, String key) {
    try {
      int result = Integer.parseInt(value.trim());
      if (result < 1 || result > 3600)
        throw new IllegalArgumentException("Value out of range for " + key);
      return result;
    } catch (NumberFormatException error) {
      throw new IllegalArgumentException("Invalid value for " + key, error);
    }
  }

  static String normalizeHost(String host) {
    String value = host.trim().toLowerCase(java.util.Locale.ROOT);
    if (value.endsWith(".")) value = value.substring(0, value.length() - 1);
    if (!value.matches("[a-z0-9](?:[a-z0-9.-]{0,252}[a-z0-9])?")) {
      throw new IllegalArgumentException("Invalid host: " + host);
    }
    return value;
  }
}
