package dev.tunnel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/** Small persistent store for mappings created through the management API. */
final class DynamicStore {
  static final class Spec {
    final String name;
    final Settings.Rule.Kind kind;
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
    final Settings.Rule.HealthCheck healthCheck;

    Spec(
        String name,
        Settings.Rule.Kind kind,
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
        Settings.Rule.HealthCheck healthCheck) {
      Wire.validateName(name);
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

    String encode() {
      String health = "";
      if (healthCheck != null) {
        health =
            healthCheck.type
                + ","
                + healthCheck.timeoutSeconds
                + ","
                + healthCheck.maxFailed
                + ","
                + healthCheck.intervalSeconds;
      }
      String raw =
          String.join(
              "\u001f",
              name,
              kind.name(),
              String.valueOf(remotePort),
              localHost,
              String.valueOf(localPort),
              String.join("\u001e", hosts),
              String.join("\u001e", locations),
              hostRewrite,
              basicUser,
              basicPassword,
              balanceGroup,
              balanceKey,
              String.valueOf(bandwidthBytesPerSecond),
              health);
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }
  }

  static Map<String, Map<String, Spec>> load(String filename) throws IOException {
    if (filename == null || filename.trim().isEmpty()) return new LinkedHashMap<>();
    Properties properties = new Properties();
    Path path = Path.of(filename);
    if (Files.exists(path)) {
      try (InputStream input = Files.newInputStream(path)) {
        properties.load(input);
      }
    }
    Map<String, Map<String, Spec>> result = new LinkedHashMap<>();
    for (String key : properties.stringPropertyNames()) {
      int dot = key.indexOf('.');
      if (dot <= 0 || dot == key.length() - 1)
        throw new IllegalArgumentException("Invalid store key: " + key);
      String clientId = key.substring(0, dot);
      String name = key.substring(dot + 1);
      Wire.validateName(clientId);
      Wire.validateName(name);
      Map<String, Spec> client = result.computeIfAbsent(clientId, ignored -> new LinkedHashMap<>());
      client.put(name, decode(properties.getProperty(key)));
    }
    return result;
  }

  static synchronized void save(String filename, Map<String, Map<String, Spec>> values)
      throws IOException {
    if (filename == null || filename.trim().isEmpty()) return;
    Path path = Path.of(filename);
    Path parent = path.toAbsolutePath().getParent();
    if (parent != null) Files.createDirectories(parent);
    Properties properties = new Properties();
    for (Map.Entry<String, Map<String, Spec>> client : values.entrySet())
      for (Map.Entry<String, Spec> entry : client.getValue().entrySet())
        properties.setProperty(client.getKey() + "." + entry.getKey(), entry.getValue().encode());
    try (OutputStream output = Files.newOutputStream(path)) {
      properties.store(output, "tunnel dynamic mappings");
    }
  }

  static Spec decode(String encoded) {
    final String raw;
    try {
      raw = new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException error) {
      throw new IllegalArgumentException("Invalid dynamic mapping encoding", error);
    }
    String[] fields = raw.split("\u001f", -1);
    if (fields.length != 14)
      throw new IllegalArgumentException("Invalid dynamic mapping field count");
    Settings.Rule.Kind kind;
    try {
      kind = Settings.Rule.Kind.valueOf(fields[1]);
    } catch (IllegalArgumentException error) {
      throw new IllegalArgumentException("Invalid dynamic mapping kind", error);
    }
    List<String> hosts = split(fields[5], '\u001e');
    List<String> locations = split(fields[6], '\u001e');
    Settings.Rule.HealthCheck health = null;
    if (!fields[13].isEmpty()) {
      String[] parts = fields[13].split(",", -1);
      if (parts.length != 4) throw new IllegalArgumentException("Invalid dynamic health check");
      health =
          new Settings.Rule.HealthCheck(
              parts[0],
              Integer.parseInt(parts[1]),
              Integer.parseInt(parts[2]),
              Integer.parseInt(parts[3]));
    }
    return new Spec(
        fields[0],
        kind,
        Integer.parseInt(fields[2]),
        fields[3],
        Integer.parseInt(fields[4]),
        hosts,
        locations,
        fields[7],
        fields[8],
        fields[9],
        fields[10],
        fields[11],
        Integer.parseInt(fields[12]),
        health);
  }

  static Settings.Rule toRule(Spec spec) {
    return new Settings.Rule(
        spec.name,
        spec.kind,
        spec.remotePort,
        spec.localHost,
        spec.localPort,
        spec.hosts,
        spec.locations,
        spec.hostRewrite,
        spec.basicUser,
        spec.basicPassword,
        spec.balanceGroup,
        spec.balanceKey,
        spec.bandwidthBytesPerSecond,
        spec.healthCheck);
  }

  private static List<String> split(String value, char separator) {
    if (value.isEmpty()) return Collections.emptyList();
    List<String> result = new ArrayList<>();
    for (String item : value.split(java.util.regex.Pattern.quote(String.valueOf(separator))))
      if (!item.isEmpty()) result.add(item);
    return result;
  }

  private DynamicStore() {}
}
