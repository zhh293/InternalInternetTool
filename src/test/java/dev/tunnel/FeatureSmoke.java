package dev.tunnel;

import io.netty.handler.ssl.util.SelfSignedCertificate;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** End-to-end check for UDP, HTTP Host routing and the management API. */
public final class FeatureSmoke {
  public static void main(String[] args) throws Exception {
    if (args.length > 1 || (args.length == 1 && !"--limits".equals(args[0])))
      throw new IllegalArgumentException("Usage: FeatureSmoke [--limits]");
    Path temp = Files.createTempDirectory("tunnel-feature-smoke-");
    SelfSignedCertificate certificate = new SelfSignedCertificate("localhost");
    AtomicBoolean running = new AtomicBoolean(true);
    AtomicInteger unhealthyRequests = new AtomicInteger();
    try (DatagramSocket udpEcho = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
        ServerSocket httpEcho = new ServerSocket(0, 20, InetAddress.getByName("127.0.0.1"));
        ServerSocket unhealthyHttp = new ServerSocket(0, 20, InetAddress.getByName("127.0.0.1"))) {
      Set<Integer> used = new HashSet<>();
      used.add(udpEcho.getLocalPort());
      used.add(httpEcho.getLocalPort());
      used.add(unhealthyHttp.getLocalPort());
      int control = freePort(used),
          work = freePort(used),
          udpPublic = freePort(used),
          httpPublic = freePort(used),
          management = freePort(used),
          httpsPublic = freePort(used);
      Path token = temp.resolve("token");
      Files.writeString(token, "feature-testing-token-0123456789", StandardCharsets.UTF_8);
      Path clientsFile = temp.resolve("clients.properties");
      String clientToken = "feature-client-token-0123456789";
      Files.writeString(clientsFile, "feature-client=" + clientToken, StandardCharsets.UTF_8);
      Path clientTokenFile = temp.resolve("feature-client.token");
      Files.writeString(clientTokenFile, clientToken, StandardCharsets.UTF_8);
      Path managementTokenFile = temp.resolve("management.token");
      String managementToken = "feature-management-token-0123456789";
      Files.writeString(managementTokenFile, managementToken, StandardCharsets.UTF_8);
      Path serverConfig = temp.resolve("server.properties"),
          clientConfig = temp.resolve("client.properties");
      Properties server = new Properties();
      server.setProperty("bindHost", "127.0.0.1");
      server.setProperty("controlPort", String.valueOf(control));
      server.setProperty("workPort", String.valueOf(work));
      server.setProperty("publicBindHost", "127.0.0.1");
      server.setProperty("allowedPortStart", String.valueOf(udpPublic));
      server.setProperty("allowedPortEnd", String.valueOf(udpPublic));
      server.setProperty("httpPort", String.valueOf(httpPublic));
      server.setProperty("httpBindHost", "127.0.0.1");
      server.setProperty("managementPort", String.valueOf(management));
      server.setProperty("managementBindHost", "127.0.0.1");
      server.setProperty("muxPoolSize", "2");
      server.setProperty("httpsPort", String.valueOf(httpsPublic));
      server.setProperty("storeFile", temp.resolve("mappings.properties").toString());
      server.setProperty("clientsFile", clientsFile.toString());
      server.setProperty("managementTokenFile", managementTokenFile.toString());
      server.setProperty("certFile", certificate.certificate().getAbsolutePath());
      server.setProperty("keyFile", certificate.privateKey().getAbsolutePath());
      try (OutputStream output = Files.newOutputStream(serverConfig)) {
        server.store(output, "feature smoke");
      }
      Properties client = new Properties();
      client.setProperty("serverHost", "localhost");
      client.setProperty("controlPort", String.valueOf(control));
      client.setProperty("workPort", String.valueOf(work));
      client.setProperty("clientId", "feature-client");
      client.setProperty("clientTokenFile", clientTokenFile.toString());
      client.setProperty("caFile", certificate.certificate().getAbsolutePath());
      client.setProperty("muxPoolSize", "2");
      client.setProperty("http.web.locations", "/health");
      client.setProperty("health.web", "http,1,2,2");
      client.setProperty("udp.echo", udpPublic + ",127.0.0.1," + udpEcho.getLocalPort());
      client.setProperty("http.web", "feature.test,127.0.0.1," + httpEcho.getLocalPort());
      try (OutputStream output = Files.newOutputStream(clientConfig)) {
        client.store(output, "feature smoke");
      }
      Thread udpThread = new Thread(() -> udpEchoLoop(udpEcho, running), "udp-echo");
      udpThread.setDaemon(true);
      udpThread.start();
      Thread httpThread = new Thread(() -> httpEchoLoop(httpEcho, running), "http-echo");
      httpThread.setDaemon(true);
      httpThread.start();
      Thread unhealthyThread =
          new Thread(
              () -> httpUnavailableLoop(unhealthyHttp, running, unhealthyRequests),
              "http-unhealthy");
      unhealthyThread.setDaemon(true);
      unhealthyThread.start();
      try (Server tunnel = new Server(serverConfig.toString());
          Client agent = new Client(clientConfig.toString())) {
        tunnel.start();
        agent.start();
        waitForStatus(management, "feature-client", managementToken);
        waitForHealthy(management, managementToken);
        udpRoundTrip(udpPublic, new byte[] {0, 1, 2, -1, 10});
        httpRoundTrip(httpPublic);
        httpBodyRoundTrip(httpPublic);
        httpsRoundTrip(httpsPublic);
        String status = get("http://127.0.0.1:" + management + "/api/status", managementToken);
        if (!status.contains("feature-client")
            || !status.contains("UDP")
            || !status.contains("HTTP")
            || !status.contains("\"muxes\":2")
            || !status.contains("\"healthy\":true"))
          throw new AssertionError("Management status missing feature mappings: " + status);
        postForm(
            "http://127.0.0.1:" + management + "/api/clients/feature-client/bindings",
            managementToken,
            "name=dynamic&kind=HTTP&remotePort=1&localHost=127.0.0.1&localPort="
                + httpEcho.getLocalPort()
                + "&hosts=dynamic.test&locations=/health");
        waitForStatus(management, "feature-client", managementToken, "dynamic");
        httpRoundTrip(httpPublic, "dynamic.test");
        Properties saved = new Properties();
        try (InputStream input = Files.newInputStream(temp.resolve("mappings.properties"))) {
          saved.load(input);
        }
        if (!saved.containsKey("feature-client.dynamic"))
          throw new AssertionError("Dynamic mapping was not persisted");
        delete(
            "http://127.0.0.1:" + management + "/api/clients/feature-client/bindings/dynamic",
            managementToken);
        saved.clear();
        try (InputStream input = Files.newInputStream(temp.resolve("mappings.properties"))) {
          saved.load(input);
        }
        if (saved.containsKey("feature-client.dynamic"))
          throw new AssertionError("Deleted dynamic mapping remains persisted");
        postForm(
            "http://127.0.0.1:" + management + "/api/clients/feature-client/bindings",
            managementToken,
            "name=unhealthy&kind=HTTP&remotePort=1&localHost=127.0.0.1&localPort="
                + unhealthyHttp.getLocalPort()
                + "&hosts=unhealthy.test&health=http,1,1,1");
        waitForUnhealthy(management, managementToken, unhealthyRequests);
        delete(
            "http://127.0.0.1:" + management + "/api/clients/feature-client/bindings/unhealthy",
            managementToken);
        oversizedFormRejected(management, managementToken);
        try {
          get("http://127.0.0.1:" + management + "/api/status");
          throw new AssertionError("Management API accepted an unauthenticated request");
        } catch (java.io.IOException expected) {
          // Expected HTTP 401.
        }
        String metrics = get("http://127.0.0.1:" + management + "/metrics", managementToken);
        if (!metrics.contains("tunnel_clients") || !metrics.contains("tunnel_auth_failures_total"))
          throw new AssertionError("Prometheus metrics missing: " + metrics);
        if (args.length == 1) {
          httpHeaderBoundary(httpPublic);
          httpHeaderTimeout(httpPublic);
          dynamicStoreRollback(tunnel, management, managementToken, httpEcho.getLocalPort(), temp);
          udpStreamLimit(tunnel, udpPublic);
          System.out.println("FEATURE_LIMITS_OK: HTTP header limits, dynamic rollback and 512 UDP streams");
        }
        System.out.println("FEATURE_SMOKE_OK: mux UDP, HTTP Host route and management API");
        running.set(false);
      }
    } finally {
      running.set(false);
      certificate.delete();
      Files.deleteIfExists(temp.resolve("server.properties"));
      Files.deleteIfExists(temp.resolve("client.properties"));
      Files.deleteIfExists(temp.resolve("token"));
      Files.deleteIfExists(temp.resolve("clients.properties"));
      Files.deleteIfExists(temp.resolve("feature-client.token"));
      Files.deleteIfExists(temp.resolve("management.token"));
      Files.deleteIfExists(temp.resolve("mappings.properties"));
      Files.deleteIfExists(temp);
    }
  }

  private static int freePort(Set<Integer> used) throws Exception {
    for (int i = 0; i < 30; i++)
      try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
        if (used.add(socket.getLocalPort())) return socket.getLocalPort();
      }
    throw new IllegalStateException("No free port");
  }

  private static void udpEchoLoop(DatagramSocket socket, AtomicBoolean running) {
    byte[] buffer = new byte[65535];
    while (running.get())
      try {
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        socket.send(
            new DatagramPacket(
                packet.getData(), packet.getLength(), packet.getAddress(), packet.getPort()));
      } catch (Exception ignored) {
        // Health checks may connect and close before sending a request.
      }
  }

  private static void httpEchoLoop(ServerSocket server, AtomicBoolean running) {
    while (running.get())
      try (Socket socket = server.accept()) {
        socket.setSoTimeout(5000);
        InputStream input = socket.getInputStream();
        ByteArrayOutputStream request = new ByteArrayOutputStream();
        int a = -1, b;
        while (request.size() < 65536 && (b = input.read()) >= 0) {
          request.write(b);
          if (a == '\r'
              && b == '\n'
              && request.toString(StandardCharsets.ISO_8859_1).endsWith("\r\n\r\n")) break;
          a = b;
        }
        String header = request.toString(StandardCharsets.ISO_8859_1);
        byte[] body = "feature-ok".getBytes(StandardCharsets.UTF_8);
        if (header.startsWith("POST /health ")) {
          int length = 0;
          for (String line : header.split("\\r\\n"))
            if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:"))
              length = Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
          body = input.readNBytes(length);
          if (body.length != length) throw new AssertionError("Incomplete POST body");
        }
        OutputStream output = socket.getOutputStream();
        output.write(
            ("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        output.write(body);
        output.flush();
      } catch (Exception ignored) {
        // The echo endpoint is shutting down or a health check closed early.
      }
  }

  private static void httpUnavailableLoop(
      ServerSocket server, AtomicBoolean running, AtomicInteger requests) {
    while (running.get())
      try (Socket socket = server.accept()) {
        socket.setSoTimeout(2000);
        if (socket.getInputStream().read() < 0) continue;
        requests.incrementAndGet();
        socket.getOutputStream().write(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .getBytes(StandardCharsets.ISO_8859_1));
      } catch (Exception ignored) {
        // The endpoint is shutting down or a TCP-only probe disconnected.
      }
  }

  private static void waitForUnhealthy(int management, String token, AtomicInteger requests)
      throws Exception {
    for (int i = 0; i < 80 && requests.get() == 0; i++) Thread.sleep(100);
    if (requests.get() == 0) throw new AssertionError("HTTP health check did not send a request");
    Thread.sleep(250);
    String status = get("http://127.0.0.1:" + management + "/api/status", token);
    int binding = status.indexOf("\"name\":\"unhealthy\"");
    if (binding < 0 || !status.substring(binding).startsWith(
        "\"name\":\"unhealthy\",\"kind\":\"HTTP\",\"port\":0,\"ready\":true,\"healthy\":false"))
      throw new AssertionError("HTTP 503 endpoint was marked healthy: " + status);
  }

  private static void oversizedFormRejected(int management, String token) throws Exception {
    HttpURLConnection connection =
        (HttpURLConnection)
            new URL("http://127.0.0.1:" + management + "/api/clients/feature-client/bindings")
                .openConnection();
    connection.setDoOutput(true);
    connection.setRequestMethod("POST");
    connection.setRequestProperty("Authorization", "Bearer " + token);
    connection.getOutputStream().write(("padding=" + "x".repeat(65536)).getBytes(StandardCharsets.UTF_8));
    int status = connection.getResponseCode();
    connection.disconnect();
    if (status != 413) throw new AssertionError("Oversized management form returned " + status);
  }

  private static void waitForStatus(int management, String client, String token) throws Exception {
    waitForStatus(management, client, token, null);
  }

  private static void waitForStatus(int management, String client, String token, String mapping)
      throws Exception {
    for (int i = 0; i < 80; i++) {
      try {
        String status = get("http://127.0.0.1:" + management + "/api/status", token);
        if (status.contains(client)
            && status.contains("\"UDP\"")
            && status.contains("\"HTTP\"")
            && status.contains("\"ready\":true")
            && (mapping == null || status.contains(mapping))) return;
      } catch (Exception ignored) {
      }
      Thread.sleep(100);
    }
    throw new AssertionError("Client mappings did not register");
  }

  private static void waitForHealthy(int management, String token) throws Exception {
    for (int i = 0; i < 80; i++) {
      String status = get("http://127.0.0.1:" + management + "/api/status", token);
      if (status.contains("\"kind\":\"HTTP\",\"port\":0,\"ready\":true,\"healthy\":true")) return;
      Thread.sleep(100);
    }
    throw new AssertionError("HTTP mapping health check did not pass");
  }

  private static void udpRoundTrip(int port, byte[] expected) throws Exception {
    try (DatagramSocket socket = new DatagramSocket()) {
      socket.setSoTimeout(5000);
      socket.send(
          new DatagramPacket(expected, expected.length, InetAddress.getByName("127.0.0.1"), port));
      byte[] result = new byte[64];
      DatagramPacket response = new DatagramPacket(result, result.length);
      socket.receive(response);
      if (response.getLength() != expected.length) throw new AssertionError("UDP length mismatch");
      for (int i = 0; i < expected.length; i++)
        if (result[i] != expected[i]) throw new AssertionError("UDP payload mismatch");
    }
  }

  private static void httpRoundTrip(int port) throws Exception {
    httpRoundTrip(port, "feature.test");
  }

  private static void httpRoundTrip(int port, String host) throws Exception {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(5000);
      socket
          .getOutputStream()
          .write(
              ("GET /health HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
                  .getBytes(StandardCharsets.ISO_8859_1));
      socket.getOutputStream().flush();
      ByteArrayOutputStream received = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      while (received.size() < 65536) {
        int count = socket.getInputStream().read(buffer);
        if (count < 0) break;
        received.write(buffer, 0, count);
        String response = received.toString(StandardCharsets.UTF_8);
        if (response.contains("200 OK") && response.contains("feature-ok")) return;
      }
      throw new AssertionError("HTTP route failed: " + received.toString(StandardCharsets.UTF_8));
    }
  }

  private static void httpBodyRoundTrip(int port) throws Exception {
    byte[] body = new byte[96 * 1024];
    for (int i = 0; i < body.length; i++) body[i] = (byte) (i * 31);
    byte[] marker = "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    System.arraycopy(marker, 0, body, 10, marker.length);
    System.arraycopy(marker, 0, body, 70000, marker.length);
    byte[] header =
        ("POST /health HTTP/1.1\r\nHost: feature.test\r\nContent-Length: "
                + body.length
                + "\r\nX-Forwarded-For: 203.0.113.1\r\nConnection: close\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1);
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(10000);
      OutputStream output = socket.getOutputStream();
      output.write(header);
      output.write(body);
      output.flush();
      InputStream input = socket.getInputStream();
      ByteArrayOutputStream responseHead = new ByteArrayOutputStream();
      while (responseHead.size() < 8192 && findHeaderEnd(responseHead.toByteArray()) < 0) {
        int next = input.read();
        if (next < 0) break;
        responseHead.write(next);
      }
      byte[] response = responseHead.toByteArray();
      int bodyStart = findHeaderEnd(response);
      if (bodyStart < 0
          || !new String(response, 0, bodyStart, StandardCharsets.ISO_8859_1).contains("200 OK"))
        throw new AssertionError("POST response missing success status");
      byte[] echoed = input.readNBytes(body.length);
      if (!java.util.Arrays.equals(body, echoed))
        throw new AssertionError("HTTP request body changed during proxying");
    }
  }

  private static int findHeaderEnd(byte[] response) {
    for (int i = 0; i + 3 < response.length; i++)
      if (response[i] == '\r'
          && response[i + 1] == '\n'
          && response[i + 2] == '\r'
          && response[i + 3] == '\n') return i;
    return -1;
  }

  private static void httpHeaderBoundary(int port) throws Exception {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(5000);
      socket.getOutputStream().write(
          ("GET /health HTTP/1.1\r\nHost: feature.test\r\nX-Pad: " + "x".repeat(65536))
              .getBytes(StandardCharsets.ISO_8859_1));
      socket.getOutputStream().flush();
      String response =
          new String(socket.getInputStream().readNBytes(128), StandardCharsets.ISO_8859_1);
      if (!response.startsWith("HTTP/1.1 431"))
        throw new AssertionError("Oversized HTTP header returned: " + response);
    }
  }

  private static void httpHeaderTimeout(int port) throws Exception {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(20000);
      socket.getOutputStream().write(
          "GET /health HTTP/1.1\r\nHost: feature.test\r\n"
              .getBytes(StandardCharsets.ISO_8859_1));
      socket.getOutputStream().flush();
      String response =
          new String(socket.getInputStream().readNBytes(64), StandardCharsets.ISO_8859_1);
      if (!response.startsWith("HTTP/1.1 408"))
        throw new AssertionError("Incomplete HTTP header returned: " + response);
    }
  }

  private static void dynamicStoreRollback(
      Server tunnel, int management, String token, int localPort, Path temp) throws Exception {
    Path store = temp.resolve("mappings.properties");
    Path backup = temp.resolve("mappings.backup");
    Files.move(store, backup);
    Files.createDirectory(store);
    Files.writeString(store.resolve("blocker"), "keep directory nonempty");
    try {
      HttpURLConnection connection =
          (HttpURLConnection)
              new URL("http://127.0.0.1:" + management + "/api/clients/feature-client/bindings")
                  .openConnection();
      connection.setDoOutput(true);
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Authorization", "Bearer " + token);
      String form =
          "name=rollback&kind=HTTP&remotePort=1&localHost=127.0.0.1&localPort="
              + localPort
              + "&hosts=rollback.test";
      connection.getOutputStream().write(form.getBytes(StandardCharsets.UTF_8));
      int status = connection.getResponseCode();
      connection.disconnect();
      if (status != 500) throw new AssertionError("Store failure returned " + status);
      if (tunnel.dynamicBindingsJson("feature-client").contains("\"name\":\"rollback\""))
        throw new AssertionError("Failed dynamic mapping was committed in memory");
    } finally {
      Files.deleteIfExists(store.resolve("blocker"));
      Files.deleteIfExists(store);
      Files.move(backup, store);
    }
  }

  private static void udpStreamLimit(Server tunnel, int port) throws Exception {
    List<DatagramSocket> sockets = new ArrayList<>();
    try {
      int attempts = 0;
      while (udpActiveStreams(tunnel.statusJson()) < 512 && attempts++ < 540) {
        DatagramSocket socket = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
        sockets.add(socket);
        socket.setSoTimeout(3000);
        byte[] payload = {(byte) attempts};
        socket.send(
            new DatagramPacket(payload, payload.length, InetAddress.getByName("127.0.0.1"), port));
        byte[] echoed = new byte[1];
        DatagramPacket response = new DatagramPacket(echoed, echoed.length);
        socket.receive(response);
        if (response.getLength() != 1 || echoed[0] != payload[0])
          throw new AssertionError("UDP response changed while filling stream limit");
      }
      if (udpActiveStreams(tunnel.statusJson()) != 512)
        throw new AssertionError("UDP stream limit could not be reached");
      for (int i = 0; i < 16; i++) {
        DatagramSocket socket = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
        sockets.add(socket);
        byte[] payload = {(byte) i};
        socket.send(
            new DatagramPacket(payload, payload.length, InetAddress.getByName("127.0.0.1"), port));
      }
      Thread.sleep(250);
      if (udpActiveStreams(tunnel.statusJson()) != 512)
        throw new AssertionError("UDP stream count exceeded 512");
    } finally {
      for (DatagramSocket socket : sockets) socket.close();
    }
  }

  private static int udpActiveStreams(String status) {
    int binding = status.indexOf("\"name\":\"echo\"");
    if (binding < 0) throw new AssertionError("UDP binding missing: " + status);
    int field = status.indexOf("\"streams\":", binding);
    int start = field + "\"streams\":".length();
    int end = start;
    while (end < status.length() && Character.isDigit(status.charAt(end))) end++;
    return Integer.parseInt(status.substring(start, end));
  }

  private static void httpsRoundTrip(int port) throws Exception {
    TrustManager[] trustAll =
        new TrustManager[] {
          new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
              return new java.security.cert.X509Certificate[0];
            }

            public void checkClientTrusted(
                java.security.cert.X509Certificate[] chain, String authType) {}

            public void checkServerTrusted(
                java.security.cert.X509Certificate[] chain, String authType) {}
          }
        };
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, trustAll, new java.security.SecureRandom());
    try (SSLSocket socket =
        (SSLSocket) context.getSocketFactory().createSocket("127.0.0.1", port)) {
      socket.setSoTimeout(5000);
      SSLParameters parameters = socket.getSSLParameters();
      parameters.setServerNames(
          java.util.Collections.singletonList(new SNIHostName("feature.test")));
      socket.setSSLParameters(parameters);
      socket.startHandshake();
      socket
          .getOutputStream()
          .write(
              "GET /health HTTP/1.1\r\nHost: feature.test\r\nConnection: close\r\n\r\n"
                  .getBytes(StandardCharsets.ISO_8859_1));
      socket.getOutputStream().flush();
      ByteArrayOutputStream received = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      while (received.size() < 65536) {
        int count = socket.getInputStream().read(buffer);
        if (count < 0) break;
        received.write(buffer, 0, count);
        String response = received.toString(StandardCharsets.UTF_8);
        if (response.contains("200 OK") && response.contains("feature-ok")) return;
      }
      String response = received.toString(StandardCharsets.UTF_8);
      if (!response.contains("200 OK") || !response.contains("feature-ok"))
        throw new AssertionError("HTTPS route failed: " + response);
    }
  }

  private static String get(String url) throws Exception {
    return get(url, null);
  }

  private static String get(String url, String token) throws Exception {
    HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
    connection.setConnectTimeout(1000);
    connection.setReadTimeout(1000);
    if (token != null) connection.setRequestProperty("Authorization", "Bearer " + token);
    try (InputStream input = connection.getInputStream()) {
      return new String(input.readAllBytes(), StandardCharsets.UTF_8);
    } finally {
      connection.disconnect();
    }
  }

  private static void postForm(String url, String token, String form) throws Exception {
    HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
    connection.setDoOutput(true);
    connection.setRequestMethod("POST");
    connection.setRequestProperty("Authorization", "Bearer " + token);
    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    connection.getOutputStream().write(form.getBytes(StandardCharsets.UTF_8));
    if (connection.getResponseCode() >= 300) throw new AssertionError("Dynamic add failed");
    connection.disconnect();
  }

  private static void delete(String url, String token) throws Exception {
    HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
    connection.setRequestMethod("DELETE");
    connection.setRequestProperty("Authorization", "Bearer " + token);
    if (connection.getResponseCode() >= 300) throw new AssertionError("Dynamic delete failed");
    connection.disconnect();
  }
}
