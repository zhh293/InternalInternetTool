package dev.tunnel;

import io.netty.handler.ssl.util.SelfSignedCertificate;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
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
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** End-to-end check for UDP, HTTP Host routing and the management API. */
public final class FeatureSmoke {
  private static final int UDP_PERF_MAGIC = 0x54554E4C;

  public static void main(String[] args) throws Exception {
    if (args.length > 1
        || (args.length == 1
            && !"--limits".equals(args[0])
            && !"--udp-perf".equals(args[0])))
      throw new IllegalArgumentException("Usage: FeatureSmoke [--limits|--udp-perf]");
    if (args.length == 1 && "--udp-perf".equals(args[0]))
      System.setProperty(
          "tunnel.test.collectUdpPerfStats",
          String.valueOf(
              Boolean.parseBoolean(
                  System.getProperty("tunnel.test.detailedUdpPerfStats", "true"))));
    Path temp = Files.createTempDirectory("tunnel-feature-smoke-");
    SelfSignedCertificate certificate = new SelfSignedCertificate("localhost");
    AtomicBoolean running = new AtomicBoolean(true);
    AtomicInteger unhealthyRequests = new AtomicInteger();
    AtomicInteger udpEchoReceived = new AtomicInteger();
    try (DatagramSocket udpEcho = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
        ServerSocket httpEcho = new ServerSocket(0, 20, InetAddress.getByName("127.0.0.1"));
        ServerSocket unhealthyHttp = new ServerSocket(0, 20, InetAddress.getByName("127.0.0.1"))) {
      udpEcho.setReceiveBufferSize(16 * 1024 * 1024);
      udpEcho.setSendBufferSize(16 * 1024 * 1024);
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
      String flushMode = System.getProperty("tunnel.test.flushMode", "latency");
      int udpMuxPoolSize = Integer.getInteger("tunnel.test.udpMuxPoolSize", 1);
      server.setProperty("flushMode", flushMode);
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
      server.setProperty("udpMuxPoolSize", String.valueOf(udpMuxPoolSize));
      String udpMuxStriping = System.getProperty("tunnel.test.udpMuxStriping", "false");
      server.setProperty("udpMuxStriping", udpMuxStriping);
      String udpMuxWriteHighWaterMarkBytes =
          System.getProperty("tunnel.test.udpMuxWriteHighWaterMarkBytes");
      String serverUdpMuxWriteHighWaterMarkBytes =
          System.getProperty(
              "tunnel.test.serverUdpMuxWriteHighWaterMarkBytes",
              udpMuxWriteHighWaterMarkBytes);
      if (args.length == 1
          && "--udp-perf".equals(args[0])
          && serverUdpMuxWriteHighWaterMarkBytes != null)
        server.setProperty(
            "udpMuxWriteBufferHighWaterMarkBytes", serverUdpMuxWriteHighWaterMarkBytes);
      server.setProperty("httpsPort", String.valueOf(httpsPublic));
      server.setProperty("storeFile", temp.resolve("mappings.properties").toString());
      server.setProperty("clientsFile", clientsFile.toString());
      server.setProperty("managementTokenFile", managementTokenFile.toString());
      String udpSocketBufferBytes = System.getProperty("tunnel.test.udpSocketBufferBytes");
      if (args.length == 1
          && "--udp-perf".equals(args[0])
          && udpSocketBufferBytes != null) server.setProperty("udpSocketBufferBytes", udpSocketBufferBytes);
      server.setProperty("certFile", certificate.certificate().getAbsolutePath());
      server.setProperty("keyFile", certificate.privateKey().getAbsolutePath());
      try (OutputStream output = Files.newOutputStream(serverConfig)) {
        server.store(output, "feature smoke");
      }
      Properties client = new Properties();
      client.setProperty("flushMode", flushMode);
      client.setProperty("serverHost", "localhost");
      client.setProperty("controlPort", String.valueOf(control));
      client.setProperty("workPort", String.valueOf(work));
      client.setProperty("clientId", "feature-client");
      client.setProperty("clientTokenFile", clientTokenFile.toString());
      client.setProperty("caFile", certificate.certificate().getAbsolutePath());
      if (args.length == 1
          && "--udp-perf".equals(args[0])
          && udpSocketBufferBytes != null) client.setProperty("udpSocketBufferBytes", udpSocketBufferBytes);
      if (args.length == 1
          && "--udp-perf".equals(args[0])
          && System.getProperty("tunnel.test.clientUdpMuxWriteHighWaterMarkBytes", udpMuxWriteHighWaterMarkBytes) != null)
        client.setProperty(
            "udpMuxWriteBufferHighWaterMarkBytes",
            System.getProperty(
                "tunnel.test.clientUdpMuxWriteHighWaterMarkBytes", udpMuxWriteHighWaterMarkBytes));
      client.setProperty("muxPoolSize", "2");
      client.setProperty("udpMuxPoolSize", String.valueOf(udpMuxPoolSize));
      client.setProperty("udpMuxStriping", udpMuxStriping);
      client.setProperty("http.web.locations", "/health");
      client.setProperty("health.web", "http,1,2,2");
      client.setProperty("udp.echo", udpPublic + ",127.0.0.1," + udpEcho.getLocalPort());
      client.setProperty("http.web", "feature.test,127.0.0.1," + httpEcho.getLocalPort());
      try (OutputStream output = Files.newOutputStream(clientConfig)) {
        client.store(output, "feature smoke");
      }
      Thread udpThread =
          new Thread(() -> udpEchoLoop(udpEcho, running, udpEchoReceived), "udp-echo");
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
        byte[] largeDatagram = new byte[65507];
        for (int i = 0; i < largeDatagram.length; i++) largeDatagram[i] = (byte) (i * 31);
        udpRoundTrip(udpPublic, largeDatagram);
        udpMixedDatagrams(udpPublic);
        if (args.length == 1 && "--udp-perf".equals(args[0]))
          udpBurst(udpPublic, udpEchoReceived, management, managementToken, agent);
        httpRoundTrip(httpPublic);
        httpBodyRoundTrip(httpPublic);
        httpBodyRoundTrip(httpPublic, true);
        httpsRoundTrip(httpsPublic);
        String status = get("http://127.0.0.1:" + management + "/api/status", managementToken);
        if (!status.contains("feature-client")
            || !status.contains("UDP")
            || !status.contains("HTTP")
            || !status.contains("\"muxes\":" + (2 + udpMuxPoolSize))
            || !status.contains("\"tcpMuxes\":2")
            || !status.contains("\"udpMuxes\":" + udpMuxPoolSize)
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
        if (args.length == 1 && "--limits".equals(args[0])) {
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
    for (int i = 0; i < 1000; i++)
      try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
        int candidate = socket.getLocalPort();
        try (DatagramSocket udp =
            new DatagramSocket(candidate, InetAddress.getByName("127.0.0.1"))) {
          if (used.add(candidate)) return candidate;
        } catch (java.net.BindException occupiedByUdp) {
          // Select a port that is free for both stream and datagram listeners.
        }
      }
    throw new IllegalStateException("No free port");
  }

  private static void udpEchoLoop(
      DatagramSocket socket, AtomicBoolean running, AtomicInteger received) {
    byte[] buffer = new byte[65535];
    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
    while (running.get())
      try {
        packet.setLength(buffer.length);
        socket.receive(packet);
        long echoReceivedNanos = System.nanoTime();
        received.incrementAndGet();
        if (packet.getLength() >= 32) {
          int offset = packet.getOffset();
          if (readBigEndianInt(packet.getData(), offset) == UDP_PERF_MAGIC) {
            writeBigEndianLong(packet.getData(), offset + 16, echoReceivedNanos);
            writeBigEndianLong(packet.getData(), offset + 24, System.nanoTime());
          }
        }
        socket.send(packet);
      } catch (Exception ignored) {
        // Health checks may connect and close before sending a request.
      }
  }

  private static int readBigEndianInt(byte[] bytes, int offset) {
    return (bytes[offset] & 0xff) << 24
        | (bytes[offset + 1] & 0xff) << 16
        | (bytes[offset + 2] & 0xff) << 8
        | (bytes[offset + 3] & 0xff);
  }

  private static void writeBigEndianLong(byte[] bytes, int offset, long value) {
    for (int index = Long.BYTES - 1; index >= 0; index--) {
      bytes[offset + index] = (byte) value;
      value >>>= Byte.SIZE;
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
      socket.setReceiveBufferSize(1024 * 1024);
      socket.setSendBufferSize(1024 * 1024);
      socket.setSoTimeout(5000);
      socket.send(
          new DatagramPacket(expected, expected.length, InetAddress.getByName("127.0.0.1"), port));
      byte[] result = new byte[65535];
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
    httpBodyRoundTrip(port, false);
  }

  private static void httpBodyRoundTrip(int port, boolean fragmented) throws Exception {
    httpBodyRoundTrip(port, fragmented, javax.net.SocketFactory.getDefault());
  }

  private static void httpBodyRoundTrip(int port, boolean fragmented,
      javax.net.SocketFactory factory) throws Exception {
    byte[] body = new byte[96 * 1024];
    new java.util.Random(8675309L).nextBytes(body);
    byte[] marker = "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    System.arraycopy(marker, 0, body, 10, marker.length);
    System.arraycopy(marker, 0, body, 70000, marker.length);
    byte[] header =
        ("POST /health HTTP/1.1\r\nHost: feature.test\r\nContent-Length: "
                + body.length
                + "\r\nX-Forwarded-For: 203.0.113.1\r\nConnection: close\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1);
    try (Socket socket = factory.createSocket("127.0.0.1", port)) {
      socket.setSoTimeout(10000);
      OutputStream output = socket.getOutputStream();
      if (fragmented) {
        output.write(header, 0, header.length - 2);
        output.flush();
        Thread.sleep(20);
        output.write(header, header.length - 2, 2);
        output.write(body, 0, 31);
        output.flush();
        Thread.sleep(20);
        for (int offset = 31; offset < body.length; offset += 8191)
          output.write(body, offset, Math.min(8191, body.length - offset));
      } else {
        output.write(header);
        output.write(body);
      }
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
      if (!java.util.Arrays.equals(body, echoed)) {
        throw new AssertionError("HTTP request body changed during proxying: expected=" + body.length + " received=" + echoed.length + " mismatch=" + java.util.Arrays.mismatch(body, echoed) + " fragmented=" + fragmented + " socket=" + socket.getClass().getSimpleName());
      }
    }
  }

  private static void udpMixedDatagrams(int port) throws Exception {
    try (DatagramSocket socket = new DatagramSocket()) {
      socket.setSoTimeout(5000);
      for (int length : new int[] {1, 4096, 16384, 3}) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) bytes[i] = (byte) (i + length);
        socket.send(new DatagramPacket(bytes, bytes.length,
            InetAddress.getByName("127.0.0.1"), port));
        byte[] result = new byte[65535];
        DatagramPacket response = new DatagramPacket(result, result.length);
        socket.receive(response);
        if (response.getLength() != length
            || !java.util.Arrays.equals(bytes, java.util.Arrays.copyOf(result, length)))
          throw new AssertionError("UDP packet boundary or payload changed");
      }
    }
  }

  private static void udpBurst(
      int port,
      AtomicInteger echoReceived,
      int management,
      String managementToken,
      Client client)
      throws Exception {
    final int packets = Integer.getInteger("tunnel.test.udpPackets", 20000);
    final int payloadBytes = 64;
    final long paceNanos = Long.getLong("tunnel.test.udpPaceNanos", 0L);
    final boolean detailedStats =
        Boolean.parseBoolean(System.getProperty("tunnel.test.detailedUdpPerfStats", "true"));
    int sent = 0;
    AtomicInteger sentCount = new AtomicInteger();
    AtomicInteger received = new AtomicInteger();
    AtomicLong lastResponseNanos = new AtomicLong();
    AtomicLongArray sentAtNanos = new AtomicLongArray(packets);
    long[] rttNanos = new long[packets];
    long[] requestPathNanos = new long[packets];
    long[] requestToServerMuxWriteNanos = new long[packets];
    long[] serverMuxWriteToClientUdpNanos = new long[packets];
    long[] clientUdpWriteToEchoNanos = new long[packets];
    long[] clientUdpWriteQueueNanos = new long[packets];
    long[] clientUdpWriteCompleteToEchoNanos = new long[packets];
    long[] echoServiceNanos = new long[packets];
    long[] responsePathNanos = new long[packets];
    long[] clientUdpReadPathNanos = new long[packets];
    long[] clientMuxToServerNanos = new long[packets];
    long[] clientMuxWriteToServerNanos = new long[packets];
    long[] clientMuxWriteQueueNanos = new long[packets];
    long[] clientMuxWriteCompleteToServerNanos = new long[packets];
    long[] serverOutputPathNanos = new long[packets];
    InetSocketAddress remote = new InetSocketAddress("127.0.0.1", port);
    try (DatagramChannel channel = DatagramChannel.open(); Selector selector = Selector.open()) {
      channel.configureBlocking(false);
      channel.setOption(java.net.StandardSocketOptions.SO_RCVBUF, 16 * 1024 * 1024);
      channel.setOption(java.net.StandardSocketOptions.SO_SNDBUF, 16 * 1024 * 1024);
      channel.bind(new InetSocketAddress("127.0.0.1", 0));
      channel.register(selector, SelectionKey.OP_READ);
      byte[] warmup = new byte[payloadBytes];
      ByteBuffer sendBuffer = ByteBuffer.allocate(payloadBytes);
      ByteBuffer receiveBuffer = ByteBuffer.allocate(65535);
      sendBuffer.put(warmup).flip();
      if (channel.send(sendBuffer, remote) != payloadBytes)
        throw new AssertionError("UDP burst warmup send failed");
      long warmDeadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
      boolean warmReceived = false;
      while (!warmReceived && System.nanoTime() < warmDeadline) {
        selector.select(100);
        selector.selectedKeys().clear();
        receiveBuffer.clear();
        SocketAddress source = channel.receive(receiveBuffer);
        warmReceived = source != null && receiveBuffer.position() == payloadBytes;
      }
      if (!warmReceived) throw new AssertionError("UDP burst warmup failed");
      long tunnelBytesBefore =
          metricValue(
              get("http://127.0.0.1:" + management + "/metrics", managementToken),
              "tunnel_bytes_from_public_total");
      long publicBytesBefore =
          metricValue(
              get("http://127.0.0.1:" + management + "/metrics", managementToken),
              "tunnel_bytes_to_public_total");
      long udpDroppedBefore =
          metricValue(
              get("http://127.0.0.1:" + management + "/metrics", managementToken),
              "tunnel_udp_dropped_total");
      long clientDroppedBefore = client.udpMuxQueueDrops();
      long clientLocalDrainTasksBefore = client.udpLocalEgressDrainTasks();
      long clientMuxDrainTasksBefore = client.udpMuxEgressDrainTasks();
      long clientMuxQueueDelayBefore = client.udpMuxEgressQueueDelayNanos();
      long clientMuxQueueSamplesBefore = client.udpMuxEgressQueueDelaySamples();
      long clientLocalUdpReadDelayBefore = client.udpLocalUdpReadDelayNanos();
      long clientLocalUdpReadSamplesBefore = client.udpLocalUdpReadSamples();
      long clientLocalQueueDelayBefore = client.udpLocalEgressQueueDelayNanos();
      long clientLocalQueueDatagramsBefore = client.udpLocalEgressQueueDelayDatagrams();
      long egressBatchesBefore = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_batches_total");
      long egressDrainTasksBefore = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_drain_tasks_total");
      long egressQueueDelayBefore = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_queue_delay_nanos_total");
      long egressWritesBefore = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_writes_total");
      long egressWriteNanosBefore = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_write_nanos_total");
      long egressWriteSamplesBefore = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_write_samples_total");
      int echoBefore = echoReceived.get();
      long started = System.nanoTime();
      long nextSendAt = started;
      AtomicBoolean sendFinished = new AtomicBoolean();
      AtomicReference<Throwable> readerFailure = new AtomicReference<>();
      java.util.concurrent.CountDownLatch readerReady =
          new java.util.concurrent.CountDownLatch(1);
      Thread responseReader =
          new Thread(
              () -> {
                long idleSince = 0;
                long receiveDeadline = Long.MAX_VALUE;
                readerReady.countDown();
                try {
                  while (true) {
                    if (sendFinished.get()) {
                      long now = System.nanoTime();
                      if (receiveDeadline == Long.MAX_VALUE) {
                        idleSince = now;
                        receiveDeadline = now + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
                      }
                      if (received.get() >= sentCount.get()
                          || now >= receiveDeadline
                          || now - idleSince >= java.util.concurrent.TimeUnit.SECONDS.toNanos(1))
                        break;
                    }
                    selector.select(100);
                    selector.selectedKeys().clear();
                    receiveBuffer.clear();
                    boolean gotPacket = false;
                    while (channel.receive(receiveBuffer) != null) {
                      if (receiveBuffer.position() == payloadBytes) {
                        recordUdpResponse(
                            receiveBuffer,
                            sentAtNanos,
                            rttNanos,
                            requestPathNanos,
                            requestToServerMuxWriteNanos,
                            serverMuxWriteToClientUdpNanos,
                            clientUdpWriteToEchoNanos,
                            clientUdpWriteQueueNanos,
                            clientUdpWriteCompleteToEchoNanos,
                            echoServiceNanos,
                            responsePathNanos,
                            clientUdpReadPathNanos,
                            clientMuxToServerNanos,
                            clientMuxWriteToServerNanos,
                            clientMuxWriteQueueNanos,
                            clientMuxWriteCompleteToServerNanos,
                            client,
                            serverOutputPathNanos);
                        received.incrementAndGet();
                        lastResponseNanos.set(System.nanoTime());
                        gotPacket = true;
                      }
                      receiveBuffer.clear();
                    }
                    if (gotPacket && sendFinished.get()) idleSince = System.nanoTime();
                  }
                } catch (Throwable error) {
                  readerFailure.set(error);
                }
              },
              "udp-perf-reader");
      responseReader.setDaemon(true);
      responseReader.start();
      if (!readerReady.await(5, java.util.concurrent.TimeUnit.SECONDS))
        throw new AssertionError("UDP response reader did not start");
      for (int i = 0; i < packets; i++) {
        sendBuffer.clear();
        sendBuffer.putInt(UDP_PERF_MAGIC).putInt(i);
        long packetSentAt = System.nanoTime();
        sendBuffer.putLong(packetSentAt);
        while (sendBuffer.position() < payloadBytes) sendBuffer.put((byte) 0);
        sendBuffer.flip();
        sentAtNanos.set(i, packetSentAt);
        if (channel.send(sendBuffer, remote) == payloadBytes) {
          sent++;
          sentCount.incrementAndGet();
        } else sentAtNanos.set(i, 0);
        if (paceNanos > 0) {
          nextSendAt += paceNanos;
          paceUntil(nextSendAt);
        }
      }
      long sendEnded = System.nanoTime();
      sendFinished.set(true);
      selector.wakeup();
      responseReader.join(java.util.concurrent.TimeUnit.SECONDS.toMillis(11));
      if (responseReader.isAlive()) throw new AssertionError("UDP response reader stalled");
      if (readerFailure.get() != null)
        throw new AssertionError("UDP response reader failed", readerFailure.get());
      long tunnelBytesAfter =
          metricValue(
              get("http://127.0.0.1:" + management + "/metrics", managementToken),
              "tunnel_bytes_from_public_total");
      long publicBytesAfter =
          metricValue(
              get("http://127.0.0.1:" + management + "/metrics", managementToken),
              "tunnel_bytes_to_public_total");
      long udpDroppedAfter =
          metricValue(
              get("http://127.0.0.1:" + management + "/metrics", managementToken),
              "tunnel_udp_dropped_total");
      long clientDroppedAfter = client.udpMuxQueueDrops();
      long clientLocalDrainTasksAfter = client.udpLocalEgressDrainTasks();
      long clientMuxDrainTasksAfter = client.udpMuxEgressDrainTasks();
      long clientMuxQueueDelayAfter = client.udpMuxEgressQueueDelayNanos();
      long clientMuxQueueSamplesAfter = client.udpMuxEgressQueueDelaySamples();
      long clientMuxQueueDelayMax = client.udpMuxEgressQueueDelayMaxNanos();
      long clientLocalUdpReadDelayAfter = client.udpLocalUdpReadDelayNanos();
      long clientLocalUdpReadSamplesAfter = client.udpLocalUdpReadSamples();
      long clientLocalUdpReadDelayMax = client.udpLocalUdpReadMaxNanos();
      long clientLocalQueueDelayAfter = client.udpLocalEgressQueueDelayNanos();
      long clientLocalQueueDatagramsAfter = client.udpLocalEgressQueueDelayDatagrams();
      long clientLocalQueueDelayMax = client.udpLocalEgressQueueDelayMaxNanos();
      long egressBatchesAfter = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_batches_total");
      long egressDrainTasksAfter = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_drain_tasks_total");
      long egressQueueDelayAfter = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_queue_delay_nanos_total");
      long egressQueueDelayMax = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_queue_delay_nanos_max");
      long egressWritesAfter = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_writes_total");
      long egressWriteNanosAfter = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_write_nanos_total");
      long egressWriteSamplesAfter = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_write_samples_total");
      long egressWriteMax = metricValue(
          get("http://127.0.0.1:" + management + "/metrics", managementToken),
          "tunnel_udp_egress_write_nanos_max");
      double seconds = (System.nanoTime() - started) / 1_000_000_000.0;
      double sendSeconds = (sendEnded - started) / 1_000_000_000.0;
      double receiveSeconds =
          ((lastResponseNanos.get() == 0 ? sendEnded : lastResponseNanos.get()) - started)
              / 1_000_000_000.0;
      int observed = 0;
      int receivedCount = received.get();
      long[] observedRttNanos = new long[receivedCount];
      for (long rtt : rttNanos) if (rtt > 0) observedRttNanos[observed++] = rtt;
      java.util.Arrays.sort(observedRttNanos, 0, observed);
      long[] observedRequestNanos = sortedPositiveNanos(requestPathNanos);
      long[] observedRequestToMuxWriteNanos = sortedPositiveNanos(requestToServerMuxWriteNanos);
      long[] observedServerMuxToClientUdpNanos =
          sortedPositiveNanos(serverMuxWriteToClientUdpNanos);
      long[] observedClientUdpWriteToEchoNanos = sortedPositiveNanos(clientUdpWriteToEchoNanos);
      long[] observedClientUdpWriteQueueNanos = sortedPositiveNanos(clientUdpWriteQueueNanos);
      long[] observedClientUdpWriteCompleteToEchoNanos =
          sortedPositiveNanos(clientUdpWriteCompleteToEchoNanos);
      long[] observedEchoNanos = sortedPositiveNanos(echoServiceNanos);
      long[] observedResponseNanos = sortedPositiveNanos(responsePathNanos);
      long[] observedClientUdpReadNanos =
          sortedPositiveNanos(clientUdpReadPathNanos);
      long[] observedClientMuxToServerNanos =
          sortedPositiveNanos(clientMuxToServerNanos);
      long[] observedClientMuxWriteToServerNanos =
          sortedPositiveNanos(clientMuxWriteToServerNanos);
      long[] observedClientMuxWriteQueueNanos =
          sortedPositiveNanos(clientMuxWriteQueueNanos);
      long[] observedClientMuxWriteCompleteToServerNanos =
          sortedPositiveNanos(clientMuxWriteCompleteToServerNanos);
      long[] observedServerOutputNanos =
          sortedPositiveNanos(serverOutputPathNanos);
      double p50Millis = percentileMillis(observedRttNanos, observed, 0.50);
      double p95Millis = percentileMillis(observedRttNanos, observed, 0.95);
      double p99Millis = percentileMillis(observedRttNanos, observed, 0.99);
      double requestP95Millis =
          percentileMillis(observedRequestNanos, observedRequestNanos.length, 0.95);
      double requestToMuxWriteP95Millis =
          percentileMillis(
              observedRequestToMuxWriteNanos, observedRequestToMuxWriteNanos.length, 0.95);
      double serverMuxToClientUdpP95Millis =
          percentileMillis(
              observedServerMuxToClientUdpNanos,
              observedServerMuxToClientUdpNanos.length,
              0.95);
      double clientUdpWriteToEchoP95Millis =
          percentileMillis(
              observedClientUdpWriteToEchoNanos,
              observedClientUdpWriteToEchoNanos.length,
              0.95);
      double clientUdpWriteQueueP95Millis =
          percentileMillis(
              observedClientUdpWriteQueueNanos,
              observedClientUdpWriteQueueNanos.length,
              0.95);
      double clientUdpWriteCompleteToEchoP95Millis =
          percentileMillis(
              observedClientUdpWriteCompleteToEchoNanos,
              observedClientUdpWriteCompleteToEchoNanos.length,
              0.95);
      double echoP95Millis = percentileMillis(observedEchoNanos, observedEchoNanos.length, 0.95);
      double responseP95Millis =
          percentileMillis(observedResponseNanos, observedResponseNanos.length, 0.95);
      double clientUdpReadP95Millis =
          percentileMillis(observedClientUdpReadNanos, observedClientUdpReadNanos.length, 0.95);
      double clientMuxToServerP95Millis =
          percentileMillis(observedClientMuxToServerNanos, observedClientMuxToServerNanos.length, 0.95);
      double clientMuxWriteToServerP95Millis =
          percentileMillis(
              observedClientMuxWriteToServerNanos,
              observedClientMuxWriteToServerNanos.length,
              0.95);
      double clientMuxWriteQueueP95Millis =
          percentileMillis(
              observedClientMuxWriteQueueNanos,
              observedClientMuxWriteQueueNanos.length,
              0.95);
      double clientMuxWriteCompleteToServerP95Millis =
          percentileMillis(
              observedClientMuxWriteCompleteToServerNanos,
              observedClientMuxWriteCompleteToServerNanos.length,
              0.95);
      double serverOutputP95Millis =
          percentileMillis(observedServerOutputNanos, observedServerOutputNanos.length, 0.95);
      long egressBatchCount = egressBatchesAfter - egressBatchesBefore;
      long egressDrainTaskCount = egressDrainTasksAfter - egressDrainTasksBefore;
      long clientLocalDrainTaskCount = clientLocalDrainTasksAfter - clientLocalDrainTasksBefore;
      long clientMuxDrainTaskCount = clientMuxDrainTasksAfter - clientMuxDrainTasksBefore;
      long clientMuxQueueSamples = clientMuxQueueSamplesAfter - clientMuxQueueSamplesBefore;
      long clientLocalUdpReadSamples =
          clientLocalUdpReadSamplesAfter - clientLocalUdpReadSamplesBefore;
      long clientLocalQueuedDatagrams =
          clientLocalQueueDatagramsAfter - clientLocalQueueDatagramsBefore;
      long egressWriteCount = egressWritesAfter - egressWritesBefore;
      long egressWriteSampleCount = egressWriteSamplesAfter - egressWriteSamplesBefore;
      System.out.printf(
          "UDP_PERF: detailed=%s payload=%d bytes sent=%d public-in=%d public-out=%d echo-in=%d received=%d client-queue-drop=%d server-drop=%d loss=%.2f%% send-rate=%.0f pps receive-rate=%.0f pps rtt-p50=%.3f ms p95=%.3f ms p99=%.3f ms request-p95=%.3f ms request-to-server-mux-write-p95=%.3f ms server-mux-write-to-client-udp-p95=%.3f ms client-udp-write-to-echo-p95=%.3f ms client-udp-write-queue-p95=%.3f ms client-udp-write-complete-to-echo-p95=%.3f ms echo-p95=%.3f ms response-p95=%.3f ms client-udp-read-p95=%.3f ms client-mux-to-server-p95=%.3f ms client-mux-write-to-server-p95=%.3f ms client-mux-write-queue-p95=%.3f ms client-write-complete-to-server-p95=%.3f ms server-output-p95=%.3f ms server-batches=%d server-drain-tasks=%d client-local-drain-tasks=%d client-mux-drain-tasks=%d datagrams-per-batch=%.1f batches-per-server-drain=%.1f server-queue-avg=%.3f ms max=%.3f ms client-local-queue-avg=%.3f ms max=%.3f ms client-mux-queue-avg=%.3f ms max=%.3f ms client-local-udp-read-avg=%.3f ms max=%.3f ms egress-write-avg-sampled=%.3f ms samples=%d/%d max=%.3f ms elapsed=%.3f s%n",
          detailedStats,
          payloadBytes,
          sent,
          (tunnelBytesAfter - tunnelBytesBefore) / payloadBytes,
          (publicBytesAfter - publicBytesBefore) / payloadBytes,
          echoReceived.get() - echoBefore,
          receivedCount,
          clientDroppedAfter - clientDroppedBefore,
          udpDroppedAfter - udpDroppedBefore,
          sent == 0 ? 0.0 : 100.0 * (sent - receivedCount) / sent,
          sendSeconds == 0 ? 0.0 : sent / sendSeconds,
          receiveSeconds == 0 ? 0.0 : receivedCount / receiveSeconds,
          p50Millis,
          p95Millis,
          p99Millis,
          requestP95Millis,
          requestToMuxWriteP95Millis,
          serverMuxToClientUdpP95Millis,
          clientUdpWriteToEchoP95Millis,
          clientUdpWriteQueueP95Millis,
          clientUdpWriteCompleteToEchoP95Millis,
          echoP95Millis,
          responseP95Millis,
          clientUdpReadP95Millis,
          clientMuxToServerP95Millis,
          clientMuxWriteToServerP95Millis,
          clientMuxWriteQueueP95Millis,
          clientMuxWriteCompleteToServerP95Millis,
          serverOutputP95Millis,
          egressBatchCount,
          egressDrainTaskCount,
          clientLocalDrainTaskCount,
          clientMuxDrainTaskCount,
          egressBatchCount == 0 ? 0.0 : egressWriteCount / (double) egressBatchCount,
          egressDrainTaskCount == 0 ? 0.0 : egressBatchCount / (double) egressDrainTaskCount,
          egressBatchCount == 0 ? 0.0 : (egressQueueDelayAfter - egressQueueDelayBefore) / (double) egressBatchCount / 1_000_000.0,
          egressQueueDelayMax / 1_000_000.0,
          clientLocalQueuedDatagrams == 0
              ? 0.0
              : (clientLocalQueueDelayAfter - clientLocalQueueDelayBefore)
                  / (double) clientLocalQueuedDatagrams
                  / 1_000_000.0,
          clientLocalQueueDelayMax / 1_000_000.0,
          clientMuxQueueSamples == 0
              ? 0.0
              : (clientMuxQueueDelayAfter - clientMuxQueueDelayBefore)
                  / (double) clientMuxQueueSamples
                  / 1_000_000.0,
          client.udpMuxEgressQueueDelayMaxNanos() / 1_000_000.0,
          clientLocalUdpReadSamples == 0
              ? 0.0
              : (clientLocalUdpReadDelayAfter - clientLocalUdpReadDelayBefore)
                  / (double) clientLocalUdpReadSamples
                  / 1_000_000.0,
          clientLocalUdpReadDelayMax / 1_000_000.0,
          egressWriteSampleCount == 0 ? 0.0 : (egressWriteNanosAfter - egressWriteNanosBefore) / (double) egressWriteSampleCount / 1_000_000.0,
          egressWriteSampleCount,
          egressWriteCount,
          egressWriteMax / 1_000_000.0,
          seconds);
    }
  }

  private static void recordUdpResponse(
      ByteBuffer response,
      AtomicLongArray sentAtNanos,
      long[] rttNanos,
      long[] requestPathNanos,
      long[] requestToServerMuxWriteNanos,
      long[] serverMuxWriteToClientUdpNanos,
      long[] clientUdpWriteToEchoNanos,
      long[] clientUdpWriteQueueNanos,
      long[] clientUdpWriteCompleteToEchoNanos,
      long[] echoServiceNanos,
      long[] responsePathNanos,
      long[] clientUdpReadPathNanos,
      long[] clientMuxToServerNanos,
      long[] clientMuxWriteToServerNanos,
      long[] clientMuxWriteQueueNanos,
      long[] clientMuxWriteCompleteToServerNanos,
      Client client,
      long[] serverOutputPathNanos) {
    if (response.getInt(0) != UDP_PERF_MAGIC) return;
    int packetId = response.getInt(4);
    if (packetId < 0 || packetId >= rttNanos.length) return;
    long sentAt = sentAtNanos.get(packetId);
    long serverMuxWriteAt = response.getLong(56);
    long clientUdpWriteAt = client.udpLocalDatagramWriteNanos(packetId);
    long clientUdpWriteCompleteAt = client.udpLocalDatagramWriteCompleteNanos(packetId);
    long echoReceivedAt = response.getLong(16);
    long echoSentAt = response.getLong(24);
    long clientUdpReadAt = response.getLong(32);
    long serverDecodeAt = response.getLong(40);
    long clientMuxWriteAt = response.getLong(48);
    long clientMuxWriteCompleteAt = client.udpMuxWriteCompleteNanos(packetId);
    long receivedAt = System.nanoTime();
    if (sentAt > 0 && echoReceivedAt >= sentAt && echoSentAt >= echoReceivedAt) {
      rttNanos[packetId] = receivedAt - sentAt;
      requestPathNanos[packetId] = echoReceivedAt - sentAt;
      if (serverMuxWriteAt >= sentAt) {
        requestToServerMuxWriteNanos[packetId] = serverMuxWriteAt - sentAt;
        if (clientUdpWriteAt >= serverMuxWriteAt) {
          serverMuxWriteToClientUdpNanos[packetId] = clientUdpWriteAt - serverMuxWriteAt;
          if (echoReceivedAt >= clientUdpWriteAt)
            clientUdpWriteToEchoNanos[packetId] = echoReceivedAt - clientUdpWriteAt;
          if (clientUdpWriteCompleteAt >= clientUdpWriteAt) {
            clientUdpWriteQueueNanos[packetId] = clientUdpWriteCompleteAt - clientUdpWriteAt;
            if (echoReceivedAt >= clientUdpWriteCompleteAt)
              clientUdpWriteCompleteToEchoNanos[packetId] =
                  echoReceivedAt - clientUdpWriteCompleteAt;
          }
        }
      }
      echoServiceNanos[packetId] = echoSentAt - echoReceivedAt;
      responsePathNanos[packetId] = receivedAt - echoSentAt;
      if (clientUdpReadAt >= echoSentAt && serverDecodeAt >= clientUdpReadAt) {
        clientUdpReadPathNanos[packetId] = clientUdpReadAt - echoSentAt;
        clientMuxToServerNanos[packetId] = serverDecodeAt - clientUdpReadAt;
        serverOutputPathNanos[packetId] = receivedAt - serverDecodeAt;
        if (clientMuxWriteAt >= clientUdpReadAt && serverDecodeAt >= clientMuxWriteAt)
          clientMuxWriteToServerNanos[packetId] = serverDecodeAt - clientMuxWriteAt;
        if (clientMuxWriteCompleteAt >= clientMuxWriteAt) {
          clientMuxWriteQueueNanos[packetId] = clientMuxWriteCompleteAt - clientMuxWriteAt;
          if (serverDecodeAt >= clientMuxWriteCompleteAt)
            clientMuxWriteCompleteToServerNanos[packetId] =
                serverDecodeAt - clientMuxWriteCompleteAt;
        }
      }
    }
  }

  private static long[] sortedPositiveNanos(long[] values) {
    long[] samples = new long[values.length];
    int count = 0;
    for (int i = 0; i < samples.length; i++)
      if (values[i] > 0) samples[count++] = values[i];
    java.util.Arrays.sort(samples, 0, count);
    return java.util.Arrays.copyOf(samples, count);
  }

  private static double percentileMillis(long[] sortedNanos, int length, double percentile) {
    if (length == 0) return 0.0;
    int index = Math.min(length - 1, (int) Math.ceil(length * percentile) - 1);
    return sortedNanos[index] / 1_000_000.0;
  }

  private static void paceUntil(long deadlineNanos) {
    for (;;) {
      long remaining = deadlineNanos - System.nanoTime();
      if (remaining <= 0) return;
      if (remaining > 1_000_000L)
        java.util.concurrent.locks.LockSupport.parkNanos(remaining - 500_000L);
      else Thread.onSpinWait();
    }
  }

  private static long metricValue(String metrics, String name) {
    for (String line : metrics.split("\\r?\\n"))
      if (line.startsWith(name + " ")) return Long.parseLong(line.substring(name.length() + 1));
    throw new AssertionError("Metric missing: " + name);
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
    for (int attempt = 0; attempt < 4; attempt++) {
      httpBodyRoundTrip(port, false, context.getSocketFactory());
      httpBodyRoundTrip(port, true, context.getSocketFactory());
    }
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
