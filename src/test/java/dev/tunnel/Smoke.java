package dev.tunnel;

import io.netty.handler.ssl.util.SelfSignedCertificate;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/** Real TCP/TLS integration smoke test. Generates disposable local credentials. */
public final class Smoke {
  public static void main(String[] args) throws Exception {
    if (args.length != 0) throw new IllegalArgumentException("Usage: Smoke");
    AtomicBoolean running = new AtomicBoolean(true);
    Path temp = Files.createTempDirectory("tunnel-smoke-");
    SelfSignedCertificate certificate = new SelfSignedCertificate("localhost");
    try (ServerSocket echo = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
      Set<Integer> used = new HashSet<>();
      used.add(echo.getLocalPort());
      int controlPort = freePort(used);
      int workPort = freePort(used);
      int publicPort = freePort(used);
      Path secret = temp.resolve("token");
      Files.writeString(secret, "local-testing-token-0123456789abcdef", StandardCharsets.UTF_8);
      Path serverConfig = temp.resolve("server.properties");
      Path clientConfig = temp.resolve("client.properties");
      Properties serverValues = new Properties();
      serverValues.setProperty("bindHost", "127.0.0.1");
      serverValues.setProperty("controlPort", String.valueOf(controlPort));
      serverValues.setProperty("workPort", String.valueOf(workPort));
      serverValues.setProperty("publicBindHost", "127.0.0.1");
      serverValues.setProperty("allowedPortStart", String.valueOf(publicPort));
      serverValues.setProperty("allowedPortEnd", String.valueOf(publicPort));
      serverValues.setProperty("tokenFile", secret.toString());
      serverValues.setProperty("certFile", certificate.certificate().getAbsolutePath());
      serverValues.setProperty("keyFile", certificate.privateKey().getAbsolutePath());
      try (OutputStream output = Files.newOutputStream(serverConfig)) {
        serverValues.store(output, "test");
      }
      Properties clientValues = new Properties();
      clientValues.setProperty("serverHost", "localhost");
      clientValues.setProperty("controlPort", String.valueOf(controlPort));
      clientValues.setProperty("workPort", String.valueOf(workPort));
      clientValues.setProperty("clientId", "smoke-client");
      clientValues.setProperty("tokenFile", secret.toString());
      clientValues.setProperty("caFile", certificate.certificate().getAbsolutePath());
      clientValues.setProperty("map.web", publicPort + ",127.0.0.1," + echo.getLocalPort());
      try (OutputStream output = Files.newOutputStream(clientConfig)) {
        clientValues.store(output, "test");
      }
      run(echo, serverConfig.toString(), clientConfig.toString(), publicPort, running);
    } finally {
      running.set(false);
      certificate.delete();
      Files.deleteIfExists(temp.resolve("server.properties"));
      Files.deleteIfExists(temp.resolve("client.properties"));
      Files.deleteIfExists(temp.resolve("token"));
      Files.deleteIfExists(temp);
    }
  }

  private static int freePort(Set<Integer> used) throws Exception {
    for (int attempt = 0; attempt < 20; attempt++) {
      try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
        int candidate = socket.getLocalPort();
        if (used.add(candidate)) return candidate;
      }
    }
    throw new IllegalStateException("Could not find distinct test ports");
  }

  private static void run(
      ServerSocket echo,
      String serverConfig,
      String clientConfig,
      int publicPort,
      AtomicBoolean running)
      throws Exception {
    try (Server server = new Server(serverConfig);
        Client client = new Client(clientConfig)) {
      Thread echoThread =
          new Thread(
              () -> {
                while (running.get()) {
                  try {
                    Socket incoming = echo.accept();
                    Thread worker = new Thread(() -> echo(incoming), "echo-worker");
                    worker.setDaemon(true);
                    worker.start();
                  } catch (Exception e) {
                    if (running.get()) throw new RuntimeException(e);
                  }
                }
              },
              "echo-accept");
      echoThread.setDaemon(true);
      echoThread.start();
      server.start();
      client.start();
      waitUntilMapped(publicPort);
      roundTrip(publicPort, new byte[] {0, 1, 2, 3, -1, 10, 13});
      byte[] large = new byte[1024 * 1024];
      for (int i = 0; i < large.length; i++) large[i] = (byte) i;
      roundTrip(publicPort, large);
      concurrentRoundTrips(publicPort);
      client.close();
      try (Client replacement = new Client(clientConfig)) {
        replacement.start();
        waitUntilRoundTripWorks(publicPort);
      }
      System.out.println("SMOKE_OK: TLS, binary, 1 MiB, concurrent clients, restart recovery");
    }
  }

  private static void echo(Socket incoming) {
    try (Socket socket = incoming) {
      byte[] buffer = new byte[8192];
      InputStream input = socket.getInputStream();
      OutputStream output = socket.getOutputStream();
      int count;
      while ((count = input.read(buffer)) != -1) {
        output.write(buffer, 0, count);
        output.flush();
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static void waitUntilMapped(int publicPort) throws Exception {
    for (int attempt = 0; attempt < 50; attempt++) {
      try (Socket ignored = new Socket("127.0.0.1", publicPort)) {
        return;
      } catch (Exception e) {
        Thread.sleep(100);
      }
    }
    throw new AssertionError("Public port was not registered");
  }

  private static void roundTrip(int publicPort, byte[] expected) throws Exception {
    try (Socket socket = new Socket("127.0.0.1", publicPort)) {
      socket.setSoTimeout(10000);
      socket.getOutputStream().write(expected);
      socket.getOutputStream().flush();
      byte[] actual = socket.getInputStream().readNBytes(expected.length);
      if (!Arrays.equals(expected, actual)) {
        throw new AssertionError(
            "Round trip mismatch: expected=" + expected.length + " actual=" + actual.length);
      }
    }
  }

  private static void concurrentRoundTrips(int publicPort) throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(12);
    try {
      List<Future<?>> results = new ArrayList<>();
      for (int i = 0; i < 36; i++) {
        final int marker = i;
        results.add(
            pool.submit(
                () -> {
                  try {
                    roundTrip(publicPort, new byte[] {(byte) marker, 0, -1, 42});
                  } catch (Exception e) {
                    throw new RuntimeException(e);
                  }
                }));
      }
      for (Future<?> result : results) result.get();
    } finally {
      pool.shutdownNow();
    }
  }

  private static void waitUntilRoundTripWorks(int publicPort) throws Exception {
    Exception last = null;
    for (int attempt = 0; attempt < 50; attempt++) {
      try {
        roundTrip(publicPort, new byte[] {11, 22, 33});
        return;
      } catch (Exception e) {
        last = e;
        Thread.sleep(100);
      }
    }
    throw new AssertionError("Mapping did not recover after client restart", last);
  }
}
