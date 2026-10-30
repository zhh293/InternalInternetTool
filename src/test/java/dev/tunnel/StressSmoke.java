package dev.tunnel;

import io.netty.handler.ssl.util.SelfSignedCertificate;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/** Multi-client sustained TCP stress test with JVM CPU and heap sampling. */
public final class StressSmoke {
  private static final int PAYLOAD_BYTES = 16 * 1024;

  public static void main(String[] args) throws Exception {
    int clientCount = args.length > 0 ? Integer.parseInt(args[0]) : 8;
    int connectionsPerClient = args.length > 1 ? Integer.parseInt(args[1]) : 4;
    int durationSeconds = args.length > 2 ? Integer.parseInt(args[2]) : 30;
    int muxPoolSize = args.length > 3 ? Integer.parseInt(args[3]) : 2;
    boolean tcpNoDelay = Boolean.parseBoolean(System.getProperty("tunnel.test.tcpNoDelay", "true"));
    String flushMode = System.getProperty("tunnel.test.flushMode", "latency");
    if (clientCount < 1 || connectionsPerClient < 1 || durationSeconds < 1 || muxPoolSize < 1 || muxPoolSize > 32)
      throw new IllegalArgumentException("Usage: StressSmoke [clients] [connectionsPerClient] [seconds] [muxPoolSize]");

    int totalConnections = clientCount * connectionsPerClient;
    AtomicBoolean running = new AtomicBoolean(true);
    Path temp = Files.createTempDirectory("tunnel-stress-");
    SelfSignedCertificate certificate = new SelfSignedCertificate("localhost");
    List<EchoEndpoint> echoes = new ArrayList<>();
    List<Client> clients = new ArrayList<>();
    ExecutorService workers = Executors.newFixedThreadPool(totalConnections);
    AtomicLong bytes = new AtomicLong();
    AtomicLong operations = new AtomicLong();
    AtomicLong latencyNanos = new AtomicLong();
    AtomicLong errors = new AtomicLong();
    AtomicLong maxHeapBytes = new AtomicLong();
    AtomicLong maxCpuPercent = new AtomicLong();
    try {
      Set<Integer> used = new HashSet<>();
      int controlPort = freePort(used);
      int workPort = freePort(used);
      List<Integer> publicPorts = new ArrayList<>();
      for (int i = 0; i < clientCount; i++) publicPorts.add(freePort(used));
      for (int i = 0; i < clientCount; i++) echoes.add(new EchoEndpoint(used));

      Path secret = temp.resolve("token");
      Files.writeString(secret, "local-testing-token-0123456789abcdef", StandardCharsets.UTF_8);
      Path serverConfig = temp.resolve("server.properties");
      Properties serverValues = new Properties();
      serverValues.setProperty("bindHost", "127.0.0.1");
      serverValues.setProperty("controlPort", String.valueOf(controlPort));
      serverValues.setProperty("workPort", String.valueOf(workPort));
      serverValues.setProperty("publicBindHost", "127.0.0.1");
      serverValues.setProperty("allowedPortStart", String.valueOf(Collections.min(publicPorts)));
      serverValues.setProperty(
          "allowedPortEnd", String.valueOf(Collections.max(publicPorts)));
      serverValues.setProperty("muxPoolSize", String.valueOf(muxPoolSize));
      serverValues.setProperty("tcpNoDelay", String.valueOf(tcpNoDelay));
      serverValues.setProperty("flushMode", flushMode);
      serverValues.setProperty("maxPendingBytes", String.valueOf(64 * 1024 * 1024));
      serverValues.setProperty("managementPort", "0");
      serverValues.setProperty("tokenFile", secret.toString());
      serverValues.setProperty("certFile", certificate.certificate().getAbsolutePath());
      serverValues.setProperty("keyFile", certificate.privateKey().getAbsolutePath());
      try (OutputStream output = Files.newOutputStream(serverConfig)) {
        serverValues.store(output, "stress-test");
      }

      for (int i = 0; i < clientCount; i++) {
        Path clientConfig = temp.resolve("client-" + i + ".properties");
        Properties clientValues = new Properties();
        clientValues.setProperty("serverHost", "localhost");
        clientValues.setProperty("controlPort", String.valueOf(controlPort));
        clientValues.setProperty("workPort", String.valueOf(workPort));
        clientValues.setProperty("clientId", "stress-client-" + i);
        clientValues.setProperty("muxPoolSize", String.valueOf(muxPoolSize));
        clientValues.setProperty("tcpNoDelay", String.valueOf(tcpNoDelay));
        clientValues.setProperty("flushMode", flushMode);
        clientValues.setProperty("tokenFile", secret.toString());
        clientValues.setProperty("caFile", certificate.certificate().getAbsolutePath());
        clientValues.setProperty("maxPendingBytes", String.valueOf(64 * 1024 * 1024));
        clientValues.setProperty(
            "map.web", publicPorts.get(i) + ",127.0.0.1," + echoes.get(i).port());
        try (OutputStream output = Files.newOutputStream(clientConfig)) {
          clientValues.store(output, "stress-test");
        }
        clients.add(new Client(clientConfig.toString()));
      }

      for (EchoEndpoint echo : echoes) echo.start(running);
      try (Server server = new Server(serverConfig.toString())) {
        server.start();
        for (Client client : clients) client.start();
        for (int port : publicPorts) waitUntilMapped(port);

        CountDownLatch ready = new CountDownLatch(totalConnections);
        CountDownLatch warmupStart = new CountDownLatch(1);
        CountDownLatch warmupDone = new CountDownLatch(totalConnections);
        CountDownLatch measureStart = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(totalConnections);
        AtomicLong measureDeadlineNanos = new AtomicLong();
        for (int i = 0; i < totalConnections; i++) {
          int publicPort = publicPorts.get(i / connectionsPerClient);
          workers.submit(
              () -> runConnection(
                  publicPort,
                  ready,
                  warmupStart,
                  warmupDone,
                  measureStart,
                  measureDeadlineNanos,
                  done,
                  bytes,
                  operations,
                  latencyNanos,
                  errors));
        }
        if (!ready.await(30, TimeUnit.SECONDS)) throw new AssertionError("Connections did not become ready");
        warmupStart.countDown();
        if (!warmupDone.await(30, TimeUnit.SECONDS)) throw new AssertionError("Connections did not warm up");

        Thread sampler = startSampler(running, maxHeapBytes, maxCpuPercent);
        long begin = System.nanoTime();
        measureDeadlineNanos.set(begin + TimeUnit.SECONDS.toNanos(durationSeconds));
        measureStart.countDown();
        if (!done.await(durationSeconds + 30L, TimeUnit.SECONDS))
          throw new AssertionError("Stress workers did not finish");
        long elapsedNanos = System.nanoTime() - begin;
        running.set(false);
        sampler.join(3000);
        workers.shutdownNow();

        double seconds = elapsedNanos / 1_000_000_000.0;
        double mibPerSecond = bytes.get() / 1024.0 / 1024.0 / seconds;
        double averageLatencyMs = operations.get() == 0
            ? 0
            : latencyNanos.get() / 1_000_000.0 / operations.get();
        System.out.printf(
            "STRESS_RESULT: clients=%d connections=%d tcpNoDelay=%s flushMode=%s duration=%.1f s bytes=%d MiB throughput=%.2f MiB/s operations=%d avg-echo-latency=%.3f ms errors=%d max-process-cpu=%.1f%% max-heap=%.1f MiB%n",
            clientCount,
            totalConnections,
            tcpNoDelay,
            flushMode,
            seconds,
            bytes.get() / 1024 / 1024,
            mibPerSecond,
            operations.get(),
            averageLatencyMs,
            errors.get(),
            maxCpuPercent.get() / 10.0,
            maxHeapBytes.get() / 1024.0 / 1024.0);
        if (errors.get() != 0) throw new AssertionError("Stress errors: " + errors.get());
      }
    } finally {
      running.set(false);
      for (Client client : clients) client.close();
      workers.shutdownNow();
      for (EchoEndpoint echo : echoes) echo.close();
      certificate.delete();
      deleteTree(temp);
    }
  }

  private static void runConnection(
      int publicPort,
      CountDownLatch ready,
      CountDownLatch warmupStart,
      CountDownLatch warmupDone,
      CountDownLatch measureStart,
      AtomicLong measureDeadlineNanos,
      CountDownLatch done,
      AtomicLong bytes,
      AtomicLong operations,
      AtomicLong latencyNanos,
      AtomicLong errors) {
    try (Socket socket = new Socket("127.0.0.1", publicPort)) {
      socket.setSoTimeout(2000);
      ready.countDown();
      byte[] payload = new byte[PAYLOAD_BYTES];
      for (int i = 0; i < payload.length; i++) payload[i] = (byte) i;
      byte[] response = new byte[PAYLOAD_BYTES];
      InputStream input = socket.getInputStream();
      OutputStream output = socket.getOutputStream();
      warmupStart.await();
      for (int i = 0; i < 8; i++) {
        output.write(payload);
        output.flush();
        readFully(input, response);
      }
      warmupDone.countDown();
      measureStart.await();
      long end = measureDeadlineNanos.get();
      while (System.nanoTime() < end) {
        long operationStart = System.nanoTime();
        output.write(payload);
        output.flush();
        readFully(input, response);
        latencyNanos.addAndGet(System.nanoTime() - operationStart);
        operations.incrementAndGet();
        bytes.addAndGet(payload.length);
      }
    } catch (Exception error) {
      errors.incrementAndGet();
    } finally {
      ready.countDown();
      warmupDone.countDown();
      done.countDown();
    }
  }

  private static void readFully(InputStream input, byte[] buffer) throws Exception {
    int offset = 0;
    while (offset < buffer.length) {
      int count = input.read(buffer, offset, buffer.length - offset);
      if (count < 0) throw new AssertionError("Echo closed early");
      offset += count;
    }
  }

  private static Thread startSampler(
      AtomicBoolean running, AtomicLong maxHeapBytes, AtomicLong maxCpuPercent) {
    Thread sampler =
        new Thread(
            () -> {
              com.sun.management.OperatingSystemMXBean os =
                  ManagementFactory.getPlatformMXBean(
                      com.sun.management.OperatingSystemMXBean.class);
              Runtime runtime = Runtime.getRuntime();
              while (running.get()) {
                long usedHeap = runtime.totalMemory() - runtime.freeMemory();
                maxHeapBytes.accumulateAndGet(usedHeap, Math::max);
                if (os != null) {
                  double cpu = os.getProcessCpuLoad();
                  if (cpu >= 0) maxCpuPercent.accumulateAndGet((long) (cpu * 1000), Math::max);
                }
                try {
                  Thread.sleep(1000);
                } catch (InterruptedException interrupted) {
                  Thread.currentThread().interrupt();
                  return;
                }
              }
            },
            "stress-resource-sampler");
    sampler.setDaemon(true);
    sampler.start();
    return sampler;
  }

  private static void waitUntilMapped(int publicPort) throws Exception {
    for (int attempt = 0; attempt < 100; attempt++) {
      try (Socket ignored = new Socket("127.0.0.1", publicPort)) {
        return;
      } catch (Exception error) {
        Thread.sleep(100);
      }
    }
    throw new AssertionError("Public port was not registered: " + publicPort);
  }

  private static int freePort(Set<Integer> used) throws Exception {
    for (int attempt = 0; attempt < 50; attempt++) {
      try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
        int candidate = socket.getLocalPort();
        if (used.add(candidate)) return candidate;
      }
    }
    throw new IllegalStateException("Could not find distinct test ports");
  }

  private static void deleteTree(Path root) throws Exception {
    if (!Files.exists(root)) return;
    try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
      paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
        try {
          Files.deleteIfExists(path);
        } catch (Exception error) {
          throw new RuntimeException(error);
        }
      });
    }
  }

  private static final class EchoEndpoint implements AutoCloseable {
    private final ServerSocket server;
    private final AtomicBoolean running = new AtomicBoolean();
    private Thread acceptor;

    EchoEndpoint(Set<Integer> used) throws Exception {
      server = new ServerSocket(0, 100, InetAddress.getByName("127.0.0.1"));
      if (!used.add(server.getLocalPort())) throw new IllegalStateException("Duplicate endpoint port");
    }

    int port() {
      return server.getLocalPort();
    }

    void start(AtomicBoolean outerRunning) {
      running.set(true);
      acceptor =
          new Thread(
              () -> {
                while (outerRunning.get() && running.get()) {
                  try {
                    Socket socket = server.accept();
                    Thread worker = new Thread(() -> echo(socket), "stress-echo-worker");
                    worker.setDaemon(true);
                    worker.start();
                  } catch (Exception error) {
                    if (outerRunning.get() && running.get()) throw new RuntimeException(error);
                  }
                }
              },
              "stress-echo-acceptor");
      acceptor.setDaemon(true);
      acceptor.start();
    }

    private static void echo(Socket socket) {
      try (Socket closeable = socket) {
        byte[] buffer = new byte[PAYLOAD_BYTES];
        InputStream input = closeable.getInputStream();
        OutputStream output = closeable.getOutputStream();
        int count;
        while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
      } catch (Exception ignored) {
      }
    }

    @Override
    public void close() throws Exception {
      running.set(false);
      server.close();
    }
  }
}
