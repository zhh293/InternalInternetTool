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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Local throughput benchmark over the real TCP/TLS/mux path. */
public final class PerformanceSmoke {
  // Keep the measurement long enough to smooth scheduler/JIT noise on loopback.
  private static final int WARMUP_BYTES = 32 * 1024 * 1024;
  private static final int MEASURED_BYTES = 256 * 1024 * 1024;
  private static final int MEASURED_RUNS = 3;
  private static final int CHUNK_BYTES = 64 * 1024;

  public static void main(String[] args) throws Exception {
    if (args.length != 0) throw new IllegalArgumentException("Usage: PerformanceSmoke");
    int flowWindowBytes =
        Integer.getInteger("tunnel.test.flowWindowBytes", Mux.DEFAULT_FLOW_WINDOW_BYTES);
    boolean tcpNoDelay = Boolean.parseBoolean(System.getProperty("tunnel.test.tcpNoDelay", "true"));
    String flushMode = System.getProperty("tunnel.test.flushMode", "latency");
    AtomicBoolean running = new AtomicBoolean(true);
    Path temp = Files.createTempDirectory("tunnel-performance-");
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
      Properties serverValues = new Properties();
      serverValues.setProperty("bindHost", "127.0.0.1");
      serverValues.setProperty("controlPort", String.valueOf(controlPort));
      serverValues.setProperty("workPort", String.valueOf(workPort));
      serverValues.setProperty("publicBindHost", "127.0.0.1");
      serverValues.setProperty("allowedPortStart", String.valueOf(publicPort));
      serverValues.setProperty("allowedPortEnd", String.valueOf(publicPort));
      serverValues.setProperty("maxPendingBytes", String.valueOf(256 * 1024 * 1024));
      serverValues.setProperty("flowWindowBytes", String.valueOf(flowWindowBytes));
      serverValues.setProperty("tcpNoDelay", String.valueOf(tcpNoDelay));
      serverValues.setProperty("flushMode", flushMode);
      serverValues.setProperty("tokenFile", secret.toString());
      serverValues.setProperty("certFile", certificate.certificate().getAbsolutePath());
      serverValues.setProperty("keyFile", certificate.privateKey().getAbsolutePath());
      try (OutputStream output = Files.newOutputStream(serverConfig)) {
        serverValues.store(output, "performance-test");
      }

      Path clientConfig = temp.resolve("client.properties");
      Properties clientValues = new Properties();
      clientValues.setProperty("serverHost", "localhost");
      clientValues.setProperty("controlPort", String.valueOf(controlPort));
      clientValues.setProperty("workPort", String.valueOf(workPort));
      clientValues.setProperty("clientId", "performance-client");
      clientValues.setProperty("tokenFile", secret.toString());
      clientValues.setProperty("caFile", certificate.certificate().getAbsolutePath());
      clientValues.setProperty("maxPendingBytes", String.valueOf(256 * 1024 * 1024));
      clientValues.setProperty("flowWindowBytes", String.valueOf(flowWindowBytes));
      clientValues.setProperty("tcpNoDelay", String.valueOf(tcpNoDelay));
      clientValues.setProperty("flushMode", flushMode);
      clientValues.setProperty("map.web", publicPort + ",127.0.0.1," + echo.getLocalPort());
      try (OutputStream output = Files.newOutputStream(clientConfig)) {
        clientValues.store(output, "performance-test");
      }

      try (Server server = new Server(serverConfig.toString());
          Client client = new Client(clientConfig.toString())) {
        Thread echoThread = new Thread(() -> acceptEcho(echo, running), "performance-echo-accept");
        echoThread.setDaemon(true);
        echoThread.start();
        server.start();
        client.start();
        waitUntilMapped(publicPort);

        roundTrip(publicPort, WARMUP_BYTES, false);
        double[] rates = new double[MEASURED_RUNS];
        try (CpuSampler cpu = new CpuSampler()) {
          for (int i = 0; i < rates.length; i++) {
            long elapsedNanos = roundTrip(publicPort, MEASURED_BYTES, true);
            rates[i] = MEASURED_BYTES * 1_000_000_000.0 / 1024.0 / 1024.0 / elapsedNanos;
          }
          double[] sortedRates = rates.clone();
          Arrays.sort(sortedRates);
          System.out.printf(
              "PERFORMANCE_RESULT: window=%d KiB tcpNoDelay=%s flushMode=%s payload=%d MiB runs=%d application-MiB/s=[%.1f,%.1f,%.1f] median=%.1f range=%.1f..%.1f round-trip-wire-median=%.1f MiB/s process-cpu-avg=%.1f%% peak=%.1f%% system-cpu-avg=%.1f%% peak=%.1f%% samples=%d%n",
              flowWindowBytes / 1024,
              tcpNoDelay,
              flushMode,
              MEASURED_BYTES / 1024 / 1024,
              MEASURED_RUNS,
              rates[0],
              rates[1],
              rates[2],
              sortedRates[1],
              sortedRates[0],
              sortedRates[sortedRates.length - 1],
              2.0 * sortedRates[1],
              cpu.averageProcessPercent(),
              cpu.peakProcessPercent(),
              cpu.averageSystemPercent(),
              cpu.peakSystemPercent(),
              cpu.sampleCount());
        }
      }
    } finally {
      running.set(false);
      certificate.delete();
      Files.deleteIfExists(temp.resolve("server.properties"));
      Files.deleteIfExists(temp.resolve("client.properties"));
      Files.deleteIfExists(temp.resolve("token"));
      Files.deleteIfExists(temp);
    }
  }

  private static final class CpuSampler implements AutoCloseable {
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicLong processCpuSumTenthsPercent = new AtomicLong();
    private final AtomicLong processCpuPeakTenthsPercent = new AtomicLong();
    private final AtomicLong sumTenthsPercent = new AtomicLong();
    private final AtomicLong peakTenthsPercent = new AtomicLong();
    private final AtomicInteger samples = new AtomicInteger();
    private final Thread thread;

    CpuSampler() {
      thread =
          new Thread(
              () -> {
                com.sun.management.OperatingSystemMXBean os =
                    ManagementFactory.getPlatformMXBean(
                        com.sun.management.OperatingSystemMXBean.class);
                while (running.get()) {
                  double processLoad = os == null ? -1 : os.getProcessCpuLoad();
                  if (processLoad >= 0) {
                    long tenthsPercent = Math.round(processLoad * 1000);
                    processCpuSumTenthsPercent.addAndGet(tenthsPercent);
                    processCpuPeakTenthsPercent.accumulateAndGet(tenthsPercent, Math::max);
                  }
                  double load = os == null ? -1 : os.getSystemCpuLoad();
                  if (load >= 0) {
                    long tenthsPercent = Math.round(load * 1000);
                    sumTenthsPercent.addAndGet(tenthsPercent);
                    peakTenthsPercent.accumulateAndGet(tenthsPercent, Math::max);
                    samples.incrementAndGet();
                  }
                  try {
                    Thread.sleep(250);
                  } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                  }
                }
              },
              "performance-cpu-sampler");
      thread.setDaemon(true);
      thread.start();
    }

    double averageSystemPercent() {
      int count = samples.get();
      return count == 0 ? 0 : sumTenthsPercent.get() / (double) count / 10.0;
    }

    double averageProcessPercent() {
      int count = samples.get();
      return count == 0 ? 0 : processCpuSumTenthsPercent.get() / (double) count / 10.0;
    }

    double peakProcessPercent() {
      return processCpuPeakTenthsPercent.get() / 10.0;
    }

    double peakSystemPercent() {
      return peakTenthsPercent.get() / 10.0;
    }

    int sampleCount() {
      return samples.get();
    }

    @Override
    public void close() throws InterruptedException {
      running.set(false);
      thread.interrupt();
      thread.join(1000);
    }
  }

  private static void acceptEcho(ServerSocket server, AtomicBoolean running) {
    while (running.get()) {
      try {
        Socket incoming = server.accept();
        Thread worker = new Thread(() -> echo(incoming), "performance-echo-worker");
        worker.setDaemon(true);
        worker.start();
      } catch (Exception error) {
        if (running.get()) throw new RuntimeException(error);
      }
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
    } catch (Exception error) {
      throw new RuntimeException(error);
    }
  }

  private static long roundTrip(int publicPort, int bytes, boolean measure) throws Exception {
    try (Socket socket = new Socket("127.0.0.1", publicPort)) {
      socket.setSoTimeout(30_000);
      byte[] chunk = new byte[CHUNK_BYTES];
      for (int i = 0; i < chunk.length; i++) chunk[i] = (byte) i;
      CountDownLatch writerDone = new CountDownLatch(1);
      AtomicBoolean writerFailed = new AtomicBoolean(false);
      long start = measure ? System.nanoTime() : 0;
      Thread writer =
          new Thread(
              () -> {
                try {
                  OutputStream output = socket.getOutputStream();
                  int remaining = bytes;
                  while (remaining > 0) {
                    int length = Math.min(remaining, chunk.length);
                    output.write(chunk, 0, length);
                    remaining -= length;
                  }
                  output.flush();
                } catch (Exception error) {
                  writerFailed.set(true);
                } finally {
                  writerDone.countDown();
                }
              },
              "performance-writer");
      writer.start();

      InputStream input = socket.getInputStream();
      byte[] buffer = new byte[CHUNK_BYTES];
      int received = 0;
      while (received < bytes) {
        int count = input.read(buffer, 0, Math.min(buffer.length, bytes - received));
        if (count < 0) throw new AssertionError("Echo closed early: " + received + "/" + bytes);
        received += count;
      }
      if (!writerDone.await(30, TimeUnit.SECONDS) || writerFailed.get())
        throw new AssertionError("Writer failed or timed out");
      return measure ? System.nanoTime() - start : 0;
    }
  }

  private static void waitUntilMapped(int publicPort) throws Exception {
    for (int attempt = 0; attempt < 50; attempt++) {
      try (Socket ignored = new Socket("127.0.0.1", publicPort)) {
        return;
      } catch (Exception error) {
        Thread.sleep(100);
      }
    }
    throw new AssertionError("Public port was not registered");
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
}
