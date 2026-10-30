package dev.tunnel;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Inner-network agent. TCP and UDP use separate TLS mux work-channel pools. */
public final class Client implements AutoCloseable {
  private static final int TEST_UDP_PERF_MAGIC = 0x54554E4C;
  private static final int MAX_UDP_STREAMS = 512;
  private static final int MAX_UDP_PENDING_PER_STREAM = 256 * 1024;
  private static final int MAX_UDP_PENDING_TOTAL = 8 * 1024 * 1024;
  private static final int MAX_UDP_MUX_PENDING_PER_STREAM = 512 * 1024;
  private static final int MAX_UDP_MUX_PENDING_BATCHES = 2048;
  private static final long MAX_UDP_MUX_PENDING_AGE_NANOS =
      TimeUnit.MILLISECONDS.toNanos(
          Math.max(1L, Long.getLong("tunnel.test.udpQueueMaxAgeMillis", 100L)));
  private static final int MAX_UDP_LOCAL_EGRESS_DATAGRAMS = 8192;
  private static final int MAX_UDP_LOCAL_EGRESS_BATCHES_PER_TURN = 16;
  private static final int MAX_UDP_MUX_BATCHES_PER_TURN = 16;
  private static final long MAX_UDP_LOCAL_EGRESS_QUEUE_AGE_NANOS =
      TimeUnit.MILLISECONDS.toNanos(
          Math.max(1L, Long.getLong("tunnel.test.udpQueueMaxAgeMillis", 100L)));
  private final Settings settings;
  private final String token;
  private final String clientId;
  private final String serverHost;
  private final ConcurrentMap<String, Settings.Rule> rules;
  private final ConcurrentMap<String, Long> healthNext = new ConcurrentHashMap<>();
  private final SslContext ssl;
  private final EventLoopGroup group = new io.netty.channel.nio.NioEventLoopGroup();
  private final EventLoopGroup udpGroup;
  private final Map<Integer, LocalStream> streams = new ConcurrentHashMap<>();
  private final Map<Integer, UdpLocalStream> udpStreams = new ConcurrentHashMap<>();
  private final AtomicInteger activeUdpStreams = new AtomicInteger();
  private final AtomicInteger udpPendingBytes = new AtomicInteger();
  private final boolean collectUdpPerfStats =
      Boolean.parseBoolean(System.getProperty("tunnel.test.collectUdpPerfStats", "false"));
  private final java.util.concurrent.atomic.AtomicLongArray udpMuxWriteCompleteNanos =
      collectUdpPerfStats
          ? new java.util.concurrent.atomic.AtomicLongArray(
              Integer.getInteger("tunnel.test.udpPackets", 20000))
          : new java.util.concurrent.atomic.AtomicLongArray(0);
  private final java.util.concurrent.atomic.AtomicLongArray udpLocalDatagramWriteNanos =
      collectUdpPerfStats
          ? new java.util.concurrent.atomic.AtomicLongArray(
              Integer.getInteger("tunnel.test.udpPackets", 20000))
          : new java.util.concurrent.atomic.AtomicLongArray(0);
  private final java.util.concurrent.atomic.AtomicLongArray udpLocalDatagramWriteCompleteNanos =
      collectUdpPerfStats
          ? new java.util.concurrent.atomic.AtomicLongArray(
              Integer.getInteger("tunnel.test.udpPackets", 20000))
          : new java.util.concurrent.atomic.AtomicLongArray(0);
  private final AtomicLong udpMuxQueueDrops = new AtomicLong();
  private final AtomicLong udpLocalEgressDrainTasks = new AtomicLong();
  private final AtomicLong udpLocalEgressQueueDelayNanos = new AtomicLong();
  private final AtomicLong udpLocalEgressQueueDelayDatagrams = new AtomicLong();
  private final AtomicLong udpLocalEgressQueueDelayMaxNanos = new AtomicLong();
  private final AtomicLong udpMuxEgressDrainTasks = new AtomicLong();
  private final AtomicLong udpMuxEgressQueueDelayNanos = new AtomicLong();
  private final AtomicLong udpMuxEgressQueueDelaySamples = new AtomicLong();
  private final AtomicLong udpMuxEgressQueueDelayMaxNanos = new AtomicLong();
  private final AtomicLong udpLocalUdpReadDelayNanos = new AtomicLong();
  private final AtomicLong udpLocalUdpReadSamples = new AtomicLong();
  private final AtomicLong udpLocalUdpReadMaxNanos = new AtomicLong();
  private final boolean coalesceLocalUdpEgressTasks =
      Boolean.parseBoolean(System.getProperty("tunnel.test.udpLocalEgressCoalescing", "true"));
  private final boolean coalesceUdpMuxWrites =
      Boolean.parseBoolean(System.getProperty("tunnel.test.udpMuxEgressCoalescing", "true"));
  private final AtomicInteger receiveWindowReserved = new AtomicInteger();
  private final Map<Integer, String> waitingOpens = new ConcurrentHashMap<>();
  private final AtomicBoolean reconnectScheduled = new AtomicBoolean();
  private final AtomicBoolean muxRetryScheduled = new AtomicBoolean();
  private final int muxPoolSize;
  private final int udpMuxPoolSize;
  private final int maxPendingBytes;
  private final int flowWindowBytes;
  private final int maxFlowWindowBytes;
  private final int udpSocketBufferBytes;
  private final int udpMuxWriteBufferHighWaterMarkBytes;
  private final boolean udpMuxStriping;
  private final boolean consolidateFlushOutsideRead;
  private final boolean tcpNoDelay;
  private final ScheduledExecutorService healthExecutor =
      Executors.newSingleThreadScheduledExecutor(
          runnable -> {
            Thread thread = new Thread(runnable, "tunnel-health-check");
            thread.setDaemon(true);
            return thread;
          });
  private final java.util.concurrent.atomic.AtomicInteger nextMux =
      new java.util.concurrent.atomic.AtomicInteger();
  private final java.util.concurrent.atomic.AtomicInteger nextUdpMux =
      new java.util.concurrent.atomic.AtomicInteger();
  private final AtomicInteger connectingTcpMuxes = new AtomicInteger();
  private final AtomicInteger connectingUdpMuxes = new AtomicInteger();
  private volatile Channel control;
  private final java.util.Set<Channel> muxes = ConcurrentHashMap.newKeySet();
  private final java.util.Set<Channel> tcpMuxes = ConcurrentHashMap.newKeySet();
  private final java.util.Set<Channel> udpMuxes = ConcurrentHashMap.newKeySet();
  private volatile boolean stopped;
  private volatile int retrySeconds = 1;
  private volatile int muxRetrySeconds = 1;

  public Client(String configPath) throws Exception {
    this.settings = Settings.load(configPath);
    int defaultUdpIoThreads =
        Math.max(1, Math.min(8, Runtime.getRuntime().availableProcessors() / 2));
    this.udpGroup =
        new io.netty.channel.nio.NioEventLoopGroup(
            settings.optionalPositive("udpIoThreads", defaultUdpIoThreads, 1, 32));
    this.consolidateFlushOutsideRead = settings.consolidateFlushOutsideRead();
    this.tcpNoDelay = settings.optionalBoolean("tcpNoDelay", true);
    String tokenFile = settings.optional("clientTokenFile", "");
    this.token =
        tokenFile.isEmpty() ? settings.secret("tokenFile") : Settings.readSecretFile(tokenFile);
    this.clientId = settings.required("clientId");
    Wire.validateName(clientId);
    this.serverHost = settings.required("serverHost");
    this.rules = new ConcurrentHashMap<>(settings.rules());
    this.muxPoolSize = settings.optionalPositive("muxPoolSize", 1, 1, 32);
    this.udpMuxPoolSize = settings.optionalPositive("udpMuxPoolSize", 1, 0, 32);
    this.maxPendingBytes =
        settings.optionalPositive("maxPendingBytes", 8 * 1024 * 1024, 64 * 1024, 256 * 1024 * 1024);
    this.flowWindowBytes =
        settings.optionalPositive(
            "flowWindowBytes",
            Mux.DEFAULT_FLOW_WINDOW_BYTES,
            Mux.MIN_FLOW_WINDOW_BYTES,
            Mux.MAX_FLOW_WINDOW_BYTES);
    this.maxFlowWindowBytes =
        settings.optionalPositive(
            "maxFlowWindowBytes",
            512 * 1024 * 1024,
            Mux.MIN_FLOW_WINDOW_BYTES,
            1024 * 1024 * 1024);
    this.udpSocketBufferBytes =
        settings.optionalPositive("udpSocketBufferBytes", 256 * 1024, 64 * 1024, 16 * 1024 * 1024);
    this.udpMuxWriteBufferHighWaterMarkBytes =
        settings.optionalPositive(
            "udpMuxWriteBufferHighWaterMarkBytes", 8 * 1024 * 1024, 64 * 1024, 16 * 1024 * 1024);
    this.udpMuxStriping =
        settings.optionalBoolean("udpMuxStriping", false) && udpMuxPoolSize > 1;
    this.ssl =
        SslContextBuilder.forClient()
            .trustManager(Path.of(settings.required("caFile")).toFile())
            .endpointIdentificationAlgorithm("HTTPS")
            .protocols("TLSv1.3", "TLSv1.2")
            .build();
  }

  public void start() {
    connectControl();
    healthExecutor.scheduleAtFixedRate(this::runHealthChecks, 1, 1, TimeUnit.SECONDS);
  }

  private void runHealthChecks() {
    Channel channel = control;
    if (stopped || channel == null || !channel.isActive()) return;
    long now = System.nanoTime();
    for (Settings.Rule rule : rules.values()) {
      Settings.Rule.HealthCheck health = rule.healthCheck;
      if (health == null) continue;
      String key = rule.name;
      Long next = healthNext.get(key);
      if (next != null && next > now) continue;
      healthNext.put(key, now + TimeUnit.SECONDS.toNanos(health.intervalSeconds));
      boolean healthy = checkLocal(rule, health);
      Wire.send(channel, "HEALTH " + rule.name + " " + (healthy ? "1" : "0"));
    }
  }

  private boolean checkLocal(Settings.Rule rule, Settings.Rule.HealthCheck health) {
    try (Socket socket = new Socket()) {
      socket.connect(
          new InetSocketAddress(rule.localHost, rule.localPort), health.timeoutSeconds * 1000);
      if (!"http".equals(health.type)) return true;
      socket.setSoTimeout(health.timeoutSeconds * 1000);
      OutputStream output = socket.getOutputStream();
      String host = rule.hostRewrite.isEmpty() ? rule.localHost : rule.hostRewrite;
      if (host.indexOf(':') != host.lastIndexOf(':') && !host.startsWith("["))
        host = "[" + host + "]";
      output.write(
          ("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
              .getBytes(StandardCharsets.US_ASCII));
      output.flush();
      InputStream input = socket.getInputStream();
      byte[] status = new byte[128];
      int length = 0;
      int next;
      while (length < status.length && (next = input.read()) >= 0) {
        if (next == '\n') break;
        status[length++] = (byte) next;
      }
      if (length == status.length) return false;
      String line = new String(status, 0, length, StandardCharsets.US_ASCII).trim();
      return line.matches("HTTP/1\\.[01] [23][0-9][0-9](?: .*)?");
    } catch (IOException ignored) {
      return false;
    }
  }

  private Bootstrap socketBootstrap(
      ChannelInitializer<SocketChannel> initializer, boolean autoRead) {
    return new Bootstrap()
        .group(group)
        .channel(NioSocketChannel.class)
        .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
        .option(ChannelOption.TCP_NODELAY, tcpNoDelay)
        .option(
            ChannelOption.WRITE_BUFFER_WATER_MARK,
            new io.netty.channel.WriteBufferWaterMark(2 * 1024 * 1024, 8 * 1024 * 1024))
        .option(ChannelOption.AUTO_READ, autoRead)
        .handler(initializer);
  }

  private void connectControl() {
    if (stopped) return;
    socketBootstrap(
            new ChannelInitializer<SocketChannel>() {
              @Override
              protected void initChannel(SocketChannel channel) {
                channel
                    .pipeline()
                    .addLast(
                        "ssl",
                        ssl.newHandler(channel.alloc(), serverHost, settings.port("controlPort")));
                channel.pipeline().addLast("idle", new IdleStateHandler(45, 15, 0));
                channel.pipeline().addLast("lines", new LineBasedFrameDecoder(4096));
                channel.pipeline().addLast("control", new ControlHandler());
              }
            },
            true)
        .connect(serverHost, settings.port("controlPort"))
        .addListener(
            (ChannelFuture result) -> {
              if (!result.isSuccess()) {
                System.err.println("Control connect failed: " + result.cause());
                scheduleReconnect();
              } else {
                control = result.channel();
                retrySeconds = 1;
              }
            });
  }

  private void scheduleReconnect() {
    if (stopped || !reconnectScheduled.compareAndSet(false, true)) return;
    int delay = retrySeconds;
    retrySeconds = Math.min(30, retrySeconds * 2);
    group
        .next()
        .schedule(
            () -> {
              reconnectScheduled.set(false);
              connectControl();
            },
            delay,
            TimeUnit.SECONDS);
  }

  private void connectMuxPools() {
    connectMux(false);
    connectMux(true);
  }

  private void connectMux(boolean udp) {
    int target = udp ? udpMuxPoolSize : muxPoolSize;
    java.util.Set<Channel> pool = udp ? udpMuxes : tcpMuxes;
    AtomicInteger connecting = udp ? connectingUdpMuxes : connectingTcpMuxes;
    if (target == 0 || stopped || control == null || !control.isActive()) return;
    while (true) {
      int current = connecting.get();
      if (pool.size() + current >= target) return;
      if (connecting.compareAndSet(current, current + 1)) break;
    }
    AtomicBoolean pendingReleased = new AtomicBoolean();
    socketBootstrap(
            new ChannelInitializer<SocketChannel>() {
              @Override
              protected void initChannel(SocketChannel channel) {
                if (udp) {
                  int high = udpMuxWriteBufferHighWaterMarkBytes;
                  channel.config().setWriteBufferWaterMark(
                      new io.netty.channel.WriteBufferWaterMark(Math.min(high / 4, high - 1), high));
                }
                channel
                    .pipeline()
                    .addLast(
                        "ssl",
                        ssl.newHandler(channel.alloc(), serverHost, settings.port("workPort")));
                channel.pipeline().addLast("lines", new LineBasedFrameDecoder(4096));
                channel.pipeline().addLast("mux-login", new MuxLoginHandler(udp, pendingReleased));
              }
            },
            true)
        .connect(serverHost, settings.port("workPort"))
        .addListener(
            (ChannelFuture result) -> {
              if (!result.isSuccess()) {
                if (pendingReleased.compareAndSet(false, true)) connecting.decrementAndGet();
                scheduleMuxRetry();
              }
              else {
                // The channel is added after the MUX_OK handshake.
              }
            });
  }

  private void scheduleMuxRetry() {
    if (stopped || !muxRetryScheduled.compareAndSet(false, true)) return;
    int delay = muxRetrySeconds;
    muxRetrySeconds = Math.min(30, muxRetrySeconds * 2);
    group
        .next()
        .schedule(
            () -> {
              muxRetryScheduled.set(false);
              connectMuxPools();
            },
            delay,
            TimeUnit.SECONDS);
  }

  private Channel selectMux() {
    int eligible = 0;
    for (Channel channel : tcpMuxes)
      if (channel.isActive() && channel.isWritable()) eligible++;
    if (eligible == 0) return null;
    int selected = Math.floorMod(nextMux.getAndIncrement(), eligible);
    for (Channel channel : tcpMuxes) {
      if (channel.isActive() && channel.isWritable() && selected-- == 0) return channel;
    }
    return null;
  }

  private Channel selectUdpDataMux() {
    java.util.Set<Channel> pool = udpMuxPoolSize > 0 ? udpMuxes : tcpMuxes;
    int eligible = 0;
    for (Channel channel : pool)
      if (channel.isActive() && channel.isWritable()) eligible++;
    if (eligible == 0) return null;
    int selected = Math.floorMod(nextUdpMux.getAndIncrement(), eligible);
    for (Channel channel : pool)
      if (channel.isActive() && channel.isWritable() && selected-- == 0) return channel;
    return null;
  }

  private boolean isUdpDataMux(Channel channel) {
    return (udpMuxPoolSize > 0 ? udpMuxes : tcpMuxes).contains(channel);
  }

  // Borrows bytes from an inbound handler; queued and outbound views retain ownership.
  private void sendData(int id, ByteBuf bytes) {
    LocalStream tcp = streams.get(id);
    UdpLocalStream udp = udpStreams.get(id);
    Channel channel = tcp != null ? tcp.mux : udp == null ? null : udp.mux;
    if (channel == null || !channel.isActive()) return;
    if (udp != null && !channel.isWritable()) return;
    if (tcp != null) {
      synchronized (tcp.pending) {
        if (streams.get(id) != tcp) return;
        int length = bytes.readableBytes();
        int direct =
            channel.isWritable() && tcp.pending.isEmpty()
                ? Math.min(length, tcp.sendCredit)
                : 0;
        int queued = length - direct;
        if (tcp.pendingBytes + queued > maxPendingBytes) {
          tcp.channel.close();
          return;
        }
        if (direct > 0) {
          Mux.sendData(channel, id, bytes, direct);
          tcp.sendCredit -= direct;
        }
        if (queued > 0) {
          tcp.pending.addLast(bytes.retainedSlice(bytes.readerIndex() + direct, queued));
          tcp.pendingBytes += queued;
          tcp.channel.config().setAutoRead(false);
        }
        if (!tcp.pending.isEmpty() && channel.isWritable()) {
          flushPending(tcp);
        }
        tcp.channel.config().setAutoRead(
            tcp.pending.isEmpty() && tcp.sendCredit > 0 && channel.isWritable());
      }
    } else {
      Mux.sendData(channel, id, bytes);
    }
  }

  private void openTcp(int id, String ruleName) {
    Settings.Rule rule = rules.get(ruleName);
    if (rule == null || rule.kind == Settings.Rule.Kind.UDP) {
      sendFail(id);
      return;
    }
    Channel channel = selectMux();
    if (channel == null || !channel.isActive()) {
      waitingOpens.put(id, ruleName);
      return;
    }
    socketBootstrap(
            new ChannelInitializer<SocketChannel>() {
              @Override
              protected void initChannel(SocketChannel socket) {
                socket.pipeline().addLast("flush", Mux.flushConsolidator(consolidateFlushOutsideRead));
                socket.pipeline().addLast("local", new LocalTcpHandler(id));
              }
            },
            false)
        .connect(rule.localHost, rule.localPort)
        .addListener(
            (ChannelFuture result) -> {
              if (!result.isSuccess() || !channel.isActive()) {
                if (result.isSuccess()) result.channel().close();
                sendFail(id);
                return;
              }
              int receiveGrant =
                  reserveWindow(receiveWindowReserved, flowWindowBytes, maxFlowWindowBytes);
              if (receiveGrant == 0) {
                result.channel().close();
                sendFail(id);
                return;
              }
              LocalStream stream = new LocalStream(id, result.channel(), channel, receiveGrant);
              streams.put(id, stream);
              result.channel().closeFuture().addListener(f -> closeLocal(id, false));
              channel.writeAndFlush(
                  new Mux.Frame(
                      id,
                      Mux.ACK,
                      Unpooled.buffer(Integer.BYTES).writeInt(receiveGrant)));
              result.channel().config().setAutoRead(false);
            });
  }

  private void openUdp(int id, String ruleName, Channel muxChannel) {
    Settings.Rule rule = rules.get(ruleName);
    if (rule == null || rule.kind != Settings.Rule.Kind.UDP) {
      sendFail(id);
      return;
    }
    if (udpStreams.containsKey(id)) return;
    if (!reserve(activeUdpStreams, 1, MAX_UDP_STREAMS)) {
      sendFail(id);
      return;
    }
    UdpLocalStream stream = new UdpLocalStream(id, rule);
    stream.mux = muxChannel;
    if (udpStreams.putIfAbsent(id, stream) != null) {
      activeUdpStreams.decrementAndGet();
      return;
    }
    new Bootstrap()
        .group(udpGroup)
        .channel(NioDatagramChannel.class)
        .option(ChannelOption.SO_RCVBUF, udpSocketBufferBytes)
        .option(ChannelOption.SO_SNDBUF, udpSocketBufferBytes)
        .option(
            ChannelOption.WRITE_BUFFER_WATER_MARK,
            new io.netty.channel.WriteBufferWaterMark(256 * 1024, 1024 * 1024))
        .option(ChannelOption.RCVBUF_ALLOCATOR, new io.netty.channel.FixedRecvByteBufAllocator(65536))
        .option(ChannelOption.AUTO_READ, false)
        .handler(
            new ChannelInitializer<DatagramChannel>() {
              @Override
              protected void initChannel(DatagramChannel channel) {
                channel.pipeline().addLast("udp-local", new LocalUdpHandler(stream));
              }
            })
        .connect(rule.localHost, rule.localPort)
        .addListener(
            (ChannelFuture result) -> {
              if (!result.isSuccess()) {
                closeUdp(id, false);
                sendFail(id);
                return;
              }
              if (udpStreams.get(id) != stream || !muxChannel.isActive()) {
                closeUdp(id, false);
                result.channel().close();
                return;
              }
              stream.channel = result.channel();
              result.channel().closeFuture().addListener(f -> closeUdp(id, false));
              stream.mux = muxChannel;
              if (muxChannel != null && muxChannel.isActive())
                muxChannel.writeAndFlush(new Mux.Frame(id, Mux.ACK, new byte[0]));
              boolean wrotePending = false;
              synchronized (stream.pending) {
                while (!stream.pending.isEmpty()) {
                  ByteBuf packet = stream.pending.removeFirst();
                  try {
                    if (stream.channel.isWritable()) {
                      stream.channel.write(new DatagramPacket(packet.retainedSlice(), stream.target));
                      wrotePending = true;
                    }
                  } finally {
                    packet.release();
                  }
                }
                udpPendingBytes.addAndGet(-stream.pendingBytes);
                stream.pendingBytes = 0;
              }
              if (wrotePending) stream.channel.flush();
              result.channel().config().setAutoRead(true);
            });
  }

  long udpMuxQueueDrops() {
    return udpMuxQueueDrops.get();
  }

  long udpLocalEgressDrainTasks() {
    return udpLocalEgressDrainTasks.get();
  }

  long udpLocalEgressQueueDelayNanos() {
    return udpLocalEgressQueueDelayNanos.get();
  }

  long udpLocalEgressQueueDelayDatagrams() {
    return udpLocalEgressQueueDelayDatagrams.get();
  }

  long udpLocalEgressQueueDelayMaxNanos() {
    return udpLocalEgressQueueDelayMaxNanos.get();
  }

  long udpMuxEgressDrainTasks() {
    return udpMuxEgressDrainTasks.get();
  }

  long udpMuxWriteCompleteNanos(int packetId) {
    if (packetId < 0 || packetId >= udpMuxWriteCompleteNanos.length()) return 0;
    return udpMuxWriteCompleteNanos.get(packetId);
  }

  long udpLocalDatagramWriteNanos(int packetId) {
    if (packetId < 0 || packetId >= udpLocalDatagramWriteNanos.length()) return 0;
    return udpLocalDatagramWriteNanos.get(packetId);
  }

  long udpLocalDatagramWriteCompleteNanos(int packetId) {
    if (packetId < 0 || packetId >= udpLocalDatagramWriteCompleteNanos.length()) return 0;
    return udpLocalDatagramWriteCompleteNanos.get(packetId);
  }

  long udpMuxEgressQueueDelayNanos() {
    return udpMuxEgressQueueDelayNanos.get();
  }

  long udpMuxEgressQueueDelaySamples() {
    return udpMuxEgressQueueDelaySamples.get();
  }

  long udpMuxEgressQueueDelayMaxNanos() {
    return udpMuxEgressQueueDelayMaxNanos.get();
  }

  long udpLocalUdpReadDelayNanos() {
    return udpLocalUdpReadDelayNanos.get();
  }

  long udpLocalUdpReadSamples() {
    return udpLocalUdpReadSamples.get();
  }

  long udpLocalUdpReadMaxNanos() {
    return udpLocalUdpReadMaxNanos.get();
  }

  // Borrows data; the datagram or pending queue owns a retained view.
  private void sendUdp(UdpLocalStream stream, ByteBuf data) {
    synchronized (stream.pending) {
      if (udpStreams.get(stream.id) != stream) return;
      if (stream.channel != null && stream.channel.isActive()) {
        if (!stream.channel.isWritable()) return;
        stream.channel.writeAndFlush(
            new DatagramPacket(data.retainedSlice(),
                stream.target));
      } else {
        int length = data.readableBytes();
        if (stream.pending.size() < Mux.MAX_PENDING_DATAGRAMS
            && stream.pendingBytes + length <= MAX_UDP_PENDING_PER_STREAM
            && reserve(udpPendingBytes, length, MAX_UDP_PENDING_TOTAL)) {
          stream.pending.addLast(Mux.retainDatagramForQueue(data));
          stream.pendingBytes += length;
        }
      }
    }
  }

  private void forwardUdpBatch(
      UdpLocalStream stream, ByteBuf payload, ChannelHandlerContext muxContext) {
    int cursor = payload.readerIndex();
    int end = payload.writerIndex();
    int datagramBytes = 0;
    int datagrams = 0;
    while (cursor < end) {
      if (end - cursor < Short.BYTES) {
        muxContext.close();
        return;
      }
      int length = payload.getUnsignedShort(cursor);
      cursor += Short.BYTES;
      if (length > end - cursor) {
        muxContext.close();
        return;
      }
      cursor += length;
      datagramBytes += length;
      datagrams++;
    }
    Channel target = stream.channel;
    if (target == null || !target.isActive()) return;
    ByteBuf batch = payload.retainedSlice();
    boolean queued = false;
    synchronized (stream.localEgressPending) {
      if (udpStreams.get(stream.id) == stream
          && stream.localEgressPending.size() < MAX_UDP_MUX_PENDING_BATCHES
          && datagrams <= MAX_UDP_LOCAL_EGRESS_DATAGRAMS - stream.localEgressPendingDatagrams
          && datagramBytes <= MAX_UDP_PENDING_PER_STREAM - stream.localEgressPendingBytes
          && reserve(udpPendingBytes, datagramBytes, MAX_UDP_PENDING_TOTAL)) {
        stream.localEgressPending.addLast(
            new PendingLocalUdpBatch(batch, datagramBytes, datagrams));
        stream.localEgressPendingBytes += datagramBytes;
        stream.localEgressPendingDatagrams += datagrams;
        queued = true;
      }
    }
    if (!queued) {
      batch.release();
      udpMuxQueueDrops.addAndGet(datagrams);
      return;
    }
    scheduleLocalUdpDrain(stream, target);
  }

  private void scheduleLocalUdpDrain(UdpLocalStream stream, Channel target) {
    if (!coalesceLocalUdpEgressTasks) {
      try {
        target.eventLoop().execute(() -> drainLocalUdpPending(stream, target, 1));
      } catch (java.util.concurrent.RejectedExecutionException closed) {
        discardLocalUdpPending(stream, true);
      }
      return;
    }
    if (!stream.localEgressDrainScheduled.compareAndSet(false, true)) return;
    try {
      target.eventLoop()
          .execute(() -> drainLocalUdpPending(stream, target, MAX_UDP_LOCAL_EGRESS_BATCHES_PER_TURN));
    } catch (java.util.concurrent.RejectedExecutionException closed) {
      stream.localEgressDrainScheduled.set(false);
      discardLocalUdpPending(stream, true);
    }
  }

  private void drainLocalUdpPending(UdpLocalStream stream, Channel target, int maxBatches) {
    if (collectUdpPerfStats) udpLocalEgressDrainTasks.incrementAndGet();
    int drained = 0;
    boolean wrote = false;
    try {
      while (drained < maxBatches) {
        PendingLocalUdpBatch pending;
        synchronized (stream.localEgressPending) {
          pending = stream.localEgressPending.pollFirst();
          if (pending != null) {
            stream.localEgressPendingBytes -= pending.datagramBytes;
            stream.localEgressPendingDatagrams -= pending.datagrams;
            udpPendingBytes.addAndGet(-pending.datagramBytes);
          }
        }
        if (pending == null) break;
        long ageNanos = System.nanoTime() - pending.queuedAtNanos;
        if (collectUdpPerfStats) {
          udpLocalEgressQueueDelayNanos.addAndGet(ageNanos * pending.datagrams);
          udpLocalEgressQueueDelayDatagrams.addAndGet(pending.datagrams);
          udpLocalEgressQueueDelayMaxNanos.accumulateAndGet(ageNanos, Math::max);
        }
        if (ageNanos > MAX_UDP_LOCAL_EGRESS_QUEUE_AGE_NANOS
            || udpStreams.get(stream.id) != stream
            || !target.isActive()) {
          udpMuxQueueDrops.addAndGet(pending.datagrams);
          pending.payload.release();
          drained++;
          continue;
        }
        try {
          while (pending.payload.isReadable()) {
            int length = pending.payload.readUnsignedShort();
            ByteBuf datagram = pending.payload.readRetainedSlice(length);
            if (target.isWritable()) {
              int packetId =
                  collectUdpPerfStats ? stampUdpPerfLocalWrite(datagram, System.nanoTime()) : -1;
              ChannelFuture write = target.write(new DatagramPacket(datagram, stream.target));
              if (packetId >= 0) {
                write.addListener(
                    result -> {
                      if (result.isSuccess())
                        udpLocalDatagramWriteCompleteNanos.set(packetId, System.nanoTime());
                    });
              }
              wrote = true;
            } else {
              datagram.release();
              udpMuxQueueDrops.incrementAndGet();
            }
          }
        } finally {
          pending.payload.release();
        }
        drained++;
      }
      if (wrote && target.isActive()) target.flush();
    } finally {
      stream.localEgressDrainScheduled.set(false);
      if (coalesceLocalUdpEgressTasks) {
        boolean pending;
        synchronized (stream.localEgressPending) {
          pending = !stream.localEgressPending.isEmpty();
        }
        if (pending) scheduleLocalUdpDrain(stream, target);
      }
    }
  }

  private void discardLocalUdpPending(UdpLocalStream stream, boolean countDrops) {
    synchronized (stream.localEgressPending) {
      PendingLocalUdpBatch pending;
      while ((pending = stream.localEgressPending.pollFirst()) != null) {
        stream.localEgressPendingBytes -= pending.datagramBytes;
        stream.localEgressPendingDatagrams -= pending.datagrams;
        udpPendingBytes.addAndGet(-pending.datagramBytes);
        if (countDrops) udpMuxQueueDrops.addAndGet(pending.datagrams);
        pending.payload.release();
      }
    }
  }

  private void sendUdpMuxBatch(UdpLocalStream stream, Channel mux, ByteBuf payload) {
    int length = payload.readableBytes();
    boolean queued = false;
    synchronized (stream.muxPending) {
      if (udpStreams.get(stream.id) != stream
          || stream.mux == null
          || !stream.mux.isActive()) {
        payload.release();
      } else if (stream.muxPending.isEmpty()
          && mux != null
          && mux.isActive()
          && mux.isWritable()
          && (!coalesceUdpMuxWrites || mux.eventLoop().inEventLoop())) {
        writeUdpMuxBatch(mux, stream.id, payload);
        mux.flush();
      } else {
        while (!stream.muxPending.isEmpty()
            && (stream.muxPending.size() >= MAX_UDP_MUX_PENDING_BATCHES
                || length > MAX_UDP_MUX_PENDING_PER_STREAM - stream.muxPendingBytes)) {
          PendingMuxBatch stale = stream.muxPending.removeFirst();
          int staleBytes = stale.payload.readableBytes();
          stream.muxPendingBytes -= staleBytes;
          udpPendingBytes.addAndGet(-staleBytes);
          stale.payload.release();
          udpMuxQueueDrops.incrementAndGet();
        }
        if (length <= MAX_UDP_MUX_PENDING_PER_STREAM - stream.muxPendingBytes
            && reserve(udpPendingBytes, length, MAX_UDP_PENDING_TOTAL)) {
          stream.muxPending.addLast(new PendingMuxBatch(payload, System.nanoTime()));
          stream.muxPendingBytes += length;
          queued = true;
        } else {
          udpMuxQueueDrops.incrementAndGet();
          payload.release();
        }
      }
    }
    if (queued && mux != null && mux.isActive() && mux.isWritable())
      scheduleUdpMuxDrain(stream, mux);
  }

  private void scheduleUdpMuxDrain(UdpLocalStream stream, Channel mux) {
    if (!stream.muxDrainScheduled.compareAndSet(false, true)) return;
    try {
      mux.eventLoop().execute(() -> drainUdpMuxPending(stream, mux));
    } catch (java.util.concurrent.RejectedExecutionException closed) {
      stream.muxDrainScheduled.set(false);
      discardUdpMuxPending(stream, true);
    }
  }

  private void drainUdpMuxPending(UdpLocalStream stream, Channel scheduledMux) {
    if (collectUdpPerfStats) udpMuxEgressDrainTasks.incrementAndGet();
    Channel mux = udpMuxStriping ? selectUdpDataMux() : scheduledMux;
    int drained = 0;
    boolean wrote = false;
    int combinedBytes = 0;
    ByteBuf combinedPayload = null;
    CompositeByteBuf combinedComposite = null;
    try {
      synchronized (stream.muxPending) {
        while (drained < MAX_UDP_MUX_BATCHES_PER_TURN
            && udpStreams.get(stream.id) == stream
            && !stream.muxPending.isEmpty()
            && mux != null
            && mux.isActive()
            && mux.isWritable()) {
          PendingMuxBatch first = stream.muxPending.peekFirst();
          int nextBytes = first.payload.readableBytes();
          if (combinedBytes > 0 && nextBytes > Mux.MAX_PAYLOAD - combinedBytes) break;
          PendingMuxBatch pending = stream.muxPending.removeFirst();
          int length = pending.payload.readableBytes();
          stream.muxPendingBytes -= length;
          udpPendingBytes.addAndGet(-length);
          long queueDelayNanos = System.nanoTime() - pending.queuedAtNanos;
          if (collectUdpPerfStats) {
            udpMuxEgressQueueDelayNanos.addAndGet(queueDelayNanos);
            udpMuxEgressQueueDelaySamples.incrementAndGet();
            udpMuxEgressQueueDelayMaxNanos.accumulateAndGet(queueDelayNanos, Math::max);
          }
          if (queueDelayNanos > MAX_UDP_MUX_PENDING_AGE_NANOS) {
            udpMuxQueueDrops.incrementAndGet();
            pending.payload.release();
          } else {
            if (combinedPayload == null) combinedPayload = pending.payload;
            else {
              if (combinedComposite == null) {
                combinedComposite = mux.alloc().compositeBuffer(MAX_UDP_MUX_BATCHES_PER_TURN);
                combinedComposite.addComponent(true, combinedPayload);
                combinedPayload = combinedComposite;
              }
              combinedComposite.addComponent(true, pending.payload);
            }
            combinedBytes += length;
          }
          drained++;
        }
      }
      if (combinedPayload != null
          && udpStreams.get(stream.id) == stream
          && mux != null
          && mux.isActive()) {
        writeUdpMuxBatch(mux, stream.id, combinedPayload);
        combinedPayload = null;
        wrote = true;
      }
      if (wrote && mux != null && mux.isActive()) mux.flush();
    } finally {
      if (combinedPayload != null) combinedPayload.release();
      stream.muxDrainScheduled.set(false);
      boolean pending;
      synchronized (stream.muxPending) {
        pending = !stream.muxPending.isEmpty();
      }
      if (pending) {
        Channel next = udpMuxStriping ? selectUdpDataMux() : mux;
        if (next != null && next.isActive() && next.isWritable())
          scheduleUdpMuxDrain(stream, next);
      }
    }
  }

  private void discardUdpMuxPending(UdpLocalStream stream, boolean countDrops) {
    synchronized (stream.muxPending) {
      PendingMuxBatch pending;
      while ((pending = stream.muxPending.pollFirst()) != null) {
        int length = pending.payload.readableBytes();
        stream.muxPendingBytes -= length;
        udpPendingBytes.addAndGet(-length);
        if (countDrops) udpMuxQueueDrops.incrementAndGet();
        pending.payload.release();
      }
    }
  }

  private static int[] stampUdpPerfMuxWrite(ByteBuf payload, long timestampNanos) {
    int cursor = payload.readerIndex();
    int end = payload.writerIndex();
    List<Integer> packetIds = new ArrayList<>();
    while (cursor < end) {
      int length = payload.getUnsignedShort(cursor);
      cursor += Short.BYTES;
      if (length > end - cursor) return new int[0];
      if (length >= 56 && payload.getInt(cursor) == TEST_UDP_PERF_MAGIC) {
        payload.setLong(cursor + 48, timestampNanos);
        packetIds.add(payload.getInt(cursor + 4));
      }
      cursor += length;
    }
    return packetIds.stream().mapToInt(Integer::intValue).toArray();
  }

  private int stampUdpPerfLocalWrite(ByteBuf datagram, long timestampNanos) {
    int index = datagram.readerIndex();
    if (datagram.readableBytes() < 8 || datagram.getInt(index) != TEST_UDP_PERF_MAGIC) return -1;
    int packetId = datagram.getInt(index + 4);
    if (packetId >= 0 && packetId < udpLocalDatagramWriteNanos.length()) {
      udpLocalDatagramWriteNanos.set(packetId, timestampNanos);
      return packetId;
    }
    return -1;
  }

  private void writeUdpMuxBatch(Channel mux, int streamId, ByteBuf payload) {
    int[] packetIds = collectUdpPerfStats ? stampUdpPerfMuxWrite(payload, System.nanoTime()) : null;
    ChannelFuture write = mux.write(new Mux.Frame(streamId, Mux.UDP_BATCH, payload));
    if (packetIds != null && packetIds.length > 0) {
      write.addListener(
          result -> {
            if (!result.isSuccess()) return;
            long completedAtNanos = System.nanoTime();
            for (int packetId : packetIds) {
              if (packetId >= 0 && packetId < udpMuxWriteCompleteNanos.length())
                udpMuxWriteCompleteNanos.set(packetId, completedAtNanos);
            }
          });
    }
  }

  private void sendFail(int id) {
    Channel channel = control;
    if (channel != null && channel.isActive()) Wire.send(channel, "FAIL " + id);
  }

  private void flushWaiting() {
    for (Map.Entry<Integer, String> entry : waitingOpens.entrySet())
      if (waitingOpens.remove(entry.getKey(), entry.getValue()))
        openTcp(entry.getKey(), entry.getValue());
  }

  private final class ControlHandler extends SimpleChannelInboundHandler<ByteBuf> {
    private boolean authenticated;

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
      control = ctx.channel();
      SslHandler tls = ctx.pipeline().get(SslHandler.class);
      tls.handshakeFuture()
          .addListener(
              result -> {
                if (result.isSuccess())
                  Wire.send(
                      ctx.channel(),
                      "HELLO " + Wire.PROTOCOL_VERSION + " " + clientId + " " + token);
                else ctx.close();
              });
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf message) {
      String[] words = Wire.readLine(message).split(" ");
      try {
        switch (words[0]) {
          case "HELLO_OK":
            if (words.length != 2 || !String.valueOf(Wire.PROTOCOL_VERSION).equals(words[1]))
              throw new IllegalArgumentException("Protocol_version_mismatch");
            if (authenticated) throw new IllegalArgumentException("Duplicate HELLO_OK");
            authenticated = true;
            for (Settings.Rule rule : rules.values()) {
              if (rule.kind == Settings.Rule.Kind.TCP)
                Wire.send(ctx.channel(), registerLine("REGISTER", rule));
              else if (rule.kind == Settings.Rule.Kind.UDP)
                Wire.send(ctx.channel(), registerLine("REGISTER_UDP", rule));
              else Wire.send(ctx.channel(), registerLine("REGISTER_HTTP", rule));
            }
            connectMuxPools();
            System.out.println("Connected to " + serverHost);
            break;
          case "REGISTER_OK":
          case "REGISTER_UDP_OK":
          case "REGISTER_HTTP_OK":
            if (words.length != 2) throw new IllegalArgumentException("Invalid register response");
            System.out.println("Published " + words[1]);
            break;
          case "REGISTER_FAIL":
          case "REGISTER_UDP_FAIL":
          case "REGISTER_HTTP_FAIL":
            System.err.println("Rule rejected: " + Wire.readLine(message));
            break;
          case "CONFIG_ADD":
            if (!authenticated || words.length != 2)
              throw new IllegalArgumentException("Invalid CONFIG_ADD");
            DynamicStore.Spec added = DynamicStore.decode(words[1]);
            rules.put(added.name, DynamicStore.toRule(added));
            Wire.send(ctx.channel(), registerLine(commandFor(added.kind), rules.get(added.name)));
            break;
          case "CONFIG_REMOVE":
            if (!authenticated || words.length != 2)
              throw new IllegalArgumentException("Invalid CONFIG_REMOVE");
            Wire.send(ctx.channel(), "UNREGISTER " + words[1]);
            rules.remove(words[1]);
            break;
          case "OPEN":
            if (!authenticated || words.length != 3)
              throw new IllegalArgumentException("Invalid OPEN");
            openTcp(Integer.parseInt(words[1]), words[2]);
            break;
          case "PONG":
            break;
          case "ERROR":
            System.err.println("Server error: " + String.join(" ", words));
            ctx.close();
            break;
          default:
            throw new IllegalArgumentException("Unknown command");
        }
      } catch (RuntimeException error) {
        System.err.println("Control protocol error: " + error.getMessage());
        ctx.close();
      }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      if (control == ctx.channel()) control = null;
      for (Channel mux : new ArrayList<>(muxes)) mux.close();
      for (LocalStream stream : streams.values()) stream.channel.close();
      for (UdpLocalStream stream : new ArrayList<>(udpStreams.values())) closeUdp(stream.id, false);
      scheduleReconnect();
      ctx.fireChannelInactive();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object event) {
      if (event instanceof IdleStateEvent) {
        IdleStateEvent idle = (IdleStateEvent) event;
        if (idle.state() == io.netty.handler.timeout.IdleState.READER_IDLE) ctx.close();
        else if (authenticated) Wire.send(ctx.channel(), "PING");
      } else ctx.fireUserEventTriggered(event);
    }
  }

  private static String registerLine(String command, Settings.Rule rule) {
    String health = "-";
    if (rule.healthCheck != null)
      health =
          rule.healthCheck.type
              + ","
              + rule.healthCheck.timeoutSeconds
              + ","
              + rule.healthCheck.maxFailed
              + ","
              + rule.healthCheck.intervalSeconds;
    if (rule.kind == Settings.Rule.Kind.HTTP)
      return String.join(
          " ",
          command,
          rule.name,
          String.join("|", rule.hosts),
          rule.locations.isEmpty() ? "-" : String.join("|", rule.locations),
          emptyDash(rule.hostRewrite),
          emptyDash(rule.basicUser),
          emptyDash(rule.basicPassword),
          emptyDash(rule.balanceGroup),
          emptyDash(rule.balanceKey),
          String.valueOf(rule.bandwidthBytesPerSecond),
          health);
    return String.join(
        " ",
        command,
        rule.name,
        String.valueOf(rule.remotePort),
        emptyDash(rule.balanceGroup),
        emptyDash(rule.balanceKey),
        String.valueOf(rule.bandwidthBytesPerSecond),
        health);
  }

  private static String commandFor(Settings.Rule.Kind kind) {
    return kind == Settings.Rule.Kind.TCP
        ? "REGISTER"
        : kind == Settings.Rule.Kind.UDP ? "REGISTER_UDP" : "REGISTER_HTTP";
  }

  private static String emptyDash(String value) {
    return value == null || value.isEmpty() ? "-" : value.replaceAll("\\s+", "_");
  }

  private final class MuxLoginHandler extends SimpleChannelInboundHandler<ByteBuf> {
    private final boolean udp;
    private final AtomicBoolean pendingReleased;
    private boolean registered;

    MuxLoginHandler(boolean udp, AtomicBoolean pendingReleased) {
      this.udp = udp;
      this.pendingReleased = pendingReleased;
    }

    private void releasePending() {
      if (pendingReleased.compareAndSet(false, true))
        (udp ? connectingUdpMuxes : connectingTcpMuxes).decrementAndGet();
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
      SslHandler tls = ctx.pipeline().get(SslHandler.class);
      tls.handshakeFuture()
          .addListener(
              result -> {
                if (result.isSuccess())
                  Wire.send(
                      ctx.channel(),
                      "MUX "
                          + Wire.PROTOCOL_VERSION
                          + " "
                          + (udp ? "UDP" : "TCP")
                          + " "
                          + clientId
                          + " "
                          + token);
                else ctx.close();
              });
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf message) {
      String line = Wire.readLine(message);
      String[] words = line.split(" ");
      if (words.length == 3
          && "MUX_OK".equals(words[0])
          && String.valueOf(Wire.PROTOCOL_VERSION).equals(words[1])
          && (udp ? "UDP" : "TCP").equals(words[2])) {
        releasePending();
        muxes.add(ctx.channel());
        (udp ? udpMuxes : tcpMuxes).add(ctx.channel());
        registered = true;
        ctx.pipeline().remove("lines");
        ctx.pipeline().replace(this, "mux-decoder", new Mux.Decoder());
        ctx.pipeline().addBefore("mux-decoder", "flush", Mux.flushConsolidator(consolidateFlushOutsideRead));
        ctx.pipeline().addLast("mux-encoder", new Mux.Encoder());
        ctx.pipeline().addLast("mux-keepalive", new Mux.KeepaliveHandler());
        ctx.pipeline().addLast("mux", new MuxClientHandler());
        muxRetrySeconds = 1;
        flushWaiting();
        connectMuxPools();
      } else {
        ctx.close();
      }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      releasePending();
      muxes.remove(ctx.channel());
      tcpMuxes.remove(ctx.channel());
      udpMuxes.remove(ctx.channel());
      if (registered && !stopped && control != null && control.isActive()) scheduleMuxRetry();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }
  }

  private final class MuxClientHandler extends SimpleChannelInboundHandler<Mux.Frame> {
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Mux.Frame frame) {
      if (frame.type == Mux.OPEN_UDP) {
        openUdp(frame.streamId, frame.payload.toString(StandardCharsets.UTF_8), ctx.channel());
        return;
      }
      LocalStream tcp = streams.get(frame.streamId);
      if (tcp != null) {
        if (frame.type == Mux.DATA) {
          int length = frame.payload.readableBytes();
          tcp.channel
              .writeAndFlush(frame.payload.retainedSlice())
              .addListener(
                  f -> {
                    if (f.isSuccess() && tcp.mux == ctx.channel() && tcp.channel.isActive())
                      tcp.windowCredit.add(length);
                    else if (!f.isSuccess()) closeLocal(tcp.id, true);
                  });
        } else if (frame.type == Mux.WINDOW) {
          int credit = frame.payload.readInt();
          synchronized (tcp.pending) {
            if (tcp.sendCreditLimit == 0) {
              if (credit < Mux.MIN_FLOW_WINDOW_BYTES || credit > Mux.MAX_FLOW_WINDOW_BYTES) {
                ctx.close();
                return;
              }
              tcp.sendCreditLimit = credit;
              tcp.sendCredit = credit;
            } else if (credit <= 0 || credit > tcp.sendCreditLimit - tcp.sendCredit) {
              ctx.close();
              return;
            } else {
              tcp.sendCredit += credit;
            }
            flushPending(tcp);
            tcp.channel.config().setAutoRead(
                tcp.pending.isEmpty() && tcp.sendCredit > 0 && tcp.mux.isWritable());
          }
        }
        else if (frame.type == Mux.CLOSE) closeLocal(frame.streamId, false);
        return;
      }
      UdpLocalStream udp = udpStreams.get(frame.streamId);
      if (udp == null) return;
      if (frame.type == Mux.DATA) sendUdp(udp, frame.payload);
      else if (frame.type == Mux.UDP_BATCH) forwardUdpBatch(udp, frame.payload, ctx);
      else if (frame.type == Mux.CLOSE) closeUdp(frame.streamId, false);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      muxes.remove(ctx.channel());
      for (LocalStream stream : new ArrayList<>(streams.values()))
        if (stream.mux == ctx.channel()) stream.channel.close();
      for (UdpLocalStream stream : new ArrayList<>(udpStreams.values()))
        if (stream.mux == ctx.channel()) closeUdp(stream.id, false);
      if (!stopped && control != null && control.isActive()) scheduleMuxRetry();
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
      if (!ctx.channel().isWritable()) {
        for (LocalStream stream : streams.values())
          if (stream.mux == ctx.channel()) stream.channel.config().setAutoRead(false);
      } else {
        // Do not drain inline from a write-completion callback: previously submitted
        // cross-event-loop writes may still be queued and must stay ahead of this data.
        ctx.executor().execute(() -> {
          for (LocalStream stream : streams.values()) {
            if (stream.mux != ctx.channel()) continue;
            synchronized (stream.pending) {
              flushPending(stream);
              stream.channel.config().setAutoRead(
                  stream.pending.isEmpty() && stream.sendCredit > 0 && ctx.channel().isWritable());
            }
          }
          for (UdpLocalStream stream : udpStreams.values())
            if (stream.mux == ctx.channel()
                || (udpMuxStriping && isUdpDataMux(ctx.channel())))
              scheduleUdpMuxDrain(stream, ctx.channel());
        });
      }
      ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }
  }

  private final class LocalTcpHandler extends SimpleChannelInboundHandler<ByteBuf> {
    private final int id;

    LocalTcpHandler(int id) {
      this.id = id;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf message) {
      sendData(id, message);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      closeLocal(id, true);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }
  }

  private final class LocalUdpHandler extends SimpleChannelInboundHandler<DatagramPacket> {
    private final UdpLocalStream stream;
    private Mux.DatagramBatch batch;

    LocalUdpHandler(UdpLocalStream stream) {
      this.stream = stream;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
      if (collectUdpPerfStats) {
        ByteBuf content = packet.content();
        int index = content.readerIndex();
        if (content.readableBytes() >= 32 && content.getInt(index) == TEST_UDP_PERF_MAGIC) {
          long sentAtNanos = content.getLong(index + 24);
          long receivedAtNanos = System.nanoTime();
          long delayNanos = receivedAtNanos - sentAtNanos;
          if (sentAtNanos > 0 && delayNanos >= 0) {
            udpLocalUdpReadDelayNanos.addAndGet(delayNanos);
            udpLocalUdpReadSamples.incrementAndGet();
            udpLocalUdpReadMaxNanos.accumulateAndGet(delayNanos, Math::max);
            if (content.readableBytes() >= 48) content.setLong(index + 32, receivedAtNanos);
          }
        }
      }
      Channel primaryMux = stream.mux;
      if (primaryMux == null || !primaryMux.isActive()) return;
      if (batch == null) batch = new Mux.DatagramBatch(ctx.alloc());
      int length = packet.content().readableBytes();
      if (!batch.canAdd(length)) flushBatch();
      if (batch == null) batch = new Mux.DatagramBatch(ctx.alloc());
      if (batch.canAdd(length)) batch.add(packet.content());
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
      flushBatch();
      ctx.fireChannelReadComplete();
    }

    private void flushBatch() {
      if (batch == null) return;
      ByteBuf payload = batch.take();
      batch.release();
      batch = null;
      if (payload == null) return;
      Channel primaryMux = stream.mux;
      if (primaryMux == null || !primaryMux.isActive()) {
        payload.release();
        return;
      }
      Channel mux = udpMuxStriping ? selectUdpDataMux() : primaryMux;
      sendUdpMuxBatch(stream, mux, payload);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      if (batch != null) batch.release();
      closeUdp(stream.id, true);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }
  }

  private void flushPending(LocalStream stream) {
    synchronized (stream.pending) {
      while (!stream.pending.isEmpty() && stream.mux.isWritable() && stream.sendCredit > 0) {
        ByteBuf bytes = stream.pending.peekFirst();
        int sent = Math.min(bytes.readableBytes(), stream.sendCredit);
        Mux.sendData(stream.mux, stream.id, bytes, sent);
        bytes.skipBytes(sent);
        stream.pendingBytes -= sent;
        stream.sendCredit -= sent;
        if (!bytes.isReadable()) stream.pending.removeFirst().release();
      }
    }
  }

  private void closeLocal(int id, boolean notify) {
    LocalStream stream = streams.remove(id);
    if (stream == null) return;
    receiveWindowReserved.addAndGet(-stream.receiveWindowGrant);
    synchronized (stream.pending) {
      while (!stream.pending.isEmpty()) stream.pending.removeFirst().release();
      stream.pendingBytes = 0;
    }
    if (notify && stream.mux != null && stream.mux.isActive())
      stream.mux.writeAndFlush(new Mux.Frame(id, Mux.CLOSE, new byte[0]));
    stream.channel.close();
  }

  private void closeUdp(int id, boolean notify) {
    UdpLocalStream stream = udpStreams.remove(id);
    if (stream == null) return;
    activeUdpStreams.decrementAndGet();
    synchronized (stream.pending) {
      udpPendingBytes.addAndGet(-stream.pendingBytes);
      while (!stream.pending.isEmpty()) stream.pending.removeFirst().release();
      stream.pendingBytes = 0;
    }
    discardUdpMuxPending(stream, false);
    discardLocalUdpPending(stream, false);
    if (notify && stream.mux != null && stream.mux.isActive())
      stream.mux.writeAndFlush(new Mux.Frame(id, Mux.CLOSE, new byte[0]));
    if (stream.channel != null) stream.channel.close();
  }

  private static boolean reserve(AtomicInteger counter, int amount, int limit) {
    for (;;) {
      int current = counter.get();
      if (amount > limit - current) return false;
      if (counter.compareAndSet(current, current + amount)) return true;
    }
  }

  private static int reserveWindow(AtomicInteger counter, int requested, int limit) {
    for (;;) {
      int current = counter.get();
      int grant = Math.min(requested, limit - current);
      if (grant < Mux.MIN_FLOW_WINDOW_BYTES) return 0;
      if (counter.compareAndSet(current, current + grant)) return grant;
    }
  }

  private static final class LocalStream {
    final int id;
    final Channel channel;
    final Channel mux;
    final Deque<ByteBuf> pending = new ArrayDeque<>();
    int pendingBytes;
    int sendCredit;
    int sendCreditLimit;
    final int receiveWindowGrant;
    final Mux.WindowCredit windowCredit;

    LocalStream(int id, Channel channel, Channel mux, int receiveWindowGrant) {
      this.id = id;
      this.channel = channel;
      this.mux = mux;
      this.receiveWindowGrant = receiveWindowGrant;
      this.windowCredit = new Mux.WindowCredit(mux, id);
    }
  }

  private static final class UdpLocalStream {
    final int id;
    final Settings.Rule rule;
    final InetSocketAddress target;
    final Deque<ByteBuf> pending = new ArrayDeque<>();
    int pendingBytes;
    final Deque<PendingLocalUdpBatch> localEgressPending = new ArrayDeque<>();
    int localEgressPendingBytes;
    int localEgressPendingDatagrams;
    final AtomicBoolean localEgressDrainScheduled = new AtomicBoolean();
    final Deque<PendingMuxBatch> muxPending = new ArrayDeque<>();
    final AtomicBoolean muxDrainScheduled = new AtomicBoolean();
    int muxPendingBytes;
    volatile Channel channel;
    volatile Channel mux;

    UdpLocalStream(int id, Settings.Rule rule) {
      this.id = id;
      this.rule = rule;
      this.target = new InetSocketAddress(rule.localHost, rule.localPort);
    }
  }

  private static final class PendingMuxBatch {
    final ByteBuf payload;
    final long queuedAtNanos;

    PendingMuxBatch(ByteBuf payload, long queuedAtNanos) {
      this.payload = payload;
      this.queuedAtNanos = queuedAtNanos;
    }
  }

  private static final class PendingLocalUdpBatch {
    final ByteBuf payload;
    final int datagramBytes;
    final int datagrams;
    final long queuedAtNanos;

    PendingLocalUdpBatch(ByteBuf payload, int datagramBytes, int datagrams) {
      this.payload = payload;
      this.datagramBytes = datagramBytes;
      this.datagrams = datagrams;
      this.queuedAtNanos = System.nanoTime();
    }
  }

  @Override
  public void close() {
    stopped = true;
    if (control != null) control.close();
    for (Channel mux : new ArrayList<>(muxes)) mux.close();
    for (LocalStream stream : streams.values()) stream.channel.close();
    for (UdpLocalStream stream : new ArrayList<>(udpStreams.values())) closeUdp(stream.id, false);
    group.shutdownGracefully();
    udpGroup.shutdownGracefully();
    healthExecutor.shutdownNow();
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("Usage: Client <client.properties>");
    Client client = new Client(args[0]);
    Runtime.getRuntime().addShutdownHook(new Thread(client::close));
    client.start();
  }
}
