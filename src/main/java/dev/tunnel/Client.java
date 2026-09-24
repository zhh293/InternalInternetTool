package dev.tunnel;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
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
import java.io.IOException;
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

/** Inner-network agent. One TLS mux work channel carries all TCP and UDP streams. */
public final class Client implements AutoCloseable {
  private final Settings settings;
  private final String token;
  private final String clientId;
  private final String serverHost;
  private final ConcurrentMap<String, Settings.Rule> rules;
  private final ConcurrentMap<String, Long> healthNext = new ConcurrentHashMap<>();
  private final SslContext ssl;
  private final EventLoopGroup group = new io.netty.channel.nio.NioEventLoopGroup();
  private final Map<Integer, LocalStream> streams = new ConcurrentHashMap<>();
  private final Map<Integer, UdpLocalStream> udpStreams = new ConcurrentHashMap<>();
  private final Map<Integer, String> waitingOpens = new ConcurrentHashMap<>();
  private final AtomicBoolean reconnectScheduled = new AtomicBoolean();
  private final AtomicBoolean muxRetryScheduled = new AtomicBoolean();
  private final int muxPoolSize;
  private final int maxPendingBytes;
  private final ScheduledExecutorService healthExecutor =
      Executors.newSingleThreadScheduledExecutor(
          runnable -> {
            Thread thread = new Thread(runnable, "tunnel-health-check");
            thread.setDaemon(true);
            return thread;
          });
  private final java.util.concurrent.atomic.AtomicInteger nextMux =
      new java.util.concurrent.atomic.AtomicInteger();
  private volatile Channel control;
  private final java.util.Set<Channel> muxes = ConcurrentHashMap.newKeySet();
  private volatile boolean stopped;
  private volatile int retrySeconds = 1;
  private volatile int muxRetrySeconds = 1;

  public Client(String configPath) throws Exception {
    this.settings = Settings.load(configPath);
    String tokenFile = settings.optional("clientTokenFile", "");
    this.token =
        tokenFile.isEmpty() ? settings.secret("tokenFile") : Settings.readSecretFile(tokenFile);
    this.clientId = settings.required("clientId");
    Wire.validateName(clientId);
    this.serverHost = settings.required("serverHost");
    this.rules = new ConcurrentHashMap<>(settings.rules());
    this.muxPoolSize = settings.optionalPositive("muxPoolSize", 1, 1, 32);
    this.maxPendingBytes =
        settings.optionalPositive("maxPendingBytes", 8 * 1024 * 1024, 64 * 1024, 256 * 1024 * 1024);
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
      return true;
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

  private void connectMux() {
    if (stopped || control == null || !control.isActive() || activeMuxCount() >= muxPoolSize)
      return;
    socketBootstrap(
            new ChannelInitializer<SocketChannel>() {
              @Override
              protected void initChannel(SocketChannel channel) {
                channel
                    .pipeline()
                    .addLast(
                        "ssl",
                        ssl.newHandler(channel.alloc(), serverHost, settings.port("workPort")));
                channel.pipeline().addLast("lines", new LineBasedFrameDecoder(4096));
                channel.pipeline().addLast("mux-login", new MuxLoginHandler());
              }
            },
            true)
        .connect(serverHost, settings.port("workPort"))
        .addListener(
            (ChannelFuture result) -> {
              if (!result.isSuccess()) scheduleMuxRetry();
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
              connectMux();
            },
            delay,
            TimeUnit.SECONDS);
  }

  private int activeMuxCount() {
    int count = 0;
    for (Channel channel : muxes) if (channel.isActive()) count++;
    return count;
  }

  private Channel selectMux() {
    List<Channel> active = new ArrayList<>();
    for (Channel channel : muxes)
      if (channel.isActive() && channel.isWritable()) active.add(channel);
    if (active.isEmpty()) return null;
    return active.get(Math.floorMod(nextMux.getAndIncrement(), active.size()));
  }

  private void sendData(int id, byte[] bytes) {
    LocalStream tcp = streams.get(id);
    UdpLocalStream udp = udpStreams.get(id);
    Channel channel = tcp != null ? tcp.mux : udp == null ? null : udp.mux;
    if (channel == null || !channel.isActive()) return;
    if (!channel.isWritable() && tcp != null) {
      synchronized (tcp.pending) {
        if (tcp.pendingBytes + bytes.length > maxPendingBytes) {
          tcp.channel.close();
          return;
        }
        tcp.pending.addLast(bytes.clone());
        tcp.pendingBytes += bytes.length;
        tcp.channel.config().setAutoRead(false);
      }
      return;
    }
    for (int offset = 0; offset < bytes.length; offset += Mux.MAX_PAYLOAD) {
      int length = Math.min(Mux.MAX_PAYLOAD, bytes.length - offset);
      byte[] part = new byte[length];
      System.arraycopy(bytes, offset, part, 0, length);
      channel.writeAndFlush(new Mux.Frame(id, Mux.DATA, part));
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
              LocalStream stream = new LocalStream(id, result.channel(), channel);
              streams.put(id, stream);
              result.channel().closeFuture().addListener(f -> closeLocal(id, false));
              channel.writeAndFlush(new Mux.Frame(id, Mux.ACK, new byte[0]));
              result.channel().config().setAutoRead(true);
            });
  }

  private void openUdp(int id, String ruleName, Channel muxChannel) {
    Settings.Rule rule = rules.get(ruleName);
    if (rule == null || rule.kind != Settings.Rule.Kind.UDP) {
      sendFail(id);
      return;
    }
    if (udpStreams.containsKey(id)) return;
    UdpLocalStream stream = new UdpLocalStream(id, rule);
    udpStreams.put(id, stream);
    new Bootstrap()
        .group(group)
        .channel(NioDatagramChannel.class)
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
                udpStreams.remove(id, stream);
                sendFail(id);
                return;
              }
              stream.channel = result.channel();
              result.channel().closeFuture().addListener(f -> closeUdp(id, false));
              stream.mux = muxChannel;
              if (muxChannel != null && muxChannel.isActive())
                muxChannel.writeAndFlush(new Mux.Frame(id, Mux.ACK, new byte[0]));
              synchronized (stream.pending) {
                for (byte[] packet : stream.pending) sendUdp(stream, packet);
                stream.pending.clear();
              }
              result.channel().config().setAutoRead(true);
            });
  }

  private void sendUdp(UdpLocalStream stream, byte[] data) {
    if (stream.channel != null && stream.channel.isActive()) {
      stream.channel.writeAndFlush(
          new DatagramPacket(
              Unpooled.wrappedBuffer(data),
              new InetSocketAddress(stream.rule.localHost, stream.rule.localPort)));
    } else stream.pending.add(data);
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
            connectMux();
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
      for (UdpLocalStream stream : udpStreams.values())
        if (stream.channel != null) stream.channel.close();
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
    @Override
    public void channelActive(ChannelHandlerContext ctx) {
      SslHandler tls = ctx.pipeline().get(SslHandler.class);
      tls.handshakeFuture()
          .addListener(
              result -> {
                if (result.isSuccess())
                  Wire.send(
                      ctx.channel(), "MUX " + Wire.PROTOCOL_VERSION + " " + clientId + " " + token);
                else ctx.close();
              });
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf message) {
      String line = Wire.readLine(message);
      String[] words = line.split(" ");
      if (words.length == 2
          && "MUX_OK".equals(words[0])
          && String.valueOf(Wire.PROTOCOL_VERSION).equals(words[1])) {
        muxes.add(ctx.channel());
        ctx.pipeline().remove("lines");
        ctx.pipeline().replace(this, "mux-decoder", new Mux.Decoder());
        ctx.pipeline().addLast("mux-encoder", new Mux.Encoder());
        ctx.pipeline().addLast("mux-keepalive", new Mux.KeepaliveHandler());
        ctx.pipeline().addLast("mux", new MuxClientHandler());
        muxRetrySeconds = 1;
        flushWaiting();
        connectMux();
      } else {
        ctx.close();
      }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      muxes.remove(ctx.channel());
      if (!stopped && control != null && control.isActive()) scheduleMuxRetry();
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
        openUdp(frame.streamId, new String(frame.payload, StandardCharsets.UTF_8), ctx.channel());
        return;
      }
      LocalStream tcp = streams.get(frame.streamId);
      if (tcp != null) {
        if (frame.type == Mux.DATA)
          tcp.channel.writeAndFlush(Unpooled.wrappedBuffer(frame.payload));
        else if (frame.type == Mux.CLOSE) closeLocal(frame.streamId, false);
        return;
      }
      UdpLocalStream udp = udpStreams.get(frame.streamId);
      if (udp == null) return;
      if (frame.type == Mux.DATA) sendUdp(udp, frame.payload);
      else if (frame.type == Mux.CLOSE) closeUdp(frame.streamId, false);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      muxes.remove(ctx.channel());
      for (LocalStream stream : new ArrayList<>(streams.values()))
        if (stream.mux == ctx.channel()) stream.channel.close();
      for (UdpLocalStream stream : udpStreams.values())
        if (stream.mux == ctx.channel() && stream.channel != null) stream.channel.close();
      if (!stopped && control != null && control.isActive()) scheduleMuxRetry();
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
      boolean writable = ctx.channel().isWritable();
      for (LocalStream stream : streams.values()) {
        if (stream.mux != ctx.channel()) continue;
        if (writable) flushPending(stream);
        stream.channel.config().setAutoRead(writable);
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
      byte[] bytes = new byte[message.readableBytes()];
      message.readBytes(bytes);
      sendData(id, bytes);
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

    LocalUdpHandler(UdpLocalStream stream) {
      this.stream = stream;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
      byte[] bytes = new byte[packet.content().readableBytes()];
      packet.content().getBytes(packet.content().readerIndex(), bytes);
      sendData(stream.id, bytes);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      closeUdp(stream.id, true);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }
  }

  private void flushPending(LocalStream stream) {
    synchronized (stream.pending) {
      while (!stream.pending.isEmpty() && stream.mux.isWritable()) {
        byte[] bytes = stream.pending.removeFirst();
        stream.pendingBytes -= bytes.length;
        for (int offset = 0; offset < bytes.length; offset += Mux.MAX_PAYLOAD) {
          int length = Math.min(Mux.MAX_PAYLOAD, bytes.length - offset);
          byte[] part = new byte[length];
          System.arraycopy(bytes, offset, part, 0, length);
          stream.mux.writeAndFlush(new Mux.Frame(stream.id, Mux.DATA, part));
        }
      }
    }
  }

  private void closeLocal(int id, boolean notify) {
    LocalStream stream = streams.remove(id);
    if (stream == null) return;
    if (notify && stream.mux != null && stream.mux.isActive())
      stream.mux.writeAndFlush(new Mux.Frame(id, Mux.CLOSE, new byte[0]));
    stream.channel.close();
  }

  private void closeUdp(int id, boolean notify) {
    UdpLocalStream stream = udpStreams.remove(id);
    if (stream == null) return;
    if (notify && stream.mux != null && stream.mux.isActive())
      stream.mux.writeAndFlush(new Mux.Frame(id, Mux.CLOSE, new byte[0]));
    if (stream.channel != null) stream.channel.close();
  }

  private static final class LocalStream {
    final int id;
    final Channel channel;
    final Channel mux;
    final Deque<byte[]> pending = new ArrayDeque<>();
    int pendingBytes;

    LocalStream(int id, Channel channel, Channel mux) {
      this.id = id;
      this.channel = channel;
      this.mux = mux;
    }
  }

  private static final class UdpLocalStream {
    final int id;
    final Settings.Rule rule;
    final java.util.List<byte[]> pending =
        java.util.Collections.synchronizedList(new java.util.ArrayList<>());
    volatile Channel channel;
    volatile Channel mux;

    UdpLocalStream(int id, Settings.Rule rule) {
      this.id = id;
      this.rule = rule;
    }
  }

  @Override
  public void close() {
    stopped = true;
    if (control != null) control.close();
    for (Channel mux : new ArrayList<>(muxes)) mux.close();
    for (LocalStream stream : streams.values()) stream.channel.close();
    for (UdpLocalStream stream : udpStreams.values())
      if (stream.channel != null) stream.channel.close();
    group.shutdownGracefully();
    healthExecutor.shutdownNow();
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("Usage: Client <client.properties>");
    Client client = new Client(args[0]);
    Runtime.getRuntime().addShutdownHook(new Thread(client::close));
    client.start();
  }
}
