package dev.tunnel;

import com.sun.net.httpserver.HttpServer;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.traffic.ChannelTrafficShapingHandler;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.ImmediateEventExecutor;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Public endpoint and control-plane server. A client owns one TLS mux channel. */
public final class Server implements AutoCloseable {
  private static final int TEST_UDP_PERF_MAGIC = 0x54554E4C;
  private static final int MAX_UDP_STREAMS_PER_CLIENT = 512;
  private static final int MAX_UDP_PENDING_PER_STREAM = 256 * 1024;
  private static final int MAX_UDP_PENDING_PER_CLIENT = 8 * 1024 * 1024;
  private static final int MAX_UDP_OUTBOUND_PER_STREAM = 512 * 1024;
  private static final int MAX_UDP_OUTBOUND_DATAGRAMS = 2048;
  private static final int MAX_UDP_EGRESS_QUEUED_DATAGRAMS = 65536;
  private static final int MAX_UDP_EGRESS_BATCHES_PER_TURN = 16;
  private static final long MAX_UDP_EGRESS_QUEUE_AGE_NANOS =
      TimeUnit.MILLISECONDS.toNanos(
          Math.max(1L, Long.getLong("tunnel.test.udpQueueMaxAgeMillis", 100L)));
  private static final long UDP_IDLE_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(120);
  private final Settings settings;
  private final byte[] password;
  private final Map<String, byte[]> clientTokens;
  private final Metrics metrics = new Metrics();
  private final String managementToken;
  private final SslContext ssl;
  private final EventLoopGroup acceptors = new NioEventLoopGroup(1);
  private final EventLoopGroup workers = new NioEventLoopGroup();
  private final EventLoopGroup udpWorkers;
  private final Map<String, Session> sessions = new ConcurrentHashMap<>();
  private final Map<Integer, PortGroup> ports = new ConcurrentHashMap<>();
  private final Map<String, List<Binding>> httpRoutes = new ConcurrentHashMap<>();
  private final String dynamicStoreFile;
  private volatile Map<String, Map<String, DynamicStore.Spec>> dynamicMappings;
  private final int muxPoolSize;
  private final int udpMuxPoolSize;
  private final int maxPendingBytes;
  private final int flowWindowBytes;
  private final int maxFlowWindowBytes;
  private final int udpSocketBufferBytes;
  private final int udpMuxWriteBufferHighWaterMarkBytes;
  private final boolean udpMuxStriping;
  private final boolean collectUdpPerfStats =
      Boolean.parseBoolean(System.getProperty("tunnel.test.collectUdpPerfStats", "false"));
  private final boolean consolidateFlushOutsideRead;
  private final boolean tcpNoDelay;
  private final AtomicInteger httpRoundRobin = new AtomicInteger();
  private Channel controlListener;
  private Channel workListener;
  private Channel httpListener;
  private Channel httpsListener;
  private HttpServer management;

  public Server(String configPath) throws Exception {
    this.settings = Settings.load(configPath);
    int defaultUdpIoThreads =
        Math.max(1, Math.min(8, Runtime.getRuntime().availableProcessors() / 2));
    this.udpWorkers =
        new NioEventLoopGroup(
            settings.optionalPositive("udpIoThreads", defaultUdpIoThreads, 1, 32));
    this.consolidateFlushOutsideRead = settings.consolidateFlushOutsideRead();
    this.tcpNoDelay = settings.optionalBoolean("tcpNoDelay", true);
    String credentialsFile = settings.optional("clientsFile", "");
    if (credentialsFile.isEmpty()) {
      this.password = settings.secret("tokenFile").getBytes(StandardCharsets.UTF_8);
      this.clientTokens = Collections.emptyMap();
    } else {
      this.password = null;
      this.clientTokens = Settings.loadCredentials(credentialsFile);
    }
    String managementTokenFile = settings.optional("managementTokenFile", "");
    this.managementToken =
        managementTokenFile.isEmpty() ? null : Settings.readSecretFile(managementTokenFile);
    String managementHost = settings.optional("managementBindHost", "127.0.0.1");
    if (managementToken == null && !isLoopbackHost(managementHost)) {
      throw new IllegalArgumentException(
          "managementTokenFile is required when managementBindHost is not loopback");
    }
    this.ssl =
        SslContextBuilder.forServer(
                Path.of(settings.required("certFile")).toFile(),
                Path.of(settings.required("keyFile")).toFile())
            .protocols("TLSv1.3", "TLSv1.2")
            .build();
    if (settings.port("allowedPortStart") > settings.port("allowedPortEnd")) {
      throw new IllegalArgumentException("Invalid allowed port range");
    }
    this.dynamicStoreFile = settings.optional("storeFile", "");
    this.dynamicMappings = DynamicStore.load(dynamicStoreFile);
    this.muxPoolSize = settings.optionalPositive("muxPoolSize", 1, 1, 32);
    this.udpMuxPoolSize = settings.optionalPositive("udpMuxPoolSize", 1, 0, 32);
    this.udpMuxStriping =
        settings.optionalBoolean("udpMuxStriping", false) && udpMuxPoolSize > 1;
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
        settings.optionalPositive("udpSocketBufferBytes", 1024 * 1024, 64 * 1024, 16 * 1024 * 1024);
    this.udpMuxWriteBufferHighWaterMarkBytes =
        settings.optionalPositive(
            "udpMuxWriteBufferHighWaterMarkBytes", 8 * 1024 * 1024, 64 * 1024, 16 * 1024 * 1024);
  }

  public void start() throws Exception {
    controlListener =
        new ServerBootstrap()
            .group(acceptors, workers)
            .channel(NioServerSocketChannel.class)
            .childOption(ChannelOption.TCP_NODELAY, tcpNoDelay)
            .childOption(
                ChannelOption.WRITE_BUFFER_WATER_MARK,
                new io.netty.channel.WriteBufferWaterMark(2 * 1024 * 1024, 8 * 1024 * 1024))
            .childHandler(
                new ChannelInitializer<SocketChannel>() {
                  @Override
                  protected void initChannel(SocketChannel channel) {
                    channel.pipeline().addLast("ssl", ssl.newHandler(channel.alloc()));
                    channel.pipeline().addLast("idle", new IdleStateHandler(60, 0, 0));
                    channel.pipeline().addLast("lines", new LineBasedFrameDecoder(4096));
                    channel.pipeline().addLast("control", new ControlHandler());
                  }
                })
            .bind(settings.optional("bindHost", "0.0.0.0"), settings.port("controlPort"))
            .sync()
            .channel();
    try {
      workListener =
          new ServerBootstrap()
              .group(acceptors, workers)
              .channel(NioServerSocketChannel.class)
              .childOption(ChannelOption.TCP_NODELAY, tcpNoDelay)
              .childOption(
                  ChannelOption.WRITE_BUFFER_WATER_MARK,
                  new io.netty.channel.WriteBufferWaterMark(
                      2 * 1024 * 1024, 8 * 1024 * 1024))
              .childHandler(
                  new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) {
                      channel.pipeline().addLast("ssl", ssl.newHandler(channel.alloc()));
                      channel.pipeline().addLast("timeout", new ReadTimeoutHandler(15));
                      channel.pipeline().addLast("lines", new LineBasedFrameDecoder(4096));
                      channel.pipeline().addLast("mux-login", new MuxLoginHandler());
                    }
                  })
              .bind(settings.optional("bindHost", "0.0.0.0"), settings.port("workPort"))
              .sync()
              .channel();
      int httpPort = settings.optionalPort("httpPort", 0);
      if (httpPort > 0) {
        httpListener =
            new ServerBootstrap()
                .group(acceptors, workers)
                .channel(NioServerSocketChannel.class)
                .childOption(ChannelOption.TCP_NODELAY, tcpNoDelay)
                .childHandler(
                    new ChannelInitializer<SocketChannel>() {
                      @Override
                      protected void initChannel(SocketChannel channel) {
                        channel.pipeline().addLast("flush", Mux.flushConsolidator(consolidateFlushOutsideRead));
                        channel.pipeline().addLast("http", new HttpPublicHandler());
                      }
                    })
                .bind(
                    settings.optional(
                        "httpBindHost", settings.optional("publicBindHost", "0.0.0.0")),
                    httpPort)
                .sync()
                .channel();
      }
      int httpsPort = settings.optionalPort("httpsPort", 0);
      if (httpsPort > 0) {
        httpsListener =
            new ServerBootstrap()
                .group(acceptors, workers)
                .channel(NioServerSocketChannel.class)
                .childOption(ChannelOption.TCP_NODELAY, tcpNoDelay)
                .childHandler(
                    new ChannelInitializer<SocketChannel>() {
                      @Override
                      protected void initChannel(SocketChannel channel) {
                        channel.pipeline().addLast("ssl", ssl.newHandler(channel.alloc()));
                        channel.pipeline().addLast("flush", Mux.flushConsolidator(consolidateFlushOutsideRead));
                        channel.pipeline().addLast("https", new HttpPublicHandler(true));
                      }
                    })
                .bind(
                    settings.optional(
                        "httpsBindHost", settings.optional("publicBindHost", "0.0.0.0")),
                    httpsPort)
                .sync()
                .channel();
      }
      int managementPort = settings.optionalPort("managementPort", 8088);
      management =
          Management.start(
              this,
              settings.optional("managementBindHost", "127.0.0.1"),
              managementPort,
              managementToken);
    } catch (Exception error) {
      close();
      throw error;
    }
    System.out.println(
        "Server ready: control="
            + settings.port("controlPort")
            + " work="
            + settings.port("workPort")
            + (httpListener == null ? "" : " http=" + settings.optionalPort("httpPort", 0))
            + (httpsListener == null ? "" : " https=" + settings.optionalPort("httpsPort", 0))
            + " management="
            + settings.optionalPort("managementPort", 8088));
  }

  private ServerBootstrap tcpBootstrap(PortGroup group) {
    return new ServerBootstrap()
        .group(acceptors, workers)
        .channel(NioServerSocketChannel.class)
        .childOption(ChannelOption.TCP_NODELAY, tcpNoDelay)
        .childOption(ChannelOption.AUTO_READ, true)
        .childHandler(
            new ChannelInitializer<SocketChannel>() {
              @Override
              protected void initChannel(SocketChannel channel) {
                Binding binding = chooseBinding(group);
                if (binding == null) {
                  channel.close();
                  return;
                }
                if (binding.bandwidthBytesPerSecond > 0)
                  channel
                      .pipeline()
                      .addLast(
                          "traffic",
                          new ChannelTrafficShapingHandler(
                              binding.bandwidthBytesPerSecond,
                              binding.bandwidthBytesPerSecond,
                              1000));
                channel.pipeline().addLast("flush", Mux.flushConsolidator(consolidateFlushOutsideRead));
                channel.pipeline().addLast(new PublicHandler(group, binding));
              }
            });
  }

  private void registerTcp(Session owner, String name, int port, boolean udp, String[] command) {
    if (port < settings.port("allowedPortStart") || port > settings.port("allowedPortEnd")) {
      Wire.send(
          owner.channel,
          (udp ? "REGISTER_UDP_FAIL " : "REGISTER_FAIL ") + name + " port_not_allowed");
      return;
    }
    if (owner.bindings.size() >= 128 || owner.bindings.containsKey(name)) {
      Wire.send(
          owner.channel,
          (udp ? "REGISTER_UDP_FAIL " : "REGISTER_FAIL ") + name + " duplicate_or_limit");
      return;
    }
    Binding binding =
        new Binding(owner, name, udp ? Settings.Rule.Kind.UDP : Settings.Rule.Kind.TCP, port);
    configureBinding(binding, command, 3);
    PortGroup group = ports.get(port);
    if (group != null
        && (group.kind != binding.kind
            || binding.balanceGroup.isEmpty()
            || !binding.balanceGroup.equals(group.balanceGroup)
            || !binding.balanceKey.equals(group.balanceKey))) {
      Wire.send(
          owner.channel, (udp ? "REGISTER_UDP_FAIL " : "REGISTER_FAIL ") + name + " port_in_use");
      return;
    }
    if (group == null) {
      group = new PortGroup(port, binding.kind, binding.balanceGroup, binding.balanceKey);
      ports.put(port, group);
    }
    binding.group = group;
    group.bindings.add(binding);
    PortGroup selectedGroup = group;
    owner.bindings.put(name, binding);
    if (group.listener != null && group.listener.isActive()) {
      binding.listener = group.listener;
      binding.ready = true;
      Wire.send(owner.channel, (udp ? "REGISTER_UDP_OK " : "REGISTER_OK ") + name);
      return;
    }
    if (udp) {
      new Bootstrap()
          .group(udpWorkers)
          .channel(NioDatagramChannel.class)
          .option(ChannelOption.SO_RCVBUF, udpSocketBufferBytes)
          .option(ChannelOption.SO_SNDBUF, udpSocketBufferBytes)
          .option(
              ChannelOption.WRITE_BUFFER_WATER_MARK,
              new io.netty.channel.WriteBufferWaterMark(256 * 1024, 1024 * 1024))
          .option(ChannelOption.RCVBUF_ALLOCATOR, new io.netty.channel.FixedRecvByteBufAllocator(65536))
          .handler(
              new ChannelInitializer<DatagramChannel>() {
                @Override
                protected void initChannel(DatagramChannel channel) {
                  channel.pipeline().addLast(new UdpPublicHandler(selectedGroup));
                }
              })
          .bind(settings.optional("publicBindHost", "0.0.0.0"), port)
          .addListener(
              (ChannelFuture result) ->
                  registrationResult(selectedGroup, owner, binding, result, true));
    } else {
      tcpBootstrap(selectedGroup)
          .bind(settings.optional("publicBindHost", "0.0.0.0"), port)
          .addListener(
              (ChannelFuture result) ->
                  registrationResult(selectedGroup, owner, binding, result, false));
    }
  }

  private void registrationResult(
      PortGroup group, Session owner, Binding binding, ChannelFuture result, boolean udp) {
    if (result.isSuccess() && owner.channel.isActive()) {
      binding.listener = result.channel();
      group.listener = result.channel();
      for (Binding member : group.bindings) member.listener = result.channel();
      binding.ready = true;
      Wire.send(owner.channel, (udp ? "REGISTER_UDP_OK " : "REGISTER_OK ") + binding.name);
      System.out.println(
          "Mapped "
              + owner.id
              + "/"
              + binding.name
              + " on "
              + binding.port
              + (udp ? "/udp" : "/tcp"));
    } else {
      if (result.isSuccess()) result.channel().close();
      owner.bindings.remove(binding.name, binding);
      ports.remove(binding.port, group);
      if (owner.channel.isActive())
        Wire.send(
            owner.channel,
            (udp ? "REGISTER_UDP_FAIL " : "REGISTER_FAIL ") + binding.name + " bind_failed");
    }
  }

  private void registerHttp(Session owner, String[] command) {
    String name = command[1];
    String hostList = command[2];
    Binding binding = new Binding(owner, name, Settings.Rule.Kind.HTTP, 0);
    configureBinding(binding, command, 3);
    if (owner.bindings.size() >= 128 || owner.bindings.containsKey(name)) {
      Wire.send(owner.channel, "REGISTER_HTTP_FAIL " + name + " duplicate_or_limit");
      return;
    }
    List<String> hosts = new ArrayList<>();
    for (String raw : hostList.split("\\|")) hosts.add(Settings.normalizeHost(raw));
    if (hosts.isEmpty()) throw new IllegalArgumentException("HTTP host required");
    for (String host : hosts) {
      List<Binding> routes =
          httpRoutes.computeIfAbsent(
              host, ignored -> Collections.synchronizedList(new ArrayList<>()));
      synchronized (routes) {
        if (!routes.isEmpty()
            && (binding.balanceGroup.isEmpty()
                || !binding.balanceGroup.equals(routes.get(0).balanceGroup)
                || !binding.balanceKey.equals(routes.get(0).balanceKey))) {
          for (String added : hosts) {
            List<Binding> addedRoutes = httpRoutes.get(added);
            if (addedRoutes != null) {
              addedRoutes.remove(binding);
              if (addedRoutes.isEmpty()) httpRoutes.remove(added, addedRoutes);
            }
          }
          Wire.send(owner.channel, "REGISTER_HTTP_FAIL " + name + " host_in_use");
          return;
        }
        routes.add(binding);
      }
    }
    binding.hosts.addAll(hosts);
    binding.ready = true;
    owner.bindings.put(name, binding);
    Wire.send(owner.channel, "REGISTER_HTTP_OK " + name);
    System.out.println("HTTP route " + String.join(",", hosts) + " -> " + owner.id + "/" + name);
  }

  private static void applyRule(Binding binding, Settings.Rule rule) {
    binding.locations.addAll(rule.locations);
    binding.hostRewrite = rule.hostRewrite;
    binding.basicUser = rule.basicUser;
    binding.basicPassword = rule.basicPassword;
    binding.balanceGroup = rule.balanceGroup;
    binding.balanceKey = rule.balanceKey;
    binding.bandwidthBytesPerSecond = rule.bandwidthBytesPerSecond;
    binding.healthCheck = rule.healthCheck;
    if (rule.healthCheck != null) binding.healthy = false;
  }

  private static void configureBinding(Binding binding, String[] command, int offset) {
    if (command.length == offset) return;
    int expected = binding.kind == Settings.Rule.Kind.HTTP ? 8 : 4;
    if (command.length != offset + expected)
      throw new IllegalArgumentException("Invalid rule metadata");
    if (binding.kind == Settings.Rule.Kind.HTTP) {
      if (!"-".equals(command[offset]))
        for (String location : command[offset].split("\\|")) binding.locations.add(location);
      binding.hostRewrite = dash(command[offset + 1]);
      binding.basicUser = dash(command[offset + 2]);
      binding.basicPassword = dash(command[offset + 3]);
      binding.balanceGroup = dash(command[offset + 4]);
      binding.balanceKey = dash(command[offset + 5]);
      binding.bandwidthBytesPerSecond = Integer.parseInt(command[offset + 6]);
      binding.healthCheck = Settings.parseHealthSpec(command[offset + 7], "health");
    } else {
      binding.balanceGroup = dash(command[offset]);
      binding.balanceKey = dash(command[offset + 1]);
      binding.bandwidthBytesPerSecond = Integer.parseInt(command[offset + 2]);
      binding.healthCheck = Settings.parseHealthSpec(command[offset + 3], "health");
    }
    if (binding.healthCheck != null) binding.healthy = false;
  }

  private static String dash(String value) {
    return "-".equals(value) ? "" : value;
  }

  private static Binding chooseBinding(PortGroup group) {
    List<Binding> candidates = new ArrayList<>();
    synchronized (group.bindings) {
      for (Binding binding : group.bindings)
        if (!binding.closed.get() && binding.ready && binding.healthy) candidates.add(binding);
    }
    if (candidates.isEmpty()) return null;
    return candidates.get(Math.floorMod(group.next.getAndIncrement(), candidates.size()));
  }

  private Binding chooseHttpBinding(String host, String path) {
    List<Binding> routes = httpRoutes.get(Settings.normalizeHost(host));
    if (routes == null) return null;
    List<Binding> candidates = new ArrayList<>();
    synchronized (routes) {
      for (Binding binding : routes)
        if (!binding.closed.get()
            && binding.ready
            && binding.healthy
            && matchesLocation(binding, path)) candidates.add(binding);
    }
    if (candidates.isEmpty()) return null;
    return candidates.get(Math.floorMod(httpRoundRobin.incrementAndGet(), candidates.size()));
  }

  private static boolean matchesLocation(Binding binding, String path) {
    if (binding.locations.isEmpty()) return true;
    for (String location : binding.locations)
      if (path.equals(location)
          || path.startsWith(location.endsWith("/") ? location : location + "/")) return true;
    return false;
  }

  private void removeBinding(Binding binding) {
    binding.closed.set(true);
    binding.owner.bindings.remove(binding.name, binding);
    if (binding.port > 0 && binding.group == null && binding.listener != null)
      binding.listener.close();
    for (String host : binding.hosts) {
      List<Binding> routes = httpRoutes.get(host);
      if (routes != null) {
        routes.remove(binding);
        if (routes.isEmpty()) httpRoutes.remove(host, routes);
      }
    }
    if (binding.group != null) {
      binding.group.bindings.remove(binding);
      if (binding.group.bindings.isEmpty()) {
        ports.remove(binding.port, binding.group);
        if (binding.group.listener != null) binding.group.listener.close();
      }
    }
    for (Stream stream : new ArrayList<>(binding.streams.values())) closeStream(stream, true);
    for (UdpStream stream : new ArrayList<>(binding.udpStreams.values())) closeUdpStream(stream);
  }

  private Stream startStream(Binding binding, Channel visitor, ByteBuf initial) {
    Session owner = binding.owner;
    if (!owner.channel.isActive() || owner.streams.size() >= 2000) {
      ReferenceCountUtil.release(initial);
      visitor.close();
      return null;
    }
    int id = nextId(owner);
    Stream stream = new Stream(id, owner, binding, visitor);
    stream.initial = initial;
    owner.streams.put(id, stream);
    binding.streams.put(id, stream);
    metrics.streamsOpened.incrementAndGet();
    owner.channels.add(visitor);
    visitor.closeFuture().addListener(f -> closeStream(stream, false));
    visitor.config().setAutoRead(false);
    Wire.send(owner.channel, "OPEN " + id + " " + binding.name);
    stream.timer =
        visitor.eventLoop().schedule(() -> closeStream(stream, true), 10, TimeUnit.SECONDS);
    return stream;
  }

  // Consumes message; retained views are owned by the queue or outbound pipeline.
  private void forwardPublic(Stream stream, ByteBuf message) {
    try {
      synchronized (stream.pending) {
        if (stream.closed.get() || (stream.ready && (stream.mux == null || !stream.mux.isActive())))
          return;
        int length = message.readableBytes();
        metrics.bytesFromPublic.add(length);
        int direct =
            stream.ready && stream.mux.isWritable() && stream.pending.isEmpty()
                ? Math.min(length, stream.sendCredit)
                : 0;
        int queued = length - direct;
        if (stream.pendingBytes + queued > maxPendingBytes) {
          closeStream(stream, true);
          return;
        }
        if (direct > 0) {
          Mux.sendData(stream.mux, stream.id, message, direct);
          stream.sendCredit -= direct;
        }
        if (queued > 0) {
          stream.pending.addLast(message.retainedSlice(message.readerIndex() + direct, queued));
          stream.pendingBytes += queued;
          stream.visitor.config().setAutoRead(false);
        }
        if (!stream.pending.isEmpty() && stream.ready && stream.mux.isWritable()) {
          flushPending(stream);
        }
        stream.visitor.config().setAutoRead(
            stream.pending.isEmpty() && stream.sendCredit > 0 && stream.mux.isWritable());
      }
    } finally {
      ReferenceCountUtil.release(message);
    }
  }

  private void flushPending(Stream stream) {
    synchronized (stream.pending) {
      while (!stream.pending.isEmpty()
          && stream.mux != null
          && stream.mux.isWritable()
          && stream.sendCredit > 0) {
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

  private void closeStream(Stream stream, boolean notify) {
    if (!stream.closed.compareAndSet(false, true)) return;
    synchronized (stream.pending) {
      while (!stream.pending.isEmpty()) stream.pending.removeFirst().release();
      stream.pendingBytes = 0;
      ReferenceCountUtil.release(stream.initial);
      stream.initial = null;
    }
    stream.owner.streams.remove(stream.id, stream);
    stream.binding.streams.remove(stream.id, stream);
    if (stream.receiveWindowGrant > 0)
      stream.owner.receiveWindowReserved.addAndGet(-stream.receiveWindowGrant);
    metrics.streamsClosed.incrementAndGet();
    if (stream.timer != null) stream.timer.cancel(false);
    if (notify && stream.mux != null && stream.mux.isActive())
      Mux.sendClose(stream.mux, stream.id);
    if (stream.visitor != null) stream.visitor.close();
  }

  private void onMuxFrame(Session owner, Channel mux, Mux.Frame frame) {
    Stream stream = owner.streams.get(frame.streamId);
    if (stream == null) {
      UdpStream udp = owner.udpStreams.get(frame.streamId);
      if (udp == null || udp.closed.get()) return;
      boolean primaryMux = udp.mux == mux;
      if (!primaryMux
          && (!udpMuxStriping || !owner.isUdpMuxChannel(mux))) return;
      if (frame.type == Mux.ACK) {
        if (!primaryMux) return;
        synchronized (udp.pending) {
          if (udp.closed.get()) return;
          udp.ready = true;
          flushUdpPending(udp);
        }
      } else if (frame.type == Mux.DATA
          && udp.binding.listener != null
          && udp.binding.listener.isWritable()) {
        metrics.bytesToPublic.add(frame.payload.readableBytes());
        udp.binding.listener.writeAndFlush(
            new DatagramPacket(frame.payload.retainedSlice(), udp.visitor));
      } else if (frame.type == Mux.UDP_BATCH && udp.binding.listener != null) {
        if (!forwardUdpBatch(udp.binding.listener, udp, frame.payload)) mux.close();
      } else if (frame.type == Mux.CLOSE && primaryMux) closeUdpStream(udp);
      return;
    }
    if (stream.closed.get()) return;
    if (frame.type == Mux.ACK) {
      synchronized (stream.pending) {
        if (stream.closed.get()) return;
        stream.mux = mux;
        stream.windowCredit = new Mux.WindowCredit(mux, stream.id);
        if (frame.payload.readableBytes() != Integer.BYTES) {
          mux.close();
          return;
        }
        int clientWindow = frame.payload.readInt();
        if (clientWindow < Mux.MIN_FLOW_WINDOW_BYTES
            || clientWindow > Mux.MAX_FLOW_WINDOW_BYTES) {
          mux.close();
          return;
        }
        stream.sendCredit = clientWindow;
        stream.sendCreditLimit = clientWindow;
        int serverGrant =
            reserveWindow(owner.receiveWindowReserved, flowWindowBytes, maxFlowWindowBytes);
        if (serverGrant == 0) {
          closeStream(stream, true);
          return;
        }
        stream.receiveWindowGrant = serverGrant;
        stream.ready = true;
        Mux.sendWindow(mux, stream.id, serverGrant);
        if (stream.timer != null) stream.timer.cancel(false);
        if (stream.initial != null) {
          ByteBuf initial = stream.initial;
          stream.initial = null;
          try {
            int direct = mux.isWritable()
                ? Math.min(initial.readableBytes(), stream.sendCredit)
                : 0;
            int queued = initial.readableBytes() - direct;
            if (stream.pendingBytes + queued > maxPendingBytes) {
              closeStream(stream, true);
              return;
            }
            if (direct > 0) {
              Mux.sendData(mux, stream.id, initial, direct);
              stream.sendCredit -= direct;
            }
            if (queued > 0) {
              stream.pending.addFirst(
                  initial.retainedSlice(initial.readerIndex() + direct, queued));
              stream.pendingBytes += queued;
            }
          } finally {
            initial.release();
          }
        }
        flushPending(stream);
        stream.visitor.config().setAutoRead(
            stream.pending.isEmpty() && stream.sendCredit > 0 && mux.isWritable());
      }
    } else if (frame.type == Mux.WINDOW) {
      int credit = frame.payload.readInt();
      synchronized (stream.pending) {
        if (stream.closed.get()) return;
        if (credit <= 0 || credit > stream.sendCreditLimit - stream.sendCredit) {
          mux.close();
          return;
        }
        stream.sendCredit += credit;
        flushPending(stream);
        stream.visitor.config().setAutoRead(
            stream.pending.isEmpty() && stream.sendCredit > 0 && mux.isWritable());
      }
    } else if (frame.type == Mux.DATA) {
      if (stream.binding.kind == Settings.Rule.Kind.UDP) {
        if (stream.binding.listener != null && stream.visitorAddress != null) {
          metrics.bytesToPublic.add(frame.payload.readableBytes());
          stream.binding.listener.writeAndFlush(
              new DatagramPacket(frame.payload.retainedSlice(), stream.visitorAddress));
        }
      } else if (stream.visitor.isActive()) {
        int length = frame.payload.readableBytes();
        metrics.bytesToPublic.add(length);
        stream.visitor
            .writeAndFlush(frame.payload.retainedSlice())
            .addListener(
                f -> {
                  if (f.isSuccess() && stream.mux == mux && !stream.closed.get())
                    stream.windowCredit.add(length);
                  else if (!f.isSuccess()) closeStream(stream, true);
                });
      }
    } else if (frame.type == Mux.CLOSE) closeStream(stream, false);
  }

  private boolean forwardUdpBatch(Channel listener, UdpStream stream, ByteBuf payload) {
    int cursor = payload.readerIndex();
    int end = payload.writerIndex();
    int datagramBytes = 0;
    int datagrams = 0;
    while (cursor < end) {
      if (end - cursor < Short.BYTES) return false;
      int length = payload.getUnsignedShort(cursor);
      cursor += Short.BYTES;
      if (length > end - cursor) return false;
      if (collectUdpPerfStats
          && length >= 48
          && payload.getInt(cursor) == TEST_UDP_PERF_MAGIC
          && payload.getLong(cursor + 32) > 0) {
        payload.setLong(cursor + 40, System.nanoTime());
      }
      cursor += length;
      datagramBytes += length;
      datagrams++;
    }
    UdpPublicHandler dispatcher = listener.pipeline().get(UdpPublicHandler.class);
    if (dispatcher == null) return false;
    dispatcher.enqueueEgress(stream, payload.retainedSlice(), datagramBytes, datagrams);
    return true;
  }

  private void writePublicUdpBatch(Channel listener, UdpStream stream, ByteBuf batch) {
    // Submission and write-completion callbacks both run on this listener's EventLoop.
    if (!listener.eventLoop().inEventLoop())
      throw new IllegalStateException("UDP batch writes must run on the listener EventLoop");
    while (batch.isReadable()) {
      int length = batch.readUnsignedShort();
      ByteBuf datagram = batch.readRetainedSlice(length);
      if (stream.closed.get() || !listener.isActive()) {
        datagram.release();
        stream.binding.owner.udpPendingBytes.addAndGet(-length);
        continue;
      }
      if (stream.outboundPendingCount < MAX_UDP_OUTBOUND_DATAGRAMS
          && length <= MAX_UDP_OUTBOUND_PER_STREAM - stream.outboundPendingBytes) {
        stream.outboundPendingCount++;
        stream.outboundPendingBytes += length;
        boolean sampleWrite = (stream.outboundWriteSequence++ & 63) == 0;
        long submittedAtNanos = sampleWrite ? System.nanoTime() : 0;
        listener.write(new DatagramPacket(datagram, stream.visitor))
            .addListener(
                result -> {
                  metrics.recordUdpEgressWrite(
                      sampleWrite,
                      sampleWrite ? System.nanoTime() - submittedAtNanos : 0);
                  stream.outboundPendingCount--;
                  stream.outboundPendingBytes -= length;
                  stream.binding.owner.udpPendingBytes.addAndGet(-length);
                  if (result.isSuccess()) metrics.bytesToPublic.add(length);
                  else metrics.udpDropped.increment();
                });
      } else {
        metrics.udpDropped.increment();
        stream.binding.owner.udpPendingBytes.addAndGet(-length);
        datagram.release();
      }
    }
  }

  private final class ControlHandler extends SimpleChannelInboundHandler<ByteBuf> {
    private Session owner;

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf message) {
      String[] words = Wire.readLine(message).split(" ");
      try {
        if (words.length == 0) throw new IllegalArgumentException("Empty command");
        if (owner == null) {
          hello(ctx, words);
          return;
        }
        switch (words[0]) {
          case "REGISTER":
            if (words.length != 3 && words.length != 7)
              throw new IllegalArgumentException("Expected REGISTER name port");
            Wire.validateName(words[1]);
            registerTcp(owner, words[1], Settings.parsePort(words[2], "remotePort"), false, words);
            break;
          case "REGISTER_UDP":
            if (words.length != 3 && words.length != 7)
              throw new IllegalArgumentException("Expected REGISTER_UDP name port");
            Wire.validateName(words[1]);
            registerTcp(owner, words[1], Settings.parsePort(words[2], "remotePort"), true, words);
            break;
          case "REGISTER_HTTP":
            if (words.length != 3 && words.length != 11)
              throw new IllegalArgumentException("Expected REGISTER_HTTP name hosts");
            Wire.validateName(words[1]);
            registerHttp(owner, words);
            break;
          case "UNREGISTER":
            if (words.length != 2) throw new IllegalArgumentException("Expected UNREGISTER name");
            Binding removed = owner.bindings.get(words[1]);
            if (removed != null) removeBinding(removed);
            break;
          case "FAIL":
            if (words.length != 2)
              throw new IllegalArgumentException("Expected FAIL streamId");
            int failedId;
            try {
              failedId = Integer.parseInt(words[1]);
            } catch (NumberFormatException error) {
              throw new IllegalArgumentException("Invalid streamId");
            }
            if (failedId <= 0) throw new IllegalArgumentException("Invalid streamId");
            Stream failedStream = owner.streams.get(failedId);
            if (failedStream != null) closeStream(failedStream, false);
            UdpStream failedUdp = owner.udpStreams.get(failedId);
            if (failedUdp != null) closeUdpStream(failedUdp);
            break;
          case "PING":
            Wire.send(ctx.channel(), "PONG");
            break;
          case "HEALTH":
            if (words.length != 3)
              throw new IllegalArgumentException("Expected HEALTH name status");
            Binding healthBinding = owner.bindings.get(words[1]);
            if (healthBinding != null && healthBinding.healthCheck != null) {
              if ("1".equals(words[2])) {
                healthBinding.healthFailures = 0;
                healthBinding.healthy = true;
              } else {
                healthBinding.healthFailures++;
                healthBinding.healthy =
                    healthBinding.healthFailures < healthBinding.healthCheck.maxFailed;
              }
            }
            break;
          default:
            throw new IllegalArgumentException("Unknown command");
        }
      } catch (IllegalArgumentException e) {
        Wire.sendError(ctx.channel(), errorCode(e), e.getMessage());
        ctx.close();
      }
    }

    private void hello(ChannelHandlerContext ctx, String[] words) {
      if (words.length != 4 || !"HELLO".equals(words[0]))
        throw new IllegalArgumentException("Expected HELLO version clientId token");
      if (!String.valueOf(Wire.PROTOCOL_VERSION).equals(words[1]))
        throw new IllegalArgumentException("Protocol_version_mismatch");
      Wire.validateName(words[2]);
      byte[] expected = clientTokens.isEmpty() ? password : clientTokens.get(words[2]);
      if (expected == null
          || !MessageDigest.isEqual(expected, words[3].getBytes(StandardCharsets.UTF_8))) {
        metrics.authFailures.incrementAndGet();
        throw new IllegalArgumentException("Authentication_failed");
      }
      Session candidate = new Session(words[2], ctx.channel(), expected, udpMuxPoolSize > 0);
      if (sessions.putIfAbsent(candidate.id, candidate) != null)
        throw new IllegalArgumentException("Client_already_connected");
      owner = candidate;
      Wire.send(ctx.channel(), "HELLO_OK " + Wire.PROTOCOL_VERSION);
      Map<String, DynamicStore.Spec> stored = dynamicMappings.get(candidate.id);
      if (stored != null)
        for (DynamicStore.Spec spec : stored.values())
          Wire.send(ctx.channel(), "CONFIG_ADD " + spec.encode());
      System.out.println("Client online: " + candidate.id);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      if (owner != null) {
        sessions.remove(owner.id, owner);
        for (Binding binding : new ArrayList<>(owner.bindings.values())) removeBinding(binding);
        for (Channel mux : owner.muxes) mux.close();
        owner.channels.close();
        System.out.println("Client offline: " + owner.id);
      }
      ctx.fireChannelInactive();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object event) {
      if (event instanceof IdleStateEvent) ctx.close();
      else ctx.fireUserEventTriggered(event);
    }
  }

  // ACK can release a burst of queued datagrams. Preserve their order and batch
  // them without adding a timer or per-datagram flush.
  private void flushUdpPending(UdpStream stream) {
    Channel mux = stream.mux;
    Mux.DatagramBatch batch = new Mux.DatagramBatch(mux.alloc());
    try {
      while (!stream.pending.isEmpty()) {
        ByteBuf packet = stream.pending.removeFirst();
        int length = packet.readableBytes();
        try {
          if (mux.isActive()) {
            if (!batch.canAdd(length)) Mux.sendUdpBatch(mux, stream.id, batch.take());
            batch.add(packet);
          }
        } finally {
          packet.release();
          stream.pendingBytes -= length;
          stream.binding.owner.udpPendingBytes.addAndGet(-length);
        }
      }
      if (mux.isActive() && !batch.isEmpty()) Mux.sendUdpBatch(mux, stream.id, batch.take());
    } finally {
      batch.release();
    }
  }

  private final class MuxLoginHandler extends SimpleChannelInboundHandler<ByteBuf> {
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf message) {
      String[] words = Wire.readLine(message).split(" ");
      try {
        if (words.length != 5 || !"MUX".equals(words[0]))
          throw new IllegalArgumentException("Expected MUX version role clientId token");
        if (!String.valueOf(Wire.PROTOCOL_VERSION).equals(words[1]))
          throw new IllegalArgumentException("Protocol_version_mismatch");
        boolean udp;
        if ("UDP".equals(words[2])) udp = true;
        else if ("TCP".equals(words[2])) udp = false;
        else throw new IllegalArgumentException("Invalid_mux_role");
        Session owner = sessions.get(words[3]);
        if (owner == null
            || !MessageDigest.isEqual(owner.token, words[4].getBytes(StandardCharsets.UTF_8))) {
          metrics.authFailures.incrementAndGet();
          throw new IllegalArgumentException("Authentication_failed");
        }
        if (udp) {
          int high = udpMuxWriteBufferHighWaterMarkBytes;
          ctx.channel().config().setWriteBufferWaterMark(
              new io.netty.channel.WriteBufferWaterMark(Math.min(high / 4, high - 1), high));
        }
        synchronized (owner) {
          Set<Channel> rolePool = udp ? owner.udpMuxes : owner.tcpMuxes;
          int roleLimit = udp ? udpMuxPoolSize : muxPoolSize;
          if (roleLimit == 0 || rolePool.size() >= roleLimit)
            throw new IllegalArgumentException("Mux_pool_full");
          owner.muxes.add(ctx.channel());
          rolePool.add(ctx.channel());
          if (!udp) owner.primaryMux = ctx.channel();
        }
        metrics.muxConnections.incrementAndGet();
        Wire.send(ctx.channel(), "MUX_OK " + Wire.PROTOCOL_VERSION + " " + words[2]);
        ctx.pipeline().remove("timeout");
        ctx.pipeline().remove("lines");
        ctx.pipeline().replace(this, "mux-decoder", new Mux.Decoder());
        ctx.pipeline().addBefore("mux-decoder", "flush", Mux.flushConsolidator(consolidateFlushOutsideRead));
        ctx.pipeline().addLast("mux-encoder", new Mux.Encoder());
        ctx.pipeline().addLast("mux-keepalive", new Mux.KeepaliveHandler());
        ctx.pipeline().addLast("mux", new MuxServerHandler(owner));
      } catch (IllegalArgumentException error) {
        Wire.sendError(ctx.channel(), errorCode(error), error.getMessage());
        ctx.close();
      }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }
  }

  private final class MuxServerHandler extends SimpleChannelInboundHandler<Mux.Frame> {
    private final Session owner;

    MuxServerHandler(Session owner) {
      this.owner = owner;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Mux.Frame frame) {
      onMuxFrame(owner, ctx.channel(), frame);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      if (owner.muxes.remove(ctx.channel())) {
        owner.tcpMuxes.remove(ctx.channel());
        owner.udpMuxes.remove(ctx.channel());
        if (owner.primaryMux == ctx.channel()) owner.primaryMux = owner.selectMux(false);
        metrics.muxConnections.decrementAndGet();
      }
      for (Stream stream : new ArrayList<>(owner.streams.values()))
        if (stream.mux == ctx.channel()) closeStream(stream, false);
      for (UdpStream stream : new ArrayList<>(owner.udpStreams.values()))
        if (stream.mux == ctx.channel()) closeUdpStream(stream);
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
      if (!ctx.channel().isWritable()) {
        for (Stream stream : owner.streams.values())
          if (stream.mux == ctx.channel()) stream.visitor.config().setAutoRead(false);
      } else {
        // Do not drain inline from a write-completion callback: previously submitted
        // cross-event-loop writes may still be queued and must stay ahead of this data.
        ctx.executor().execute(() -> {
          for (Stream stream : owner.streams.values()) {
            if (stream.mux != ctx.channel()) continue;
            synchronized (stream.pending) {
              flushPending(stream);
              stream.visitor.config().setAutoRead(
                  stream.pending.isEmpty()
                      && stream.sendCredit > 0
                      && ctx.channel().isWritable());
            }
          }
        });
      }
      ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }
  }

  private final class PublicHandler extends ChannelInboundHandlerAdapter {
    private final PortGroup group;
    private final Binding binding;
    private Stream stream;

    PublicHandler(PortGroup group, Binding binding) {
      this.group = group;
      this.binding = binding;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
      stream = startStream(binding, ctx.channel(), null);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object message) {
      if (stream != null) forwardPublic(stream, (ByteBuf) message);
      else ReferenceCountUtil.release(message);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      if (stream != null) closeStream(stream, true);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }
  }

  private final class HttpPublicHandler extends ChannelInboundHandlerAdapter {
    private static final int MAX_HEADER_BYTES = 64 * 1024;
    private final boolean https;
    private ByteArrayOutputStream head = new ByteArrayOutputStream();
    private Stream stream;
    private boolean routed;
    private boolean rejected;
    private String sniHost;
    private ScheduledFuture<?> headerTimeout;
    private int headerTerminatorState;

    HttpPublicHandler() {
      this(false);
    }

    HttpPublicHandler(boolean https) {
      this.https = https;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
      headerTimeout =
          ctx.executor().schedule(
              () -> {
                if (!routed && ctx.channel().isActive())
                  httpError(ctx, 408, "Request Timeout");
              },
              15,
              TimeUnit.SECONDS);
      ctx.fireChannelActive();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object message) {
      ByteBuf buffer = (ByteBuf) message;
      try {
        if (rejected) return;
        if (routed) {
          if (stream != null) forwardPublic(stream, buffer.retainedSlice());
          return;
        }
        boolean headersComplete = false;
        while (buffer.isReadable()) {
          byte value = buffer.readByte();
          head.write(value);
          if (head.size() > MAX_HEADER_BYTES) {
            httpError(ctx, 431, "Request Header Fields Too Large");
            return;
          }
          if (headerTerminatorState == 0) headerTerminatorState = value == '\r' ? 1 : 0;
          else if (headerTerminatorState == 1)
            headerTerminatorState = value == '\n' ? 2 : value == '\r' ? 1 : 0;
          else if (headerTerminatorState == 2)
            headerTerminatorState = value == '\r' ? 3 : 0;
          else headerTerminatorState = value == '\n' ? 4 : value == '\r' ? 1 : 0;
          if (headerTerminatorState == 4) {
            headersComplete = true;
            break;
          }
        }
        if (!headersComplete) return;
        String text = head.toString(StandardCharsets.ISO_8859_1);
        String host = null;
        for (String line : text.split("\\r\\n")) {
          int colon = line.indexOf(':');
          if (colon > 0 && "host".equalsIgnoreCase(line.substring(0, colon).trim()))
            host = line.substring(colon + 1).trim();
        }
        String requestLine = text.substring(0, text.indexOf("\r\n"));
        String[] requestWords = requestLine.split(" ", 3);
        String path = requestWords.length > 1 ? requestWords[1] : "/";
        if ((host == null || host.isEmpty()) && https) host = sniHost;
        if (host == null || host.isEmpty()) {
          httpError(ctx, 400, "Host header required");
          return;
        }
        int colon = host.lastIndexOf(':');
        if (colon > 0 && host.indexOf(']') < colon) host = host.substring(0, colon);
        Binding binding = chooseHttpBinding(host, path);
        if (binding == null) {
          httpError(ctx, 404, "Unknown host route");
          return;
        }
        if (!binding.basicUser.isEmpty()) {
          String authorization = header(text, "authorization");
          String expected =
              "Basic "
                  + Base64.getEncoder()
                      .encodeToString(
                          (binding.basicUser + ":" + binding.basicPassword)
                              .getBytes(StandardCharsets.ISO_8859_1));
          if (!expected.equals(authorization)) {
            rejected = true;
            if (headerTimeout != null) headerTimeout.cancel(false);
            ctx.writeAndFlush(
                    Unpooled.wrappedBuffer(
                        ("HTTP/1.1 401 Unauthorized\r\n"
                             + "WWW-Authenticate: Basic realm=\"tunnel\"\r\n"
                             + "Connection: close\r\n"
                             + "Content-Length: 0\r\n\r\n")
                            .getBytes(StandardCharsets.ISO_8859_1)))
                .addListener(f -> ctx.close());
            return;
          }
        }
        routed = true;
        if (headerTimeout != null) headerTimeout.cancel(false);
        head = null;
        if (binding.bandwidthBytesPerSecond > 0 && ctx.pipeline().get("traffic") == null)
          ctx.pipeline()
              .addFirst(
                  "traffic",
                  new ChannelTrafficShapingHandler(
                      binding.bandwidthBytesPerSecond, binding.bandwidthBytesPerSecond, 1000));
        stream = startStream(binding, ctx.channel(), prepareRequest(text, binding, ctx, buffer));
      } finally {
        ReferenceCountUtil.release(message);
      }
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object event) {
      if (https && event instanceof SslHandshakeCompletionEvent) {
        SslHandshakeCompletionEvent handshake = (SslHandshakeCompletionEvent) event;
        if (handshake.isSuccess()) {
          try {
            javax.net.ssl.SSLSession session =
                ctx.pipeline().get("ssl") instanceof io.netty.handler.ssl.SslHandler
                    ? ((io.netty.handler.ssl.SslHandler) ctx.pipeline().get("ssl"))
                        .engine()
                        .getSession()
                    : null;
            if (session instanceof javax.net.ssl.ExtendedSSLSession)
              for (javax.net.ssl.SNIServerName name :
                  ((javax.net.ssl.ExtendedSSLSession) session).getRequestedServerNames())
                if (name.getType() == 0)
                  sniHost = new String(name.getEncoded(), StandardCharsets.US_ASCII).toLowerCase();
          } catch (RuntimeException ignored) {
            // Host routing still works when the TLS provider does not expose SNI.
          }
        }
      }
      ctx.fireUserEventTriggered(event);
    }

    private void httpError(ChannelHandlerContext ctx, int code, String reason) {
      if (rejected) return;
      rejected = true;
      if (headerTimeout != null) headerTimeout.cancel(false);
      byte[] body = (code + " " + reason + "\n").getBytes(StandardCharsets.UTF_8);
      String response =
          "HTTP/1.1 "
              + code
              + " "
              + reason
              + "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
              + body.length
              + "\r\nConnection: close\r\n\r\n";
      ctx.writeAndFlush(
              Unpooled.wrappedBuffer(concat(response.getBytes(StandardCharsets.ISO_8859_1), body)))
          .addListener(f -> ctx.close());
    }

    private String header(String text, String name) {
      for (String line : text.split("\\r\\n")) {
        int colon = line.indexOf(':');
        if (colon > 0 && name.equalsIgnoreCase(line.substring(0, colon).trim()))
          return line.substring(colon + 1).trim();
      }
      return null;
    }

    private ByteBuf prepareRequest(String request, Binding binding, ChannelHandlerContext ctx,
        ByteBuf body) {
      String[] lines = request.substring(0, request.length() - 4).split("\\r\\n");
      String forwarded =
          "X-Forwarded-For: "
              + ((InetSocketAddress) ctx.channel().remoteAddress()).getAddress().getHostAddress();
      StringBuilder rebuilt = new StringBuilder();
      for (String line : lines) {
        int colon = line.indexOf(':');
        String name = colon > 0 ? line.substring(0, colon).trim() : "";
        if ("x-forwarded-for".equalsIgnoreCase(name)) continue;
        if ("host".equalsIgnoreCase(name) && !binding.hostRewrite.isEmpty())
          line = "Host: " + binding.hostRewrite;
        rebuilt.append(line).append("\r\n");
      }
      rebuilt.append(forwarded).append("\r\n\r\n");
      byte[] headers = rebuilt.toString().getBytes(StandardCharsets.ISO_8859_1);
      if (!body.isReadable()) return Unpooled.wrappedBuffer(headers);
      return ctx.alloc().compositeBuffer(2)
          .addComponents(true, Unpooled.wrappedBuffer(headers), body.retainedSlice());
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      if (headerTimeout != null) headerTimeout.cancel(false);
      if (stream != null) closeStream(stream, true);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      ctx.close();
    }
  }

  private final class UdpPublicHandler extends SimpleChannelInboundHandler<DatagramPacket> {
    private final PortGroup group;
    private final Map<UdpStream, Mux.DatagramBatch> batches = new HashMap<>();
    private final ConcurrentLinkedQueue<UdpEgressWork> egressQueue = new ConcurrentLinkedQueue<>();
    private final AtomicBoolean egressDrainScheduled = new AtomicBoolean();
    private final AtomicInteger queuedEgressDatagrams = new AtomicInteger();
    private final boolean coalesceEgressTasks =
        Boolean.parseBoolean(System.getProperty("tunnel.test.udpEgressCoalescing", "true"));
    private volatile ChannelHandlerContext egressContext;
    private ScheduledFuture<?> expirySweep;

    UdpPublicHandler(PortGroup group) {
      this.group = group;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
      egressContext = ctx;
    }

    private void enqueueEgress(
        UdpStream stream, ByteBuf payload, int datagramBytes, int datagrams) {
      ChannelHandlerContext ctx = egressContext;
      if (ctx == null
          || !ctx.channel().isActive()
          || !reserve(stream.binding.owner.udpPendingBytes, datagramBytes, MAX_UDP_PENDING_PER_CLIENT)) {
        metrics.udpDropped.add(datagrams);
        ReferenceCountUtil.release(payload);
        return;
      }
      if (!reserve(queuedEgressDatagrams, datagrams, MAX_UDP_EGRESS_QUEUED_DATAGRAMS)) {
        stream.binding.owner.udpPendingBytes.addAndGet(-datagramBytes);
        metrics.udpDropped.add(datagrams);
        ReferenceCountUtil.release(payload);
        return;
      }
      egressQueue.offer(new UdpEgressWork(stream, payload, datagramBytes, datagrams));
      if (coalesceEgressTasks) scheduleEgressDrain(ctx);
      else scheduleSingleEgressDrain(ctx);
    }

    private void scheduleSingleEgressDrain(ChannelHandlerContext ctx) {
      try {
        ctx.executor()
            .execute(
                () -> {
                  metrics.udpEgressDrainTasks.incrementAndGet();
                  UdpEgressWork work = egressQueue.poll();
                  if (work != null) {
                    queuedEgressDatagrams.addAndGet(-work.datagrams);
                    processEgressWork(ctx, work);
                    ctx.flush();
                  }
                });
      } catch (java.util.concurrent.RejectedExecutionException closed) {
        discardEgressQueue(true);
      }
    }

    private void scheduleEgressDrain(ChannelHandlerContext ctx) {
      if (!egressDrainScheduled.compareAndSet(false, true)) return;
      try {
        ctx.executor().execute(() -> drainEgress(ctx));
      } catch (java.util.concurrent.RejectedExecutionException closed) {
        egressDrainScheduled.set(false);
        discardEgressQueue(true);
      }
    }

    private void drainEgress(ChannelHandlerContext ctx) {
      metrics.udpEgressDrainTasks.incrementAndGet();
      int drained = 0;
      try {
        UdpEgressWork work;
        while (drained < MAX_UDP_EGRESS_BATCHES_PER_TURN
            && (work = egressQueue.poll()) != null) {
          queuedEgressDatagrams.addAndGet(-work.datagrams);
          processEgressWork(ctx, work);
          drained++;
        }
        if (drained > 0 && ctx.channel().isActive()) ctx.flush();
      } finally {
        egressDrainScheduled.set(false);
        if (!egressQueue.isEmpty()) scheduleEgressDrain(ctx);
      }
    }

    private void processEgressWork(ChannelHandlerContext ctx, UdpEgressWork work) {
      try {
        long queueDelayNanos = System.nanoTime() - work.queuedAtNanos;
        metrics.observeUdpEgressQueueDelay(queueDelayNanos);
        if (queueDelayNanos > MAX_UDP_EGRESS_QUEUE_AGE_NANOS) {
          metrics.udpDropped.add(work.datagrams);
          work.stream.binding.owner.udpPendingBytes.addAndGet(-work.datagramBytes);
        } else {
          writePublicUdpBatch(ctx.channel(), work.stream, work.payload);
        }
      } finally {
        work.payload.release();
      }
    }

    private void discardEgressQueue(boolean countDrops) {
      UdpEgressWork work;
      while ((work = egressQueue.poll()) != null) {
        queuedEgressDatagrams.addAndGet(-work.datagrams);
        work.stream.binding.owner.udpPendingBytes.addAndGet(-work.datagramBytes);
        if (countDrops) metrics.udpDropped.add(work.datagrams);
        work.payload.release();
      }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
      expirySweep =
          ctx.executor().scheduleAtFixedRate(
              () -> {
                long now = System.nanoTime();
                List<Binding> bindings;
                synchronized (group.bindings) {
                  bindings = new ArrayList<>(group.bindings);
                }
                for (Binding binding : bindings) {
                  for (UdpStream stream : binding.udpStreams.values()) {
                    if (now - stream.lastSeen >= UDP_IDLE_TIMEOUT_NANOS)
                      closeUdpStream(stream);
                  }
                }
              },
              5,
              5,
              TimeUnit.SECONDS);
      ctx.fireChannelActive();
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
      InetSocketAddress address = packet.sender();
      InetSocketAddress key = address;
      Binding binding = group.udpAffinity.get(key);
      if (binding == null || binding.closed.get() || !binding.healthy) {
        binding = chooseBinding(group);
        if (binding == null) return;
      }
      UdpStream stream = binding.udpStreams.get(key);
      if (stream == null || stream.closed.get()) {
        Channel mux = binding.owner.selectMux(true);
        if (mux == null || !reserve(binding.owner.activeUdpStreams, 1, MAX_UDP_STREAMS_PER_CLIENT))
          return;
        stream = new UdpStream(nextId(binding.owner), binding, address);
        binding.udpStreams.put(key, stream);
        binding.owner.udpStreams.put(stream.id, stream);
        group.udpAffinity.put(key, binding);
        metrics.streamsOpened.incrementAndGet();
        stream.mux = mux;
        mux.writeAndFlush(
            new Mux.Frame(
                stream.id, Mux.OPEN_UDP, binding.name.getBytes(StandardCharsets.UTF_8)));
      }
      stream.lastSeen = System.nanoTime();
      ByteBuf bytes = packet.content();
      int length = bytes.readableBytes();
      if (!binding.allowDatagram(length)) return;
      metrics.bytesFromPublic.add(length);
      if (stream.closed.get()) return;
      if (stream.ready) {
        addReadyDatagram(ctx, stream, bytes);
        return;
      }
      synchronized (stream.pending) {
        if (stream.closed.get()) return;
        if (!stream.ready) {
          if (stream.pending.size() < Mux.MAX_PENDING_DATAGRAMS
              && stream.pendingBytes + length <= MAX_UDP_PENDING_PER_STREAM
              && reserve(binding.owner.udpPendingBytes, length, MAX_UDP_PENDING_PER_CLIENT)) {
            stream.pending.addLast(Mux.retainDatagramForQueue(bytes));
            stream.pendingBytes += length;
          }
          return;
        }
      }
      addReadyDatagram(ctx, stream, bytes);
    }

    private void addReadyDatagram(ChannelHandlerContext ctx, UdpStream stream, ByteBuf packet) {
      Channel mux = stream.mux;
      if (!stream.closed.get() && mux != null && mux.isActive() && mux.isWritable())
        addToBatch(ctx, stream, packet);
    }

    private void addToBatch(ChannelHandlerContext ctx, UdpStream stream, ByteBuf packet) {
      int length = packet.readableBytes();
      Mux.DatagramBatch batch = batches.get(stream);
      if (batch != null && !batch.canAdd(length)) {
        flushBatch(stream);
        batch = null;
      }
      if (batch == null) {
        batch = new Mux.DatagramBatch(ctx.alloc());
        batches.put(stream, batch);
      }
      batch.add(packet);
    }

    private void flushBatch(UdpStream stream) {
      Mux.DatagramBatch batch = batches.remove(stream);
      flushBatch(stream, batch);
    }

    private void flushBatch(UdpStream stream, Mux.DatagramBatch batch) {
      if (batch == null) return;
      ByteBuf payload = batch.take();
      batch.release();
      if (payload == null) return;
      Channel mux = udpMuxStriping ? stream.binding.owner.selectMux(true) : stream.mux;
      if (!stream.closed.get()
          && stream.ready
          && stream.mux != null
          && stream.mux.isActive()
          && mux != null
          && mux.isActive()
          && mux.isWritable()) {
        if (collectUdpPerfStats) stampUdpPerfMuxWrite(payload, System.nanoTime());
        Mux.sendUdpBatch(mux, stream.id, payload);
      }
      else payload.release();
    }

    private void stampUdpPerfMuxWrite(ByteBuf payload, long timestampNanos) {
      int cursor = payload.readerIndex();
      int end = payload.writerIndex();
      while (cursor < end) {
        int length = payload.getUnsignedShort(cursor);
        cursor += Short.BYTES;
        if (length > end - cursor) return;
        if (length >= 64
            && payload.getInt(cursor) == TEST_UDP_PERF_MAGIC
            && payload.getLong(cursor + 8) > 0) payload.setLong(cursor + 56, timestampNanos);
        cursor += length;
      }
    }

    private void flushBatches() {
      Iterator<Map.Entry<UdpStream, Mux.DatagramBatch>> iterator = batches.entrySet().iterator();
      while (iterator.hasNext()) {
        Map.Entry<UdpStream, Mux.DatagramBatch> entry = iterator.next();
        iterator.remove();
        flushBatch(entry.getKey(), entry.getValue());
      }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
      flushBatches();
      ctx.fireChannelReadComplete();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      if (expirySweep != null) expirySweep.cancel(false);
      egressDrainScheduled.set(false);
      discardEgressQueue(false);
      for (Mux.DatagramBatch batch : batches.values()) batch.release();
      batches.clear();
      List<Binding> bindings;
      synchronized (group.bindings) {
        bindings = new ArrayList<>(group.bindings);
      }
      for (Binding binding : bindings) {
        for (UdpStream stream : binding.udpStreams.values()) {
          if (stream.binding.group == group) closeUdpStream(stream);
        }
      }
    }
  }

  private void closeUdpStream(UdpStream stream) {
    if (!stream.closed.compareAndSet(false, true)) return;
    metrics.streamsClosed.incrementAndGet();
    stream.binding.udpStreams.remove(stream.visitor, stream);
    stream.binding.owner.udpStreams.remove(stream.id, stream);
    stream.binding.owner.activeUdpStreams.decrementAndGet();
    synchronized (stream.pending) {
      stream.binding.owner.udpPendingBytes.addAndGet(-stream.pendingBytes);
      while (!stream.pending.isEmpty()) stream.pending.removeFirst().release();
      stream.pendingBytes = 0;
    }
    if (stream.binding.group != null)
      stream.binding.group.udpAffinity.remove(stream.visitor, stream.binding);
    if (stream.mux != null && stream.mux.isActive())
      Mux.sendClose(stream.mux, stream.id);
  }

  private static int nextId(Session session) {
    int id = session.nextStream.getAndIncrement();
    if (id <= 0) {
      session.nextStream.set(1);
      return session.nextStream.getAndIncrement();
    }
    return id;
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

  private static boolean isLoopbackHost(String host) {
    return "127.0.0.1".equals(host)
        || "localhost".equalsIgnoreCase(host)
        || "::1".equals(host)
        || "0:0:0:0:0:0:0:1".equals(host);
  }

  private static byte[] concat(byte[] left, byte[] right) {
    byte[] out = new byte[left.length + right.length];
    System.arraycopy(left, 0, out, 0, left.length);
    System.arraycopy(right, 0, out, left.length, right.length);
    return out;
  }

  private static final class Stream {
    final int id;
    final Session owner;
    final Binding binding;
    final Channel visitor;
    final AtomicBoolean closed = new AtomicBoolean();
    volatile Channel mux;
    final Deque<ByteBuf> pending = new ArrayDeque<>();
    int pendingBytes;
    int sendCredit;
    int sendCreditLimit;
    int receiveWindowGrant;
    volatile boolean ready;
    volatile Mux.WindowCredit windowCredit;
    volatile ByteBuf initial;
    volatile InetSocketAddress visitorAddress;
    volatile ScheduledFuture<?> timer;

    Stream(int id, Session owner, Binding binding, Channel visitor) {
      this.id = id;
      this.owner = owner;
      this.binding = binding;
      this.visitor = visitor;
    }
  }

  private static final class Session {
    final String id;
    final Channel channel;
    final byte[] token;
    final boolean dedicatedUdpMux;
    final Set<Channel> muxes = ConcurrentHashMap.newKeySet();
    final Set<Channel> tcpMuxes = ConcurrentHashMap.newKeySet();
    final Set<Channel> udpMuxes = ConcurrentHashMap.newKeySet();
    volatile Channel primaryMux;
    final Map<String, Binding> bindings = new ConcurrentHashMap<>();
    final Map<Integer, Stream> streams = new ConcurrentHashMap<>();
    final Map<Integer, UdpStream> udpStreams = new ConcurrentHashMap<>();
    final AtomicInteger activeUdpStreams = new AtomicInteger();
    final AtomicInteger udpPendingBytes = new AtomicInteger();
    final AtomicInteger receiveWindowReserved = new AtomicInteger();
    final ChannelGroup channels = new DefaultChannelGroup(ImmediateEventExecutor.INSTANCE);
    final AtomicInteger nextStream = new AtomicInteger(1);
    final AtomicInteger nextMux = new AtomicInteger();

    Session(String id, Channel channel, byte[] token, boolean dedicatedUdpMux) {
      this.id = id;
      this.channel = channel;
      this.token = token;
      this.dedicatedUdpMux = dedicatedUdpMux;
    }

    Channel selectMux(boolean udp) {
      Set<Channel> pool = udp && dedicatedUdpMux ? udpMuxes : tcpMuxes;
      int eligible = 0;
      for (Channel mux : pool) if (mux.isActive() && mux.isWritable()) eligible++;
      if (eligible == 0) return null;
      int selected = Math.floorMod(nextMux.getAndIncrement(), eligible);
      for (Channel mux : pool) {
        if (mux.isActive() && mux.isWritable() && selected-- == 0) return mux;
      }
      return null;
    }

    boolean isUdpMuxChannel(Channel mux) {
      return (dedicatedUdpMux ? udpMuxes : tcpMuxes).contains(mux);
    }
  }

  private static final class Binding {
    final Session owner;
    final String name;
    final Settings.Rule.Kind kind;
    final int port;
    final List<String> hosts = Collections.synchronizedList(new ArrayList<>());
    final List<String> locations = Collections.synchronizedList(new ArrayList<>());
    final Map<Integer, Stream> streams = new ConcurrentHashMap<>();
    final Map<InetSocketAddress, UdpStream> udpStreams = new ConcurrentHashMap<>();
    final AtomicBoolean closed = new AtomicBoolean();
    volatile String hostRewrite = "";
    volatile String basicUser = "";
    volatile String basicPassword = "";
    volatile String balanceGroup = "";
    volatile String balanceKey = "";
    volatile int bandwidthBytesPerSecond;
    long bandwidthWindowStart;
    long bandwidthWindowBytes;
    volatile Settings.Rule.HealthCheck healthCheck;
    volatile int healthFailures;
    volatile boolean healthy = true;

    synchronized boolean allowDatagram(int bytes) {
      if (bandwidthBytesPerSecond <= 0) return true;
      long now = System.nanoTime();
      if (now - bandwidthWindowStart >= TimeUnit.SECONDS.toNanos(1)) {
        bandwidthWindowStart = now;
        bandwidthWindowBytes = 0;
      }
      if (bandwidthWindowBytes + bytes > bandwidthBytesPerSecond) return false;
      bandwidthWindowBytes += bytes;
      return true;
    }

    volatile boolean ready;
    volatile Channel listener;
    volatile PortGroup group;

    Binding(Session owner, String name, Settings.Rule.Kind kind, int port) {
      this.owner = owner;
      this.name = name;
      this.kind = kind;
      this.port = port;
    }
  }

  private static final class PortGroup {
    final int port;
    final Settings.Rule.Kind kind;
    final String balanceGroup;
    final String balanceKey;
    final List<Binding> bindings = Collections.synchronizedList(new ArrayList<>());
    final Map<InetSocketAddress, Binding> udpAffinity = new ConcurrentHashMap<>();
    final AtomicInteger next = new AtomicInteger();
    volatile Channel listener;

    PortGroup(int port, Settings.Rule.Kind kind, String balanceGroup, String balanceKey) {
      this.port = port;
      this.kind = kind;
      this.balanceGroup = balanceGroup;
      this.balanceKey = balanceKey;
    }
  }

  private static final class UdpStream {
    final int id;
    final Binding binding;
    final InetSocketAddress visitor;
    final AtomicBoolean closed = new AtomicBoolean();
    volatile Channel mux;
    final Deque<ByteBuf> pending = new ArrayDeque<>();
    int pendingBytes;
    // Confined to binding.listener's EventLoop; write completion runs on that loop too.
    int outboundPendingCount;
    int outboundPendingBytes;
    int outboundWriteSequence;
    volatile boolean ready;
    volatile long lastSeen;

    UdpStream(int id, Binding binding, InetSocketAddress visitor) {
      this.id = id;
      this.binding = binding;
      this.visitor = visitor;
      this.lastSeen = System.nanoTime();
    }
  }

  private static final class UdpEgressWork {
    final UdpStream stream;
    final ByteBuf payload;
    final int datagramBytes;
    final int datagrams;
    final long queuedAtNanos;

    UdpEgressWork(UdpStream stream, ByteBuf payload, int datagramBytes, int datagrams) {
      this.stream = stream;
      this.payload = payload;
      this.datagramBytes = datagramBytes;
      this.datagrams = datagrams;
      this.queuedAtNanos = System.nanoTime();
    }
  }

  String statusJson() {
    StringBuilder json =
        new StringBuilder("{\"protocolVersion\":")
            .append(Wire.PROTOCOL_VERSION)
            .append(",\"clients\":[");
    boolean first = true;
    for (Session session : sessions.values()) {
      if (!first) json.append(',');
      first = false;
      json.append("{\"id\":\"")
          .append(escape(session.id))
          .append("\",\"mux\":")
          .append(session.muxes.stream().anyMatch(Channel::isActive))
          .append(",\"muxes\":")
          .append(session.muxes.size())
          .append(",\"tcpMuxes\":")
          .append(session.tcpMuxes.size())
          .append(",\"udpMuxes\":")
          .append(session.udpMuxes.size())
          .append(",\"streams\":")
          .append(session.streams.size() + session.udpStreams.size())
          .append(",\"bindings\":[");
      boolean bindingFirst = true;
      for (Binding binding : session.bindings.values()) {
        if (!bindingFirst) json.append(',');
        bindingFirst = false;
        json.append("{\"name\":\"")
            .append(escape(binding.name))
            .append("\",\"kind\":\"")
            .append(binding.kind)
            .append("\",\"port\":")
            .append(binding.port)
            .append(",\"ready\":")
            .append(binding.ready)
            .append(",\"healthy\":")
            .append(binding.healthy)
            .append(",\"group\":\"")
            .append(escape(binding.balanceGroup))
            .append(",\"hosts\":[");
        for (int i = 0; i < binding.hosts.size(); i++) {
          if (i > 0) json.append(',');
          json.append('"').append(escape(binding.hosts.get(i))).append('"');
        }
        json.append("],\"locations\":[");
        for (int i = 0; i < binding.locations.size(); i++) {
          if (i > 0) json.append(',');
          json.append('"').append(escape(binding.locations.get(i))).append('"');
        }
        json.append("],\"streams\":")
            .append(binding.streams.size() + binding.udpStreams.size())
            .append('}');
      }
      json.append("]}");
    }
    return json.append("]}").toString();
  }

  String prometheus() {
    int activeStreams = 0;
    for (Session session : sessions.values()) {
      activeStreams += session.streams.size() + session.udpStreams.size();
    }
    return metrics.prometheus(sessions.size(), activeStreams);
  }

  boolean disconnect(String clientId) {
    Session session = sessions.get(clientId);
    if (session == null) return false;
    session.channel.close();
    return true;
  }

  synchronized String dynamicBindingsJson(String clientId) {
    Map<String, DynamicStore.Spec> values = dynamicMappings.get(clientId);
    StringBuilder json = new StringBuilder("[");
    boolean first = true;
    if (values != null)
      for (DynamicStore.Spec spec : values.values()) {
        if (!first) json.append(',');
        first = false;
        json.append("{\"name\":\"")
            .append(escape(spec.name))
            .append("\",\"kind\":\"")
            .append(spec.kind)
            .append("\",\"remotePort\":")
            .append(spec.remotePort)
            .append(",\"localHost\":\"")
            .append(escape(spec.localHost))
            .append("\",\"localPort\":")
            .append(spec.localPort)
            .append("}");
      }
    return json.append(']').toString();
  }

  synchronized void addDynamicBinding(String clientId, Map<String, String> form)
      throws IOException {
    Wire.validateName(clientId);
    String name = requiredForm(form, "name");
    Settings.Rule.Kind kind = Settings.Rule.Kind.valueOf(requiredForm(form, "kind").toUpperCase());
    int remotePort = Settings.parsePort(requiredForm(form, "remotePort"), "remotePort");
    String localHost = requiredForm(form, "localHost");
    int localPort = Settings.parsePort(requiredForm(form, "localPort"), "localPort");
    List<String> hosts = splitForm(form.getOrDefault("hosts", ""));
    List<String> locations = splitForm(form.getOrDefault("locations", ""));
    if (kind == Settings.Rule.Kind.HTTP && hosts.isEmpty())
      throw new IllegalArgumentException("hosts is required for HTTP mappings");
    Settings.Rule.HealthCheck health =
        Settings.parseHealthSpec(form.getOrDefault("health", ""), "health");
    DynamicStore.Spec spec =
        new DynamicStore.Spec(
            name,
            kind,
            remotePort,
            localHost,
            localPort,
            hosts,
            locations,
            form.getOrDefault("hostRewrite", ""),
            form.getOrDefault("basicUser", ""),
            form.getOrDefault("basicPassword", ""),
            form.getOrDefault("balanceGroup", ""),
            form.getOrDefault("balanceKey", ""),
            Settings.parseBandwidthSpec(form.getOrDefault("bandwidth", ""), "bandwidth"),
            health);
    Map<String, Map<String, DynamicStore.Spec>> updated = new LinkedHashMap<>(dynamicMappings);
    Map<String, DynamicStore.Spec> values =
        new LinkedHashMap<>(updated.getOrDefault(clientId, Collections.emptyMap()));
    boolean replaced = values.put(name, spec) != null;
    updated.put(clientId, values);
    DynamicStore.save(dynamicStoreFile, updated);
    dynamicMappings = updated;
    Session session = sessions.get(clientId);
    if (session != null) {
      if (replaced) Wire.send(session.channel, "CONFIG_REMOVE " + name);
      Wire.send(session.channel, "CONFIG_ADD " + spec.encode());
    }
  }

  synchronized boolean removeDynamicBinding(String clientId, String name) throws IOException {
    Map<String, DynamicStore.Spec> existing = dynamicMappings.get(clientId);
    if (existing == null || !existing.containsKey(name)) return false;
    Map<String, Map<String, DynamicStore.Spec>> updated = new LinkedHashMap<>(dynamicMappings);
    Map<String, DynamicStore.Spec> values = new LinkedHashMap<>(existing);
    values.remove(name);
    if (values.isEmpty()) updated.remove(clientId);
    else updated.put(clientId, values);
    DynamicStore.save(dynamicStoreFile, updated);
    dynamicMappings = updated;
    Session session = sessions.get(clientId);
    if (session != null) Wire.send(session.channel, "CONFIG_REMOVE " + name);
    Binding binding = session == null ? null : session.bindings.get(name);
    if (binding != null) removeBinding(binding);
    return true;
  }

  private static String requiredForm(Map<String, String> form, String key) {
    String value = form.get(key);
    if (value == null || value.trim().isEmpty())
      throw new IllegalArgumentException("Missing form field: " + key);
    return value.trim();
  }

  private static List<String> splitForm(String value) {
    List<String> result = new ArrayList<>();
    if (value != null)
      for (String item : value.split("\\|")) if (!item.trim().isEmpty()) result.add(item.trim());
    return result;
  }

  static String escape(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  private static String errorCode(IllegalArgumentException error) {
    String message = error.getMessage();
    if (message == null) return "BAD_COMMAND";
    if (message.contains("Authentication")) return "AUTH_FAILED";
    if (message.contains("Protocol_version")) return "VERSION_MISMATCH";
    if (message.contains("already") || message.contains("duplicate")) return "CONFLICT";
    return "BAD_COMMAND";
  }

  @Override
  public void close() {
    if (management != null) {
      management.stop(0);
      if (management.getExecutor() instanceof java.util.concurrent.ExecutorService)
        ((java.util.concurrent.ExecutorService) management.getExecutor()).shutdownNow();
    }
    if (controlListener != null) controlListener.close();
    if (workListener != null) workListener.close();
    if (httpListener != null) httpListener.close();
    if (httpsListener != null) httpsListener.close();
    for (Session session : sessions.values()) session.channel.close();
    acceptors.shutdownGracefully();
    workers.shutdownGracefully();
    udpWorkers.shutdownGracefully();
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("Usage: Server <server.properties>");
    Server server = new Server(args[0]);
    Runtime.getRuntime().addShutdownHook(new Thread(server::close));
    server.start();
    server.controlListener.closeFuture().sync();
  }
}
