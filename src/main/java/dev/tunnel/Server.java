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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Public endpoint and control-plane server. A client owns one TLS mux channel. */
public final class Server implements AutoCloseable {
  private final Settings settings;
  private final byte[] password;
  private final Map<String, byte[]> clientTokens;
  private final Metrics metrics = new Metrics();
  private final String managementToken;
  private final SslContext ssl;
  private final EventLoopGroup acceptors = new NioEventLoopGroup(1);
  private final EventLoopGroup workers = new NioEventLoopGroup();
  private final Map<String, Session> sessions = new ConcurrentHashMap<>();
  private final Map<Integer, PortGroup> ports = new ConcurrentHashMap<>();
  private final Map<String, List<Binding>> httpRoutes = new ConcurrentHashMap<>();
  private final String dynamicStoreFile;
  private final Map<String, Map<String, DynamicStore.Spec>> dynamicMappings;
  private final int muxPoolSize;
  private final int maxPendingBytes;
  private final AtomicInteger httpRoundRobin = new AtomicInteger();
  private Channel controlListener;
  private Channel workListener;
  private Channel httpListener;
  private Channel httpsListener;
  private HttpServer management;

  public Server(String configPath) throws Exception {
    this.settings = Settings.load(configPath);
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
    this.maxPendingBytes =
        settings.optionalPositive("maxPendingBytes", 8 * 1024 * 1024, 64 * 1024, 256 * 1024 * 1024);
  }

  public void start() throws Exception {
    controlListener =
        new ServerBootstrap()
            .group(acceptors, workers)
            .channel(NioServerSocketChannel.class)
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
                .childHandler(
                    new ChannelInitializer<SocketChannel>() {
                      @Override
                      protected void initChannel(SocketChannel channel) {
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
                .childHandler(
                    new ChannelInitializer<SocketChannel>() {
                      @Override
                      protected void initChannel(SocketChannel channel) {
                        channel.pipeline().addLast("ssl", ssl.newHandler(channel.alloc()));
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
          .group(workers)
          .channel(NioDatagramChannel.class)
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

  private void startStream(Binding binding, Channel visitor, byte[] initial) {
    Session owner = binding.owner;
    if (!owner.channel.isActive() || owner.streams.size() >= 2000) {
      visitor.close();
      return;
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
  }

  private void forwardPublic(Stream stream, ByteBuf message) {
    try {
      if (!stream.ready || stream.closed.get() || stream.mux == null || !stream.mux.isActive())
        return;
      byte[] bytes = new byte[message.readableBytes()];
      message.readBytes(bytes);
      metrics.bytesFromPublic.addAndGet(bytes.length);
      if (!stream.mux.isWritable()) {
        synchronized (stream.pending) {
          if (stream.pendingBytes + bytes.length > maxPendingBytes) {
            closeStream(stream, true);
            return;
          }
          stream.pending.addLast(bytes);
          stream.pendingBytes += bytes.length;
        }
        stream.visitor.config().setAutoRead(false);
        return;
      }
      sendData(stream.mux, stream.id, bytes);
    } finally {
      ReferenceCountUtil.release(message);
    }
  }

  private void sendData(Channel mux, int id, byte[] bytes) {
    for (int offset = 0; offset < bytes.length; offset += Mux.MAX_PAYLOAD) {
      int length = Math.min(Mux.MAX_PAYLOAD, bytes.length - offset);
      byte[] part = new byte[length];
      System.arraycopy(bytes, offset, part, 0, length);
      mux.writeAndFlush(new Mux.Frame(id, Mux.DATA, part));
    }
  }

  private void flushPending(Stream stream) {
    synchronized (stream.pending) {
      while (!stream.pending.isEmpty() && stream.mux != null && stream.mux.isWritable()) {
        byte[] bytes = stream.pending.removeFirst();
        stream.pendingBytes -= bytes.length;
        sendData(stream.mux, stream.id, bytes);
      }
    }
  }

  private void closeStream(Stream stream, boolean notify) {
    if (!stream.closed.compareAndSet(false, true)) return;
    stream.owner.streams.remove(stream.id, stream);
    stream.binding.streams.remove(stream.id, stream);
    metrics.streamsClosed.incrementAndGet();
    if (stream.timer != null) stream.timer.cancel(false);
    if (notify && stream.mux != null && stream.mux.isActive())
      stream.mux.writeAndFlush(new Mux.Frame(stream.id, Mux.CLOSE, new byte[0]));
    if (stream.visitor != null) stream.visitor.close();
  }

  private void onMuxFrame(Session owner, Channel mux, Mux.Frame frame) {
    Stream stream = owner.streams.get(frame.streamId);
    if (stream == null) {
      UdpStream udp = owner.udpStreams.get(frame.streamId);
      if (udp == null || udp.closed.get()) return;
      if (frame.type == Mux.ACK) {
        udp.ready = true;
        synchronized (udp.pending) {
          for (byte[] bytes : udp.pending) sendData(mux, udp.id, bytes);
          udp.pending.clear();
        }
      } else if (frame.type == Mux.DATA && udp.binding.listener != null) {
        metrics.bytesToPublic.addAndGet(frame.payload.length);
        udp.binding.listener.writeAndFlush(
            new DatagramPacket(Unpooled.wrappedBuffer(frame.payload), udp.visitor));
      } else if (frame.type == Mux.CLOSE) closeUdpStream(udp);
      return;
    }
    if (stream.closed.get()) return;
    if (frame.type == Mux.ACK) {
      stream.mux = mux;
      stream.ready = true;
      if (stream.timer != null) stream.timer.cancel(false);
      stream.visitor.config().setAutoRead(mux.isWritable());
      if (stream.initial != null) {
        sendData(mux, stream.id, stream.initial);
        stream.initial = null;
      }
    } else if (frame.type == Mux.DATA) {
      if (stream.binding.kind == Settings.Rule.Kind.UDP) {
        if (stream.binding.listener != null && stream.visitorAddress != null) {
          metrics.bytesToPublic.addAndGet(frame.payload.length);
          stream.binding.listener.writeAndFlush(
              new DatagramPacket(Unpooled.wrappedBuffer(frame.payload), stream.visitorAddress));
        }
      } else if (stream.visitor.isActive()) {
        metrics.bytesToPublic.addAndGet(frame.payload.length);
        stream.visitor.writeAndFlush(Unpooled.wrappedBuffer(frame.payload));
      }
    } else if (frame.type == Mux.CLOSE) closeStream(stream, false);
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
      Session candidate = new Session(words[2], ctx.channel(), expected);
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

  private final class MuxLoginHandler extends SimpleChannelInboundHandler<ByteBuf> {
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf message) {
      String[] words = Wire.readLine(message).split(" ");
      try {
        if (words.length != 4 || !"MUX".equals(words[0]))
          throw new IllegalArgumentException("Expected MUX version clientId token");
        if (!String.valueOf(Wire.PROTOCOL_VERSION).equals(words[1]))
          throw new IllegalArgumentException("Protocol_version_mismatch");
        Session owner = sessions.get(words[2]);
        if (owner == null
            || !MessageDigest.isEqual(owner.token, words[3].getBytes(StandardCharsets.UTF_8))) {
          metrics.authFailures.incrementAndGet();
          throw new IllegalArgumentException("Authentication_failed");
        }
        if (owner.muxes.size() >= muxPoolSize) throw new IllegalArgumentException("Mux_pool_full");
        owner.muxes.add(ctx.channel());
        owner.primaryMux = ctx.channel();
        metrics.muxConnections.incrementAndGet();
        Wire.send(ctx.channel(), "MUX_OK " + Wire.PROTOCOL_VERSION);
        ctx.pipeline().remove("timeout");
        ctx.pipeline().remove("lines");
        ctx.pipeline().replace(this, "mux-decoder", new Mux.Decoder());
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
        if (owner.primaryMux == ctx.channel()) owner.primaryMux = owner.selectMux();
        metrics.muxConnections.decrementAndGet();
      }
      for (Stream stream : new ArrayList<>(owner.streams.values()))
        if (stream.mux == ctx.channel()) closeStream(stream, false);
      for (UdpStream stream : new ArrayList<>(owner.udpStreams.values()))
        if (stream.mux == ctx.channel()) closeUdpStream(stream);
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
      boolean writable = ctx.channel().isWritable();
      for (Stream stream : owner.streams.values()) {
        if (stream.mux != ctx.channel()) continue;
        if (writable) flushPending(stream);
        stream.visitor.config().setAutoRead(writable);
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
      startStream(binding, ctx.channel(), null);
      stream = findStream(ctx.channel());
    }

    private Stream findStream(Channel channel) {
      for (Stream candidate : binding.streams.values())
        if (candidate.visitor == channel) return candidate;
      return null;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object message) {
      if (stream == null) stream = findStream(ctx.channel());
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
    private final boolean https;
    private final ByteArrayOutputStream head = new ByteArrayOutputStream();
    private Stream stream;
    private boolean routed;
    private String sniHost;

    HttpPublicHandler() {
      this(false);
    }

    HttpPublicHandler(boolean https) {
      this.https = https;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object message) {
      ByteBuf buffer = (ByteBuf) message;
      try {
        byte[] bytes = new byte[buffer.readableBytes()];
        buffer.readBytes(bytes);
        if (routed) {
          forwardPublic(stream, Unpooled.wrappedBuffer(bytes));
          return;
        }
        if (head.size() + bytes.length > 64 * 1024) {
          httpError(ctx, 431, "Request Header Fields Too Large");
          return;
        }
        head.write(bytes, 0, bytes.length);
        byte[] all = head.toByteArray();
        int end = indexOf(all, new byte[] {'\r', '\n', '\r', '\n'});
        if (end < 0) return;
        String text = new String(all, 0, end + 4, StandardCharsets.ISO_8859_1);
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
        if (binding.bandwidthBytesPerSecond > 0 && ctx.pipeline().get("traffic") == null)
          ctx.pipeline()
              .addFirst(
                  "traffic",
                  new ChannelTrafficShapingHandler(
                      binding.bandwidthBytesPerSecond, binding.bandwidthBytesPerSecond, 1000));
        startStream(binding, ctx.channel(), prepareRequest(all, binding, ctx));
        stream = findStream(binding, ctx.channel());
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

    private Stream findStream(Binding binding, Channel channel) {
      for (Stream candidate : binding.streams.values())
        if (candidate.visitor == channel) return candidate;
      return null;
    }

    private void httpError(ChannelHandlerContext ctx, int code, String reason) {
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

    private byte[] prepareRequest(byte[] request, Binding binding, ChannelHandlerContext ctx) {
      String text = new String(request, StandardCharsets.ISO_8859_1);
      String forwarded =
          "X-Forwarded-For: "
              + ((InetSocketAddress) ctx.channel().remoteAddress()).getAddress().getHostAddress();
      if (!text.toLowerCase().contains("\r\nx-forwarded-for:"))
        text = text.replace("\r\n\r\n", "\r\n" + forwarded + "\r\n\r\n");
      if (!binding.hostRewrite.isEmpty()) {
        text = text.replaceFirst("(?im)^Host:.*$", "Host: " + binding.hostRewrite);
      }
      return text.getBytes(StandardCharsets.ISO_8859_1);
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

  private final class UdpPublicHandler extends SimpleChannelInboundHandler<DatagramPacket> {
    private final PortGroup group;

    UdpPublicHandler(PortGroup group) {
      this.group = group;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
      InetSocketAddress address = packet.sender();
      String key = String.valueOf(address);
      Binding binding = group.udpAffinity.get(key);
      if (binding == null || binding.closed.get() || !binding.healthy) {
        binding = chooseBinding(group);
        if (binding == null) return;
        group.udpAffinity.put(key, binding);
      }
      UdpStream stream = binding.udpStreams.get(key);
      if (stream == null || stream.closed.get()) {
        stream = new UdpStream(nextId(binding.owner), binding, address);
        binding.udpStreams.put(key, stream);
        binding.owner.udpStreams.put(stream.id, stream);
        metrics.streamsOpened.incrementAndGet();
        UdpStream selected = stream;
        stream.timer =
            ctx.executor().schedule(() -> closeUdpStream(selected), 120, TimeUnit.SECONDS);
        Channel mux = binding.owner.selectMux();
        stream.mux = mux;
        if (mux != null)
          mux.writeAndFlush(
              new Mux.Frame(
                  stream.id, Mux.OPEN_UDP, binding.name.getBytes(StandardCharsets.UTF_8)));
      }
      stream.lastSeen = System.nanoTime();
      if (stream.timer != null) stream.timer.cancel(false);
      UdpStream selected = stream;
      stream.timer = ctx.executor().schedule(() -> closeUdpStream(selected), 120, TimeUnit.SECONDS);
      byte[] bytes = new byte[packet.content().readableBytes()];
      packet.content().getBytes(packet.content().readerIndex(), bytes);
      if (!binding.allowDatagram(bytes.length)) return;
      metrics.bytesFromPublic.addAndGet(bytes.length);
      if (stream.ready && stream.mux != null) sendData(stream.mux, stream.id, bytes);
      else stream.pending.add(bytes);
    }
  }

  private void closeUdpStream(UdpStream stream) {
    if (!stream.closed.compareAndSet(false, true)) return;
    metrics.streamsClosed.incrementAndGet();
    stream.binding.udpStreams.remove(String.valueOf(stream.visitor), stream);
    stream.binding.owner.udpStreams.remove(stream.id, stream);
    if (stream.binding.group != null)
      stream.binding.group.udpAffinity.remove(String.valueOf(stream.visitor), stream.binding);
    if (stream.mux != null && stream.mux.isActive())
      stream.mux.writeAndFlush(new Mux.Frame(stream.id, Mux.CLOSE, new byte[0]));
  }

  private static int nextId(Session session) {
    int id = session.nextStream.getAndIncrement();
    if (id <= 0) {
      session.nextStream.set(1);
      return session.nextStream.getAndIncrement();
    }
    return id;
  }

  private static boolean isLoopbackHost(String host) {
    return "127.0.0.1".equals(host)
        || "localhost".equalsIgnoreCase(host)
        || "::1".equals(host)
        || "0:0:0:0:0:0:0:1".equals(host);
  }

  private static int indexOf(byte[] value, byte[] needle) {
    outer:
    for (int i = 0; i <= value.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) if (value[i + j] != needle[j]) continue outer;
      return i;
    }
    return -1;
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
    final Deque<byte[]> pending = new ArrayDeque<>();
    int pendingBytes;
    volatile boolean ready;
    volatile byte[] initial;
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
    final Set<Channel> muxes = ConcurrentHashMap.newKeySet();
    volatile Channel primaryMux;
    final Map<String, Binding> bindings = new ConcurrentHashMap<>();
    final Map<Integer, Stream> streams = new ConcurrentHashMap<>();
    final Map<Integer, UdpStream> udpStreams = new ConcurrentHashMap<>();
    final ChannelGroup channels = new DefaultChannelGroup(ImmediateEventExecutor.INSTANCE);
    final AtomicInteger nextStream = new AtomicInteger(1);
    final AtomicInteger nextMux = new AtomicInteger();

    Session(String id, Channel channel, byte[] token) {
      this.id = id;
      this.channel = channel;
      this.token = token;
    }

    Channel selectMux() {
      List<Channel> active = new ArrayList<>();
      for (Channel mux : muxes) if (mux.isActive() && mux.isWritable()) active.add(mux);
      if (active.isEmpty()) return null;
      return active.get(Math.floorMod(nextMux.getAndIncrement(), active.size()));
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
    final Map<String, UdpStream> udpStreams = new ConcurrentHashMap<>();
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
    final Map<String, Binding> udpAffinity = new ConcurrentHashMap<>();
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
    final List<byte[]> pending = Collections.synchronizedList(new ArrayList<>());
    volatile boolean ready;
    volatile ScheduledFuture<?> timer;
    volatile long lastSeen;

    UdpStream(int id, Binding binding, InetSocketAddress visitor) {
      this.id = id;
      this.binding = binding;
      this.visitor = visitor;
      this.lastSeen = System.nanoTime();
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
    Map<String, DynamicStore.Spec> values =
        dynamicMappings.computeIfAbsent(clientId, ignored -> new LinkedHashMap<>());
    if (values.put(name, spec) != null) {
      Session session = sessions.get(clientId);
      if (session != null) Wire.send(session.channel, "CONFIG_REMOVE " + name);
    }
    DynamicStore.save(dynamicStoreFile, dynamicMappings);
    Session session = sessions.get(clientId);
    if (session != null) Wire.send(session.channel, "CONFIG_ADD " + spec.encode());
  }

  synchronized boolean removeDynamicBinding(String clientId, String name) throws IOException {
    Map<String, DynamicStore.Spec> values = dynamicMappings.get(clientId);
    if (values == null || values.remove(name) == null) return false;
    DynamicStore.save(dynamicStoreFile, dynamicMappings);
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
    if (management != null) management.stop(0);
    if (controlListener != null) controlListener.close();
    if (workListener != null) workListener.close();
    if (httpListener != null) httpListener.close();
    for (Session session : sessions.values()) session.channel.close();
    acceptors.shutdownGracefully();
    workers.shutdownGracefully();
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("Usage: Server <server.properties>");
    Server server = new Server(args[0]);
    Runtime.getRuntime().addShutdownHook(new Thread(server::close));
    server.start();
    server.controlListener.closeFuture().sync();
  }
}
