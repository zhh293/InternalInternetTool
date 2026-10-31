package dev.tunnel;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.DefaultEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.local.LocalAddress;
import io.netty.channel.local.LocalChannel;
import io.netty.channel.local.LocalServerChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Reproduces an in-loop write overtaking an earlier write queued by another event loop. */
public final class MuxOrderingSmoke {
  public static void main(String[] args) throws Exception {
    DefaultEventLoopGroup group = new DefaultEventLoopGroup(2);
    Channel listener = null, sender = null;
    CountDownLatch release = new CountDownLatch(1);
    try {
      List<Integer> observed = new ArrayList<>();
      CountDownLatch received = new CountDownLatch(2), entered = new CountDownLatch(1);
      LocalAddress address = new LocalAddress("mux-order-" + System.nanoTime());
      listener = new ServerBootstrap().group(group).channel(LocalServerChannel.class)
          .childHandler(new ChannelInitializer<LocalChannel>() {
            @Override protected void initChannel(LocalChannel ch) {
              ch.pipeline().addLast(new Mux.Decoder(), new SimpleChannelInboundHandler<Mux.Frame>() {
                @Override protected void channelRead0(ChannelHandlerContext ctx, Mux.Frame frame) {
                  observed.add((int) frame.payload.readUnsignedByte()); received.countDown();
                }
              });
            }
          }).bind(address).sync().channel();
      sender = new Bootstrap().group(group).channel(LocalChannel.class)
          .handler(new ChannelInitializer<LocalChannel>() {
            @Override protected void initChannel(LocalChannel ch) { }
          }).connect(address).sync().channel();
      Channel channel = sender;
      channel.eventLoop().execute(() -> {
        entered.countDown();
        try {
          if (!release.await(5, TimeUnit.SECONDS)) throw new AssertionError("Caller did not queue data");
          io.netty.buffer.ByteBuf second = Unpooled.buffer(1).writeByte(2);
          try { Mux.sendData(channel, 1, second); } finally { second.release(); }
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
      });
      if (!entered.await(5, TimeUnit.SECONDS)) throw new AssertionError("Event loop did not enter");
      io.netty.buffer.ByteBuf first = Unpooled.buffer(1).writeByte(1);
      try { Mux.sendData(channel, 1, first); } finally { first.release(); }
      release.countDown();
      if (!received.await(5, TimeUnit.SECONDS)) throw new AssertionError("Data did not arrive");
      if (!observed.equals(java.util.Arrays.asList(1, 2)))
        throw new AssertionError("Mux data reordered across event loops: " + observed);
      System.out.println("MUX_ORDERING_OK: queued data is not overtaken by in-loop data");
    } finally {
      release.countDown();
      if (sender != null) sender.close().syncUninterruptibly();
      if (listener != null) listener.close().syncUninterruptibly();
      group.shutdownGracefully(0, 5, TimeUnit.SECONDS).syncUninterruptibly();
    }
  }
}
