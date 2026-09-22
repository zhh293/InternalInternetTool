package dev.tunnel;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

final class Relay extends ChannelInboundHandlerAdapter {
  private final Channel peer;

  Relay(Channel peer) {
    this.peer = peer;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object message) {
    if (!peer.isActive()) {
      ReferenceCountUtil.release(message);
      ctx.close();
      return;
    }
    peer.writeAndFlush(message)
        .addListener(
            future -> {
              if (!future.isSuccess()) {
                ctx.close();
                peer.close();
              }
            });
    if (!peer.isWritable()) ctx.channel().config().setAutoRead(false);
  }

  @Override
  public void channelWritabilityChanged(ChannelHandlerContext ctx) {
    boolean readable = ctx.channel().isWritable();
    peer.eventLoop()
        .execute(
            () -> {
              if (peer.isActive()) peer.config().setAutoRead(readable);
            });
    ctx.fireChannelWritabilityChanged();
  }

  @Override
  public void channelInactive(ChannelHandlerContext ctx) {
    peer.close();
    ctx.fireChannelInactive();
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
    ctx.close();
    peer.close();
  }
}
