package dev.tunnel;

import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import java.util.concurrent.TimeUnit;

/** Unit-style checks for connection-level mux PING/PONG and timeout behavior. */
public final class MuxKeepaliveSmoke {
  public static void main(String[] args) throws Exception {
    pingPongKeepsBothChannelsAlive();
    missingPongClosesChannel();
    System.out.println("Mux keepalive smoke passed");
  }

  private static void pingPongKeepsBothChannelsAlive() throws Exception {
    EmbeddedChannel client = channel(25, 500);
    EmbeddedChannel server = channel(25, 500);
    try {
      for (int i = 0; i < 5; i++) {
        Thread.sleep(35);
        client.runScheduledPendingTasks();
        server.runScheduledPendingTasks();
        transfer(client, server);
        transfer(server, client);
        client.runPendingTasks();
        server.runPendingTasks();
        if (!client.isActive() || !server.isActive()) {
          throw new AssertionError("PING/PONG did not keep mux channels alive");
        }
      }
    } finally {
      client.finishAndReleaseAll();
      server.finishAndReleaseAll();
    }
  }

  private static void missingPongClosesChannel() throws Exception {
    EmbeddedChannel channel = channel(20, 65);
    try {
      Thread.sleep(100);
      channel.runScheduledPendingTasks();
      channel.runPendingTasks();
      if (channel.isActive()) throw new AssertionError("Mux channel stayed open without PONG");
    } finally {
      channel.finishAndReleaseAll();
    }
  }

  private static EmbeddedChannel channel(long intervalMillis, long timeoutMillis) {
    return new EmbeddedChannel(
        new Mux.Decoder(),
        new Mux.Encoder(),
        new Mux.KeepaliveHandler(intervalMillis, timeoutMillis, TimeUnit.MILLISECONDS));
  }

  private static void transfer(EmbeddedChannel from, EmbeddedChannel to) {
    ByteBuf frame;
    while ((frame = from.readOutbound()) != null) to.writeInbound(frame);
  }
}
