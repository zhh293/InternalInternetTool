package dev.tunnel;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;

/** Ownership and flush-progress checks, including fragmented frames and tiny payloads. */
public final class MuxBufferSmoke {
  public static void main(String[] args) {
    compositeRetainsPayload();
    fragmentedDecodeRetainsPayload();
    splitAndEmptyPayloads();
    splitPayloadFlushesOnce();
    smallDatagramsUseBoundedComponents();
    largeDatagramBatchRetainsPayload();
    emptyDatagramBatchDoesNotExhaustComponents();
    flushProgress();
    isolatedLatencyWriteFlushesImmediately();
    queuedDatagramRetention();
    System.out.println("Mux buffer smoke passed");
  }

  private static void compositeRetainsPayload() {
    ByteBuf source = Unpooled.buffer().writeByte(99).writeInt(1234);
    source.readByte();
    EmbeddedChannel encoder = new EmbeddedChannel(new Mux.Encoder());
    try {
      encoder.writeOutbound(new Mux.Frame(7, Mux.DATA, source.retainedSlice()));
      ByteBuf encoded = encoder.readOutbound();
      try {
        check(encoded instanceof CompositeByteBuf, "Frame was flattened");
        source.setInt(source.readerIndex(), 5678);
        check(encoded.getInt(Mux.HEADER_BYTES) == 5678, "Payload was copied");
        source.release();
        check(encoded.getInt(Mux.HEADER_BYTES) == 5678, "Outbound lost ownership");
      } finally {
        encoded.release();
      }
      check(source.refCnt() == 0, "Encoder leaked payload");
    } finally {
      if (source.refCnt() > 0) source.release();
      encoder.finishAndReleaseAll();
    }
  }

  private static void fragmentedDecodeRetainsPayload() {
    EmbeddedChannel decoder = new EmbeddedChannel(new Mux.Decoder());
    ByteBuf first = Unpooled.buffer().writeInt(9).writeByte(Mux.DATA);
    ByteBuf second = Unpooled.buffer().writeInt(4).writeInt(1234);
    Mux.Frame frame = null;
    ByteBuf forwarded = null;
    try {
      check(!decoder.writeInbound(first), "Incomplete header produced a frame");
      decoder.writeInbound(second);
      frame = decoder.readInbound();
      check(frame.streamId == 9 && frame.payload.readInt() == 1234, "Bad fragmented frame");
      frame.payload.readerIndex(0);
      forwarded = frame.payload.retainedSlice();
      frame.release();
      frame = null;
      decoder.finishAndReleaseAll();
      check(forwarded.readInt() == 1234, "Decoder freed forwarded bytes");
    } finally {
      if (frame != null) frame.release();
      if (forwarded != null) forwarded.release();
      decoder.finishAndReleaseAll();
    }
    check(first.refCnt() == 0 && second.refCnt() == 0, "Decoder leaked fragmented input");
  }

  private static void splitAndEmptyPayloads() {
    EmbeddedChannel channel = new EmbeddedChannel(new Mux.Decoder());
    ByteBuf data = Unpooled.buffer(Mux.MAX_PAYLOAD + 3).writeZero(Mux.MAX_PAYLOAD + 3);
    try {
      Mux.sendData(channel, 11, data);
      data.release();
      ByteBuf encoded;
      while ((encoded = channel.readOutbound()) != null) channel.writeInbound(encoded);
      Mux.Frame first = channel.readInbound();
      Mux.Frame second = channel.readInbound();
      try {
        check(first.payload.readableBytes() == Mux.MAX_PAYLOAD, "Bad first fragment");
        check(second.payload.readableBytes() == 3, "Bad last fragment");
      } finally {
        first.release();
        second.release();
      }
      Mux.sendData(channel, 12, Unpooled.EMPTY_BUFFER);
      channel.writeInbound((ByteBuf) channel.readOutbound());
      Mux.Frame empty = channel.readInbound();
      try {
        check(empty.streamId == 12 && !empty.payload.isReadable(), "Empty datagram was lost");
      } finally {
        empty.release();
      }
    } finally {
      if (data.refCnt() > 0) data.release();
      channel.finishAndReleaseAll();
    }
    check(data.refCnt() == 0, "Split payload leaked");
  }

  private static void flushProgress() {
    FlushCounter counter = new FlushCounter();
    EmbeddedChannel channel = new EmbeddedChannel(counter, Mux.flushConsolidator(true));
    try {
      // Model writes generated during a read loop: flush once when that loop completes.
      channel.pipeline().fireChannelRead(Unpooled.EMPTY_BUFFER);
      for (int i = 0; i < 3; i++) channel.writeAndFlush(Unpooled.buffer(1).writeByte(i));
      check(counter.flushes == 0, "Flush was not consolidated");
      channel.pipeline().fireChannelReadComplete();
      check(counter.flushes == 1, "Read completion did not flush");
      // One byte with no subsequent traffic must make progress without a size threshold.
      channel.writeAndFlush(Unpooled.buffer(1).writeByte(1));
      channel.runPendingTasks();
      check(counter.flushes == 2, "Isolated small write stalled");
      channel.pipeline().fireChannelRead(Unpooled.EMPTY_BUFFER);
      for (int i = 0; i < 64; i++) channel.writeAndFlush(Unpooled.buffer(1).writeByte(i));
      check(counter.flushes == 3, "Flush-count safety threshold did not flush");
      channel.pipeline().fireChannelReadComplete();
    } finally {
      channel.finishAndReleaseAll();
    }
  }

  private static void splitPayloadFlushesOnce() {
    FlushCounter counter = new FlushCounter();
    EmbeddedChannel channel = new EmbeddedChannel(counter);
    ByteBuf payload = Unpooled.buffer(Mux.MAX_PAYLOAD * 2 + 1).writeZero(Mux.MAX_PAYLOAD * 2 + 1);
    try {
      Mux.sendData(channel, 13, payload);
      check(counter.flushes == 1, "Split payload flushed once per mux frame");
      ByteBuf first = channel.readOutbound();
      ByteBuf second = channel.readOutbound();
      ByteBuf third = channel.readOutbound();
      try {
        check(first.readableBytes() == Mux.HEADER_BYTES + Mux.MAX_PAYLOAD, "Bad first output frame");
        check(second.readableBytes() == Mux.HEADER_BYTES + Mux.MAX_PAYLOAD, "Bad second output frame");
        check(third.readableBytes() == Mux.HEADER_BYTES + 1, "Bad final output frame");
        check(channel.readOutbound() == null, "Unexpected extra output frame");
      } finally {
        first.release();
        second.release();
        third.release();
      }
    } finally {
      payload.release();
      channel.finishAndReleaseAll();
    }
  }

  private static void smallDatagramsUseBoundedComponents() {
    Mux.DatagramBatch batch = new Mux.DatagramBatch(UnpooledByteBufAllocator.DEFAULT);
    ByteBuf packet = Unpooled.buffer(64, 64).writeZero(64);
    ByteBuf encoded = null;
    try {
      for (int i = 0; i < 100; i++) batch.add(packet);
      check(packet.refCnt() == 1, "Small datagrams were retained instead of compacted");
      encoded = batch.take();
      check(encoded instanceof CompositeByteBuf, "Datagram batch was flattened");
      check(((CompositeByteBuf) encoded).numComponents() < 10,
          "Small datagrams were not consolidated into bounded components");
      check(encoded.readableBytes() == 100 * (Short.BYTES + 64), "Bad encoded batch size");
      check(encoded.getUnsignedShort(0) == 64, "Datagram length prefix changed");
      check(encoded.getByte(Short.BYTES) == 0, "Datagram payload changed");
    } finally {
      if (encoded != null) encoded.release();
      batch.release();
      if (packet.refCnt() > 0) packet.release(packet.refCnt());
    }
    check(packet.refCnt() == 0, "Datagram batch leaked packet slices");
  }

  private static void emptyDatagramBatchDoesNotExhaustComponents() {
    Mux.DatagramBatch batch = new Mux.DatagramBatch(UnpooledByteBufAllocator.DEFAULT);
    ByteBuf empty = Unpooled.EMPTY_BUFFER;
    ByteBuf encoded = null;
    try {
      for (int i = 0; i < 5000; i++) batch.add(empty);
      encoded = batch.take();
      check(encoded.readableBytes() == 5000 * Short.BYTES, "Empty datagrams were lost");
      check(((CompositeByteBuf) encoded).numComponents() < 10,
          "Empty datagrams exhausted composite components");
      for (int i = 0; i < 5000; i++)
        check(encoded.getUnsignedShort(i * Short.BYTES) == 0, "Bad empty datagram boundary");
    } finally {
      if (encoded != null) encoded.release();
      batch.release();
    }
  }

  private static void largeDatagramBatchRetainsPayload() {
    Mux.DatagramBatch batch = new Mux.DatagramBatch(UnpooledByteBufAllocator.DEFAULT);
    ByteBuf packet = Unpooled.buffer(1024, 1024).writeZero(1024);
    ByteBuf encoded = null;
    try {
      packet.setByte(0, 42);
      batch.add(packet);
      check(packet.refCnt() == 2, "Large datagram payload was copied instead of retained");
      encoded = batch.take();
      check(encoded.readableBytes() == Short.BYTES + 1024, "Bad large datagram size");
      check(encoded.getUnsignedShort(0) == 1024, "Bad large datagram prefix");
      check(encoded.getByte(Short.BYTES) == 42, "Large datagram payload changed");
    } finally {
      if (encoded != null) encoded.release();
      batch.release();
      if (packet.refCnt() > 0) packet.release(packet.refCnt());
    }
    check(packet.refCnt() == 0, "Large datagram batch leaked payload");
  }

  private static void queuedDatagramRetention() {
    ByteBuf large = Unpooled.buffer(65536, 65536).writeByte(42);
    ByteBuf queued = Mux.retainDatagramForQueue(large);
    try {
      check(large.refCnt() == 1, "Tiny queued packet pinned the receive buffer");
      large.release();
      check(queued.readByte() == 42, "Compacted packet lost its bytes");
    } finally {
      queued.release();
      if (large.refCnt() > 0) large.release();
    }
    ByteBuf dense = Unpooled.buffer(8192, 8192).writeZero(8192);
    queued = Mux.retainDatagramForQueue(dense);
    try {
      check(dense.refCnt() == 2, "Dense queued packet was unnecessarily copied");
    } finally {
      queued.release();
      dense.release();
    }
  }

  private static void check(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }

  private static void isolatedLatencyWriteFlushesImmediately() {
    FlushCounter counter = new FlushCounter();
    EmbeddedChannel channel = new EmbeddedChannel(counter, Mux.flushConsolidator());
    try {
      channel.writeAndFlush(Unpooled.buffer(1).writeByte(1));
      check(counter.flushes == 1, "Latency mode deferred an isolated small write");
    } finally {
      channel.finishAndReleaseAll();
    }
  }

  private static final class FlushCounter extends ChannelDuplexHandler {
    int flushes;

    @Override
    public void flush(ChannelHandlerContext ctx) {
      flushes++;
      ctx.flush();
    }
  }
}
