package dev.tunnel;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/** Low-cardinality counters exported in Prometheus text format. */
final class Metrics {
  final AtomicLong streamsOpened = new AtomicLong();
  final AtomicLong streamsClosed = new AtomicLong();
  final LongAdder bytesFromPublic = new LongAdder();
  final LongAdder bytesToPublic = new LongAdder();
  final LongAdder udpDropped = new LongAdder();
  final AtomicLong udpEgressBatches = new AtomicLong();
  final AtomicLong udpEgressDrainTasks = new AtomicLong();
  final AtomicLong udpEgressQueueDelayNanos = new AtomicLong();
  final AtomicLong udpEgressQueueDelayMaxNanos = new AtomicLong();
  final LongAdder udpEgressWrites = new LongAdder();
  final LongAdder udpEgressWriteSamples = new LongAdder();
  final AtomicLong udpEgressWriteNanos = new AtomicLong();
  final AtomicLong udpEgressWriteMaxNanos = new AtomicLong();
  final AtomicLong authFailures = new AtomicLong();
  final AtomicLong muxConnections = new AtomicLong();

  String prometheus(int clients, int activeStreams) {
    StringBuilder output = new StringBuilder();
    gauge(output, "tunnel_clients", clients, "Connected tunnel clients.");
    gauge(
        output,
        "tunnel_mux_connections",
        muxConnections.get(),
        "Authenticated mux work connections.");
    gauge(
        output,
        "tunnel_active_streams",
        activeStreams,
        "Currently active TCP, HTTP and UDP streams.");
    counter(
        output,
        "tunnel_streams_opened_total",
        streamsOpened.get(),
        "Streams opened since process start.");
    counter(
        output,
        "tunnel_streams_closed_total",
        streamsClosed.get(),
        "Streams closed since process start.");
    counter(
        output,
        "tunnel_bytes_from_public_total",
        bytesFromPublic.sum(),
        "Bytes received from public endpoints.");
    counter(
        output,
        "tunnel_bytes_to_public_total",
        bytesToPublic.sum(),
        "Bytes sent to public endpoints.");
    counter(
        output,
        "tunnel_udp_dropped_total",
        udpDropped.sum(),
        "UDP datagrams dropped after queue limits, stale queue age, or failed UDP writes.");
    counter(
        output,
        "tunnel_udp_egress_batches_total",
        udpEgressBatches.get(),
        "UDP batches submitted to public UDP listener event loops.");
    counter(
        output,
        "tunnel_udp_egress_drain_tasks_total",
        udpEgressDrainTasks.get(),
        "UDP egress event-loop drain tasks used to process queued batches.");
    counter(
        output,
        "tunnel_udp_egress_queue_delay_nanos_total",
        udpEgressQueueDelayNanos.get(),
        "Cumulative delay from mux decode to public UDP listener event loop.");
    gauge(
        output,
        "tunnel_udp_egress_queue_delay_nanos_max",
        udpEgressQueueDelayMaxNanos.get(),
        "Maximum observed delay from mux decode to public UDP listener event loop.");
    counter(
        output,
        "tunnel_udp_egress_writes_total",
        udpEgressWrites.sum(),
        "UDP datagram write completion callbacks on public UDP listeners.");
    counter(
        output,
        "tunnel_udp_egress_write_nanos_total",
        udpEgressWriteNanos.get(),
        "Cumulative sampled time from public UDP listener write submission to completion.");
    counter(
        output,
        "tunnel_udp_egress_write_samples_total",
        udpEgressWriteSamples.sum(),
        "Sampled UDP datagram write completion timings (one in 64 writes).");
    gauge(
        output,
        "tunnel_udp_egress_write_nanos_max",
        udpEgressWriteMaxNanos.get(),
        "Maximum observed public UDP listener write completion time.");
    counter(
        output,
        "tunnel_auth_failures_total",
        authFailures.get(),
        "Rejected control or mux authentications.");
    return output.toString();
  }

  private static void gauge(StringBuilder output, String name, long value, String help) {
    metric(output, name, value, help, "gauge");
  }

  private static void counter(StringBuilder output, String name, long value, String help) {
    metric(output, name, value, help, "counter");
  }

  private static void metric(
      StringBuilder output, String name, long value, String help, String type) {
    output.append("# HELP ").append(name).append(' ').append(help).append('\n');
    output.append("# TYPE ").append(name).append(' ').append(type).append('\n');
    output.append(name).append(' ').append(value).append('\n');
  }

  void observeUdpEgressQueueDelay(long nanos) {
    udpEgressBatches.incrementAndGet();
    udpEgressQueueDelayNanos.addAndGet(nanos);
    udpEgressQueueDelayMaxNanos.accumulateAndGet(nanos, Math::max);
  }

  void recordUdpEgressWrite(boolean sampled, long nanos) {
    udpEgressWrites.increment();
    if (!sampled) return;
    udpEgressWriteSamples.increment();
    udpEgressWriteNanos.addAndGet(nanos);
    udpEgressWriteMaxNanos.accumulateAndGet(nanos, Math::max);
  }
}
