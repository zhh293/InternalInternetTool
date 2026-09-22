package dev.tunnel;

import java.util.concurrent.atomic.AtomicLong;

/** Low-cardinality counters exported in Prometheus text format. */
final class Metrics {
  final AtomicLong streamsOpened = new AtomicLong();
  final AtomicLong streamsClosed = new AtomicLong();
  final AtomicLong bytesFromPublic = new AtomicLong();
  final AtomicLong bytesToPublic = new AtomicLong();
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
        bytesFromPublic.get(),
        "Bytes received from public endpoints.");
    counter(
        output,
        "tunnel_bytes_to_public_total",
        bytesToPublic.get(),
        "Bytes sent to public endpoints.");
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
}
