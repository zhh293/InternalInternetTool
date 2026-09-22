package dev.tunnel;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

/** Tiny dependency-free management API and dashboard for the server process. */
final class Management {
  static HttpServer start(Server server, String host, int port, String token) throws IOException {
    if (port <= 0) return null;
    HttpServer http = HttpServer.create(new InetSocketAddress(host, port), 32);
    http.setExecutor(
        Executors.newCachedThreadPool(
            r -> {
              Thread thread = new Thread(r, "tunnel-management");
              thread.setDaemon(true);
              return thread;
            }));
    http.createContext(
        "/api/status",
        exchange -> {
          if (!authorize(exchange, token)) return;
          if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "Method Not Allowed", "text/plain");
            return;
          }
          send(exchange, 200, server.statusJson(), "application/json; charset=utf-8");
        });
    http.createContext(
        "/api/clients/",
        exchange -> {
          if (!authorize(exchange, token)) return;
          String path = exchange.getRequestURI().getPath();
          String prefix = "/api/clients/";
          if (path.endsWith("/disconnect")) {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
              send(exchange, 405, "Method Not Allowed", "text/plain");
              return;
            }
            String clientId =
                path.substring(prefix.length(), path.length() - "/disconnect".length());
            boolean disconnected = server.disconnect(clientId);
            send(
                exchange,
                disconnected ? 200 : 404,
                disconnected ? "{\"ok\":true}" : "{\"ok\":false}",
                "application/json; charset=utf-8");
            return;
          }
          int bindings = path.indexOf("/bindings");
          if (bindings < 0) {
            send(exchange, 404, "Not Found", "text/plain");
            return;
          }
          String clientId = path.substring(prefix.length(), bindings);
          String name = path.substring(bindings + "/bindings".length());
          try {
            if (name.isEmpty() && "GET".equalsIgnoreCase(exchange.getRequestMethod())) {
              send(
                  exchange,
                  200,
                  server.dynamicBindingsJson(clientId),
                  "application/json; charset=utf-8");
            } else if (name.isEmpty() && "POST".equalsIgnoreCase(exchange.getRequestMethod())) {
              server.addDynamicBinding(clientId, readForm(exchange));
              send(exchange, 202, "{\"ok\":true}", "application/json; charset=utf-8");
            } else if ("DELETE".equalsIgnoreCase(exchange.getRequestMethod())) {
              boolean removed = server.removeDynamicBinding(clientId, name.substring(1));
              send(
                  exchange,
                  removed ? 200 : 404,
                  removed ? "{\"ok\":true}" : "{\"ok\":false}",
                  "application/json; charset=utf-8");
            } else {
              send(exchange, 405, "Method Not Allowed", "text/plain");
            }
          } catch (IllegalArgumentException error) {
            send(exchange, 400, error.getMessage(), "text/plain");
          } catch (IOException error) {
            send(exchange, 500, "Store unavailable", "text/plain");
          }
        });
    http.createContext(
        "/metrics",
        exchange -> {
          if (!authorize(exchange, token)) return;
          if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "Method Not Allowed", "text/plain");
            return;
          }
          send(exchange, 200, server.prometheus(), "text/plain; version=0.0.4; charset=utf-8");
        });
    http.createContext(
        "/",
        exchange -> {
          if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "Method Not Allowed", "text/plain");
            return;
          }
          byte[] page;
          try (java.io.InputStream input =
              Management.class.getResourceAsStream("/web/index.html")) {
            page =
                input == null
                    ? "Tunnel management UI is unavailable".getBytes(StandardCharsets.UTF_8)
                    : input.readAllBytes();
          }
          send(exchange, 200, page, "text/html; charset=utf-8");
        });
    http.start();
    return http;
  }

  private static boolean authorize(HttpExchange exchange, String token) throws IOException {
    if (token == null) return true;
    String authorization = exchange.getRequestHeaders().getFirst("Authorization");
    if (authorization != null && authorization.equals("Bearer " + token)) return true;
    exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
    send(exchange, 401, "Unauthorized", "text/plain");
    return false;
  }

  private static void send(HttpExchange exchange, int status, String body, String type)
      throws IOException {
    send(exchange, status, body.getBytes(StandardCharsets.UTF_8), type);
  }

  private static void send(HttpExchange exchange, int status, byte[] body, String type)
      throws IOException {
    Headers headers = exchange.getResponseHeaders();
    headers.set("Content-Type", type);
    headers.set("Cache-Control", "no-store");
    exchange.sendResponseHeaders(status, body.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(body);
    }
  }

  private static Map<String, String> readForm(HttpExchange exchange) throws IOException {
    String text = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    Map<String, String> result = new HashMap<>();
    for (String pair : text.split("&")) {
      if (pair.isEmpty()) continue;
      String[] parts = pair.split("=", 2);
      String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
      String value = parts.length == 1 ? "" : URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
      result.put(key, value);
    }
    return result;
  }

  private Management() {}
}
