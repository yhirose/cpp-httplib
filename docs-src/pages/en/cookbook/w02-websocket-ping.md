---
title: "W02. Set a WebSocket Heartbeat"
order: 52
status: "draft"
---

WebSocket connections stay open for a long time, and proxies or load balancers will sometimes drop them for being "idle." To prevent that, you periodically send Ping frames to keep the connection alive. cpp-httplib can do this for you automatically.

## Server side

```cpp
svr.set_websocket_ping_interval(30); // ping every 30 seconds

svr.WebSocket("/chat", [](const auto &req, auto &ws) {
  // ...
});
```

Just pass the interval in seconds. Every WebSocket connection this server accepts will be pinged on that interval.

There's a `std::chrono` overload too.

```cpp
using namespace std::chrono_literals;
svr.set_websocket_ping_interval(30s);
```

## Client side

The client has the same API.

```cpp
httplib::ws::WebSocketClient cli("ws://localhost:8080/chat");
cli.set_websocket_ping_interval(30);
cli.connect();
```

Call it before `connect()`.

## The default

The default interval is set by the build-time macro `CPPHTTPLIB_WEBSOCKET_PING_INTERVAL_SECOND`. Usually you won't need to change it, but adjust downward if you're dealing with an aggressive proxy.

## What about Pong?

The WebSocket protocol requires that Ping frames are answered with Pong frames. cpp-httplib responds to Pings automatically — you don't need to think about it in application code.

## Picking an interval

| Environment | Suggested |
| --- | --- |
| Normal internet | 30–60s |
| Strict proxies (e.g. AWS ALB) | 15–30s |
| Mobile networks | 60s+ (too short drains battery) |

Too short wastes bandwidth; too long and connections get dropped. As a rule of thumb, target about **half the idle timeout** of whatever's between you and the client.

> **Warning:** A very short ping interval spawns background work per connection and increases CPU usage. For servers with many connections, keep the interval modest.

> For handling a closed connection, see [W03. Handle connection close](w03-websocket-close).
