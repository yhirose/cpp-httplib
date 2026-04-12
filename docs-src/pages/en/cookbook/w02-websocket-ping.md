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

## Detecting an unresponsive peer

Sending pings alone doesn't tell you anything if the peer just silently dies — the TCP socket might still look open while the process on the other end is long gone. To catch that, enable the max-missed-pongs check: if N consecutive pings go unanswered, the connection is closed.

```cpp
cli.set_websocket_max_missed_pongs(2); // close after 2 consecutive unacked pings
```

The server side has the same `set_websocket_max_missed_pongs()`.

With a 30-second ping interval and `max_missed_pongs = 2`, a dead peer is detected within roughly 60 seconds and the connection is closed with `CloseStatus::GoingAway` and the reason `"pong timeout"`.

The counter is reset whenever `read()` consumes an incoming Pong frame, so this only works if your code is actively calling `read()` in a loop — which is what a normal WebSocket client does anyway.

### Why the default is 0

`max_missed_pongs` defaults to `0`, which means "never close the connection because of missing pongs." Pings are still sent on the heartbeat interval, but their responses aren't checked. If you want unresponsive-peer detection, set it explicitly to `1` or higher.

Even with `0`, a dead connection won't linger forever: while your code is inside `read()`, `CPPHTTPLIB_WEBSOCKET_READ_TIMEOUT_SECOND` (default **300 seconds = 5 minutes**) acts as a backstop and `read()` fails if no frame arrives in time. Think of `max_missed_pongs` as the knob for detecting an unresponsive peer **faster** than that.

> For handling a closed connection, see [W03. Handle connection close](w03-websocket-close).
