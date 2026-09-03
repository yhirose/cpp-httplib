---
title: "W06. Set Timeouts"
order: 57
status: "draft"
---

`ws::WebSocketClient` has the same three kinds of timeouts as `Client`, with the same meaning.

| Kind | API | Default |
| --- | --- | --- |
| Connection | `set_connection_timeout` | 300s |
| Read | `set_read_timeout` | none — waits forever (`CPPHTTPLIB_WEBSOCKET_CLIENT_READ_TIMEOUT_SECOND`) |
| Write | `set_write_timeout` | 5s |

## Basic usage

```cpp
httplib::ws::WebSocketClient ws("ws://localhost:8080/ws");

ws.set_connection_timeout(5, 0);  // 5 seconds
ws.set_read_timeout(30, 0);       // 30 seconds
ws.set_write_timeout(10, 0);      // 10 seconds

if (ws.connect()) {
  ws.send("hello");
}
```

Set the connection and write timeouts before calling `connect()`. The read timeout can be changed at any time — setting it on an open connection takes effect on the next `read()`.

## Use `std::chrono`

Just like `Client`, there's an overload that takes a `std::chrono` duration directly.

```cpp
using namespace std::chrono_literals;

ws.set_connection_timeout(5s);
ws.set_read_timeout(30s);
ws.set_write_timeout(10s);
```

## What the read timeout means

`set_read_timeout()` applies to a single `read()` call. If no message arrives within that time, `read()` returns `ReadResult::Timeout`: **the connection is still open** and nothing was consumed, so you can send on it and read again. That is what separates it from `ReadResult::Fail`, which means the connection is gone.

This is what lets one thread own a connection in both directions:

```cpp
using namespace std::chrono_literals;

ws.set_read_timeout(100ms);
std::string msg;
while (ws.is_open()) {
  auto r = ws.read(msg);
  if (r == httplib::ws::Timeout) {
    flush_outgoing(ws);  // nothing arrived — send whatever is queued
    continue;
  }
  if (r == httplib::ws::Fail) { break; }
  handle(msg);
}
```

Without a read timeout, `read()` blocks until a message arrives, so the thread holding the connection never gets to its writes.

Two things to know about `Timeout`:

- It leaves `msg` untouched, and it is non-zero. So `while (ws.read(msg))` is not usable once a read timeout is set — the loop would keep running with the *previous* message still in `msg`.
- It is only reported on a message boundary. If the timeout elapses partway through a fragmented message, that message cannot be resumed and `read()` returns `Fail`.

For connections where long idle periods are normal — waiting on notifications, for example — either leave the read timeout unset, or treat `Timeout` as the no-op it is and keep looping.

## On the server side

A handler's `ws::WebSocket` has `set_read_timeout()` too, and the pattern above is how a handler relays between connections instead of parking in `read()`.

The server default is 300s (`CPPHTTPLIB_WEBSOCKET_SERVER_READ_TIMEOUT_SECOND`) rather than "forever": it is a backstop that reclaims a worker from a peer that has gone silent, since a WebSocket handler holds its worker for the life of the connection.

> Unresponsive-peer detection via Ping/Pong is a separate mechanism. See [W02. Set a WebSocket Heartbeat](../w02-websocket-ping) for details.

## How this differs from `Client`

For `Client`'s timeout configuration, see [C12. Set Timeouts](../c12-timeouts). The behavior and API are nearly identical, but `WebSocketClient` has no equivalent to `set_max_timeout()` for capping the whole request — once connected, the connection stays open for as long as you keep calling `read()`.
