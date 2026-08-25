---
title: "W06. Set Timeouts"
order: 57
status: "draft"
---

`ws::WebSocketClient` has the same three kinds of timeouts as `Client`, with the same meaning.

| Kind | API | Default |
| --- | --- | --- |
| Connection | `set_connection_timeout` | 300s |
| Read | `set_read_timeout` | 300s (`CPPHTTPLIB_WEBSOCKET_READ_TIMEOUT_SECOND`) |
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

Set these before calling `connect()`.

## Use `std::chrono`

Just like `Client`, there's an overload that takes a `std::chrono` duration directly.

```cpp
using namespace std::chrono_literals;

ws.set_connection_timeout(5s);
ws.set_read_timeout(30s);
ws.set_write_timeout(10s);
```

## Watch out for what the read timeout means

`set_read_timeout()` applies to a single `read()` call. If no message arrives within that time, `read()` returns `ReadResult::Fail`. For connections where long idle periods are normal — waiting on notifications, for example — set a longer timeout, or reconnect from your application code when the read fails.

> Unresponsive-peer detection via Ping/Pong is a separate mechanism. See [W02. Set a WebSocket Heartbeat](../w02-websocket-ping) for details.

## How this differs from `Client`

For `Client`'s timeout configuration, see [C12. Set Timeouts](../c12-timeouts). The behavior and API are nearly identical, but `WebSocketClient` has no equivalent to `set_max_timeout()` for capping the whole request — once connected, the connection stays open for as long as you keep calling `read()`.
