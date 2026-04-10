---
title: "E04. Receive SSE on the Client"
order: 50
status: "draft"
---

cpp-httplib ships a dedicated `sse::SSEClient` class. It handles auto-reconnect, per-event-name dispatch, and `Last-Event-ID` tracking for you — so receiving SSE is painless.

## Basic usage

```cpp
#include <httplib.h>

httplib::Client cli("http://localhost:8080");
httplib::sse::SSEClient sse(cli, "/events");

sse.on_message([](const httplib::sse::SSEMessage &msg) {
  std::cout << "data: " << msg.data << std::endl;
});

sse.start(); // blocking
```

Build an `SSEClient` with a `Client` and a path, register a callback with `on_message()`, and call `start()`. The event loop kicks in and automatically reconnects if the connection drops.

## Dispatch by event name

When the server sends events with an `event:` field, register a handler per name via `on_event()`.

```cpp
sse.on_event("message", [](const auto &msg) {
  std::cout << "chat: " << msg.data << std::endl;
});

sse.on_event("join", [](const auto &msg) {
  std::cout << msg.data << " joined" << std::endl;
});

sse.on_event("leave", [](const auto &msg) {
  std::cout << msg.data << " left" << std::endl;
});
```

`on_message()` serves as a generic fallback for unnamed events (the default `message` type).

## Connection lifecycle and errors

```cpp
sse.on_open([] {
  std::cout << "connected" << std::endl;
});

sse.on_error([](httplib::Error err) {
  std::cerr << "error: " << httplib::to_string(err) << std::endl;
});
```

Hook into connection open and error events. Even when the error handler fires, `SSEClient` keeps trying to reconnect in the background.

## Run asynchronously

If you don't want to block the main thread, use `start_async()`.

```cpp
sse.start_async();

// main thread continues to do other things
do_other_work();

// when you're done, stop it
sse.stop();
```

`start_async()` spawns a background thread to run the event loop. Use `stop()` to shut it down cleanly.

## Configure reconnection

You can tune the reconnect interval and maximum retries.

```cpp
sse.set_reconnect_interval(5000);    // 5 seconds
sse.set_max_reconnect_attempts(10);  // up to 10 (0 = unlimited)
```

If the server sends a `retry:` field, that takes precedence.

## Automatic Last-Event-ID

`SSEClient` tracks the `id` of each received event internally and sends it back as `Last-Event-ID` on reconnect. As long as the server sends events with `id:`, this all works automatically.

```cpp
std::cout << "last id: " << sse.last_event_id() << std::endl;
```

Use `last_event_id()` to read the current value.

> **Note:** `SSEClient::start()` blocks, which is fine for a one-off command-line tool. For GUI apps or embedded in a server, the `start_async()` + `stop()` pair is the usual pattern.

> For the server side, see E01. Implement an SSE Server.
