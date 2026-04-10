---
title: "C13. Set an Overall Timeout"
order: 13
status: "draft"
---

The three timeouts from C12. Set Timeouts all apply to a single `send` or `recv` call. To cap the total time a request can take, use `set_max_timeout()`.

## Basic usage

```cpp
httplib::Client cli("http://localhost:8080");

cli.set_max_timeout(5000); // 5 seconds (in milliseconds)

auto res = cli.Get("/slow-endpoint");
```

The value is in milliseconds. Connection, send, and receive together — the whole request is aborted if it exceeds the limit.

## Use `std::chrono`

There's also an overload that takes a `std::chrono` duration.

```cpp
using namespace std::chrono_literals;
cli.set_max_timeout(5s);
```

## When to use which

`set_read_timeout` fires when no data arrives for a while. If data keeps trickling in bit by bit, it will never fire. An endpoint that sends one byte per second can make `set_read_timeout` useless no matter how short you set it.

`set_max_timeout` caps elapsed time, so it handles those cases cleanly. It's great for calls to external APIs or anywhere you don't want users waiting forever.

```cpp
cli.set_connection_timeout(3s);
cli.set_read_timeout(10s);
cli.set_max_timeout(30s); // abort if the whole request takes over 30s
```

> **Note:** `set_max_timeout()` works alongside the regular timeouts. Short stalls get caught by `set_read_timeout`; long-running requests get capped by `set_max_timeout`. Use both for a safety net.
