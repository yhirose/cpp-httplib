---
title: "C12. Set Timeouts"
order: 12
status: "draft"
---

The client has three kinds of timeouts, each set independently.

| Kind | API | Default | Meaning |
| --- | --- | --- | --- |
| Connection | `set_connection_timeout` | 300s | Time to wait for the TCP connection to establish |
| Read | `set_read_timeout` | 300s | Time to wait for a single `recv` when receiving the response |
| Write | `set_write_timeout` | 5s | Time to wait for a single `send` when sending the request |

## Basic usage

```cpp
httplib::Client cli("http://localhost:8080");

cli.set_connection_timeout(5, 0);  // 5 seconds
cli.set_read_timeout(10, 0);       // 10 seconds
cli.set_write_timeout(10, 0);      // 10 seconds

auto res = cli.Get("/api/data");
```

Pass seconds and microseconds as two arguments. If you don't need the sub-second part, you can omit the second argument.

## Use `std::chrono`

There's also an overload that takes a `std::chrono` duration directly. It's easier to read — recommended.

```cpp
using namespace std::chrono_literals;

cli.set_connection_timeout(5s);
cli.set_read_timeout(10s);
cli.set_write_timeout(500ms);
```

## Watch out for the long 300s default

Connection and read timeouts default to **300 seconds (5 minutes)**. If the server hangs, you'll be waiting five minutes by default. Shorter values are usually a better idea.

```cpp
cli.set_connection_timeout(3s);
cli.set_read_timeout(10s);
```

> **Warning:** The read timeout covers a single receive call — not the whole request. If data keeps trickling in during a large download, the request can take half an hour without ever hitting the timeout. To cap the total request time, use [C13. Set an overall timeout](c13-max-timeout).
