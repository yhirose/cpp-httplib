---
title: "S20. Tune Keep-Alive"
order: 39
status: "draft"
---

`httplib::Server` enables HTTP/1.1 Keep-Alive automatically. From the client's perspective, connections are reused — so they don't pay the TCP handshake cost on every request. When you need to tune the behavior, there are two setters.

## What you can configure

| API | Default | Meaning |
| --- | --- | --- |
| `set_keep_alive_max_count` | 100 | Max requests served over a single connection |
| `set_keep_alive_timeout` | 5s | How long an idle connection is kept before closing |

## Basic usage

```cpp
httplib::Server svr;

svr.set_keep_alive_max_count(20);
svr.set_keep_alive_timeout(10); // 10 seconds

svr.listen("0.0.0.0", 8080);
```

`set_keep_alive_timeout()` also has a `std::chrono` overload.

```cpp
using namespace std::chrono_literals;
svr.set_keep_alive_timeout(10s);
```

## Tuning ideas

**Too many idle connections eating resources**  
Shorten the timeout so idle connections drop and release their worker threads.

```cpp
svr.set_keep_alive_timeout(2s);
```

**API is hammered and you want max reuse**  
Raising the per-connection request cap improves benchmark numbers.

```cpp
svr.set_keep_alive_max_count(1000);
```

**Never reuse connections**  
Set `set_keep_alive_max_count(1)` and every request gets its own connection. Mostly only useful for debugging or compatibility testing.

## Relationship with the thread pool

A Keep-Alive connection holds a worker thread for its entire lifetime. If `connections × concurrent requests` exceeds the thread pool size, new requests wait. For thread counts, see S21. Configure the Thread Pool.

> **Note:** For the client side, see C14. Understand Connection Reuse and Keep-Alive Behavior. Even when the server closes the connection on timeout, the client reconnects automatically.
