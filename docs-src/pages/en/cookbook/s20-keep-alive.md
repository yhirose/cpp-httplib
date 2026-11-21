---
title: "S20. Tune Keep-Alive"
order: 39
status: "draft"
---

`httplib::Server` enables HTTP/1.1 Keep-Alive automatically. From the client's perspective, connections are reused — so they don't pay the TCP handshake cost on every request. When you need to tune the behavior, there are two setters.

## What you can configure

| API | Default | Meaning |
| --- | --- | --- |
| `set_keep_alive_max_count` | 100 | Max requests served over a single connection (0 for no limit) |
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
Shorten the timeout so idle connections drop and release their worker threads. If you want to keep them open, turn on keep-alive parking instead (see below).

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

By default, a Keep-Alive connection holds a worker thread for its entire lifetime. The pool adds threads under load, up to its maximum thread count (4× the base count by default). If open connections outnumber that maximum, new connections wait in the queue until one closes. For thread counts, see [S21. Configure the thread pool](../s21-thread-pool).

## Keep idle connections off the threads

> **Note:** Keep-alive parking is experimental. Its behavior may change in a future release.

```cpp
svr.set_keep_alive_parking(true); // call it before listen()
```

With keep-alive parking, a connection waiting for its next request is handed to an event loop instead of keeping its worker thread, and goes back to a worker when the request arrives. An idle connection then costs a socket and some memory (a few kilobytes, more with TLS) instead of a thread, and connections that outnumber the threads take turns instead of waiting for one to close. `SSLServer` supports it too. Defining `CPPHTTPLIB_KEEPALIVE_PARKING` as `true` turns it on for every server.

What changes with it:

- Consecutive requests on one connection may run on different threads, so don't keep per-connection state in `thread_local` variables.
- Handing the connection over to a worker adds roughly 10-20 µs to each request. It only shows with very light handlers and a client as near as loopback.
- A handler, a content provider and a WebSocket still hold their thread while they run.

The full list is in the [README](https://github.com/yhirose/cpp-httplib/blob/master/README.md#keep-alive-parking).

> **Note:** For the client side, see [C14. Understand connection reuse and Keep-Alive behavior](../c14-keep-alive). Even when the server closes the connection on timeout, the client reconnects automatically.
