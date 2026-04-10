---
title: "C14. Understand Connection Reuse and Keep-Alive"
order: 14
status: "draft"
---

When you send multiple requests through the same `httplib::Client` instance, the TCP connection is reused automatically. HTTP/1.1 Keep-Alive does the work for you — you don't pay the TCP and TLS handshake cost on every call.

## Connections are reused automatically

```cpp
httplib::Client cli("https://api.example.com");

auto res1 = cli.Get("/users/1");
auto res2 = cli.Get("/users/2"); // reuses the same connection
auto res3 = cli.Get("/users/3"); // reuses the same connection
```

No special config required. Just hold on to `cli` — internally, the socket stays open across calls. The effect is especially noticeable over HTTPS, where the TLS handshake is expensive.

## Disable Keep-Alive explicitly

To force a fresh connection every time, call `set_keep_alive(false)`. Mostly useful for testing.

```cpp
cli.set_keep_alive(false);
```

For normal use, leave it on (the default).

## Don't create a `Client` per request

If you create a `Client` inside a loop and let it fall out of scope each iteration, you lose the reuse benefit. Create the instance outside the loop.

```cpp
// Bad: a new connection every iteration
for (auto id : ids) {
  httplib::Client cli("https://api.example.com");
  cli.Get("/users/" + id);
}

// Good: the connection is reused
httplib::Client cli("https://api.example.com");
for (auto id : ids) {
  cli.Get("/users/" + id);
}
```

## Concurrent requests

If you want to send requests in parallel from multiple threads, give each thread its own `Client` instance. A single `Client` uses a single TCP connection, so firing concurrent requests at the same instance ends up serializing them anyway.

> **Note:** If the server closes the connection after its Keep-Alive timeout, cpp-httplib reconnects and retries transparently. You don't need to handle this in application code.
