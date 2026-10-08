---
title: "C14. Understand Connection Reuse and Keep-Alive"
order: 14
status: "draft"
---

By default, `httplib::Client` closes the connection after every request (it sends `Connection: close`). Call `set_keep_alive(true)` and the requests you send through the same instance share one TCP connection, so you don't pay the TCP and TLS handshake cost on every call.

## Enable Keep-Alive

```cpp
httplib::Client cli("https://api.example.com");
cli.set_keep_alive(true);

auto res1 = cli.Get("/users/1");
auto res2 = cli.Get("/users/2"); // reuses the same connection
auto res3 = cli.Get("/users/3"); // reuses the same connection
```

After that, just hold on to `cli`. Internally, the socket stays open across calls. The effect is especially noticeable over HTTPS, where the TLS handshake is expensive.

## Turn Keep-Alive back off

To go back to a fresh connection every time, call `set_keep_alive(false)`. This is the default behavior.

```cpp
cli.set_keep_alive(false);
```

## Don't create a `Client` per request

If you create a `Client` inside a loop and let it fall out of scope each iteration, you lose the reuse benefit. Create the instance outside the loop.

```cpp
// Bad: a new connection every iteration
for (auto id : ids) {
  httplib::Client cli("https://api.example.com");
  cli.set_keep_alive(true);
  cli.Get("/users/" + id);
}

// Good: the connection is reused
httplib::Client cli("https://api.example.com");
cli.set_keep_alive(true);
for (auto id : ids) {
  cli.Get("/users/" + id);
}
```

## Concurrent requests

If you want to send requests in parallel from multiple threads, give each thread its own `Client` instance. A single `Client` uses a single TCP connection, so firing concurrent requests at the same instance ends up serializing them anyway.

> **Note:** If the server closes the connection after its Keep-Alive timeout, cpp-httplib notices before it sends the next request and reconnects. You don't need to handle this in application code.
