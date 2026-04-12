---
title: "S17. Bind to Any Available Port"
order: 36
status: "draft"
---

Standing up a test server often hits port conflicts. With `bind_to_any_port()`, you let the OS pick a free port and then read back which one it gave you.

## Basic usage

```cpp
httplib::Server svr;

svr.Get("/", [](const auto &req, auto &res) {
  res.set_content("hello", "text/plain");
});

int port = svr.bind_to_any_port("0.0.0.0");
std::cout << "listening on port " << port << std::endl;

svr.listen_after_bind();
```

`bind_to_any_port()` is equivalent to passing `0` as the port — the OS assigns a free one. The return value is the port actually used.

After that, call `listen_after_bind()` to start accepting. You can't combine bind and listen into a single call here, so you work in two steps.

## Useful in tests

This pattern is great for tests that spin up a server and hit it.

```cpp
httplib::Server svr;
svr.Get("/ping", [](const auto &, auto &res) { res.set_content("pong", "text/plain"); });

int port = svr.bind_to_any_port("127.0.0.1");
std::thread t([&] { svr.listen_after_bind(); });

// run the test while the server is up on another thread
httplib::Client cli("127.0.0.1", port);
auto res = cli.Get("/ping");
assert(res && res->body == "pong");

svr.stop();
t.join();
```

Because the port is assigned at runtime, parallel test runs don't collide.

> **Note:** `bind_to_any_port()` returns `-1` on failure (permission errors, no available ports, etc.). Always check the return value.

> To stop the server, see [S19. Shut down gracefully](s19-graceful-shutdown).
