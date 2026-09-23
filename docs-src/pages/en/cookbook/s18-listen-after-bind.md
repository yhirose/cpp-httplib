---
title: "S18. Control Startup Order with listen_after_bind"
order: 37
status: "draft"
---

Normally `svr.listen("0.0.0.0", 8080)` handles bind and listen in one shot. When you need to do something between the two, split them into two calls.

## Separate bind and listen

```cpp
httplib::Server svr;

svr.Get("/", [](const auto &, auto &res) { res.set_content("ok", "text/plain"); });

if (!svr.bind_to_port("0.0.0.0", 8080)) {
  std::cerr << "bind failed" << std::endl;
  return 1;
}

// bind is done here. accept hasn't started yet.
drop_privileges();
signal_ready_to_parent_process();

svr.listen_after_bind(); // start the accept loop
```

`bind_to_port()` reserves the port; `listen_after_bind()` actually starts accepting. Splitting them gives you a window between the two steps.

## Common use cases

**Privilege drop**: Binding to a port under 1024 requires root. Bind as root, drop to a normal user, and all subsequent request handling runs with reduced privileges.

```cpp
svr.bind_to_port("0.0.0.0", 80);
drop_privileges();
svr.listen_after_bind();
```

**Startup notification**: Tell the parent process or systemd "I'm ready" before starting to accept connections.

**Test synchronization**: In tests, you can reliably catch "the moment the server is bound" and start the client after that.

## Check the return values

`bind_to_port()` returns `false` on failure, for example when you don't have permission to bind to the port. Always check it.

```cpp
if (!svr.bind_to_port("0.0.0.0", 8080)) {
  std::cerr << "bind failed" << std::endl;
  return 1;
}
```

`listen_after_bind()` blocks until the server stops and returns `true` on a clean shutdown.

## Detect a port that's already in use

With the default settings, you can actually bind to a port another server is already using. That's because cpp-httplib sets `SO_REUSEPORT` (Linux, macOS) or `SO_REUSEADDR` (Windows) on the server socket. A restarted server can bind again right away. The flip side is that a second server on the same port starts without an error, and connections get split between the two.

To make `bind_to_port()` fail on a port in use, replace the socket options with `set_socket_options()`.

```cpp
svr.set_socket_options([](socket_t sock) {
#ifdef _WIN32
  httplib::set_socket_opt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
#else
  httplib::set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
#endif
});

if (!svr.bind_to_port("0.0.0.0", 8080)) {
  std::cerr << "port already in use" << std::endl;
  return 1;
}
```

`set_socket_options()` replaces the defaults entirely. Setting `SO_REUSEADDR` on Linux and macOS keeps the "restarted server can bind again right away" behavior.

> **Note:** `SO_REUSEADDR` alone isn't enough on Windows. Two sockets that both set it can bind to the same port, so use `SO_EXCLUSIVEADDRUSE` instead.

> **Note:** To auto-pick a free port, see [S17. Bind to any available port](../s17-bind-any-port). Under the hood, that's just `bind_to_any_port()` + `listen_after_bind()`.
