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

`bind_to_port()` returns `false` on failure — typically when the port is already taken. Always check it.

```cpp
if (!svr.bind_to_port("0.0.0.0", 8080)) {
  std::cerr << "port already in use" << std::endl;
  return 1;
}
```

`listen_after_bind()` blocks until the server stops and returns `true` on a clean shutdown.

> **Note:** To auto-pick a free port, see S17. Bind to Any Available Port. Under the hood, that's just `bind_to_any_port()` + `listen_after_bind()`.
