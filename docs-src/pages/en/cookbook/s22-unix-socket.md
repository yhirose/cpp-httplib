---
title: "S22. Talk Over a Unix Domain Socket"
order: 41
status: "draft"
---

When you want to talk only to other processes on the same host, a Unix domain socket is a nice fit. It avoids TCP overhead and uses filesystem permissions for access control. Local IPC and services sitting behind a reverse proxy are classic use cases.

## Server side

```cpp
httplib::Server svr;
svr.set_address_family(AF_UNIX);

svr.Get("/", [](const auto &, auto &res) {
  res.set_content("hello from unix socket", "text/plain");
});

svr.listen("/tmp/httplib.sock", 80);
```

Call `set_address_family(AF_UNIX)` first, then pass the socket file path as the first argument to `listen()`. The port number is unused but required by the signature — pass any value.

## Client side

```cpp
httplib::Client cli("/tmp/httplib.sock");
cli.set_address_family(AF_UNIX);

auto res = cli.Get("/");
if (res) {
  std::cout << res->body << std::endl;
}
```

Pass the socket file path to the `Client` constructor and call `set_address_family(AF_UNIX)`. Everything else works like a normal HTTP request.

## When to use it

- **Behind a reverse proxy**: An nginx-to-backend setup over a Unix socket is faster than TCP and sidesteps port management
- **Local-only APIs**: IPC between tools that shouldn't be reachable from outside
- **In-container IPC**: Process-to-process communication within the same pod or container
- **Dev environments**: No more worrying about port conflicts

## Clean up the socket file

A Unix domain socket creates a real file in the filesystem. It doesn't get removed on shutdown, so delete it before starting if needed.

```cpp
std::remove("/tmp/httplib.sock");
svr.listen("/tmp/httplib.sock", 80);
```

## Permissions

You control who can connect via the socket file's permissions.

```cpp
svr.listen("/tmp/httplib.sock", 80);
// from another process or thread
chmod("/tmp/httplib.sock", 0660); // owner and group only
```

> **Warning:** Some Windows versions support AF_UNIX, but the implementation and behavior differ by platform. Test thoroughly before running cross-platform in production.
