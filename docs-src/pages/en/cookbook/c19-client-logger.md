---
title: "C19. Set a Logger on the Client"
order: 19
status: "draft"
---

To log requests sent and responses received by the client, use `set_logger()`. If you only care about errors, there's a separate `set_error_logger()`.

## Log requests and responses

```cpp
httplib::Client cli("https://api.example.com");

cli.set_logger([](const httplib::Request &req, const httplib::Response &res) {
  std::cout << req.method << " " << req.path
            << " -> " << res.status << std::endl;
});

auto res = cli.Get("/users");
```

The callback you pass to `set_logger()` fires once for each completed request. You get both the request and the response as arguments — so you can log the method, path, status, headers, body, or whatever else you need.

## Catch errors only

When a network-layer error happens (like `Error::Connection`), `set_logger()` is **not** called — there's no response to log. For those cases, use `set_error_logger()`.

```cpp
cli.set_error_logger([](const httplib::Error &err, const httplib::Request *req) {
  std::cerr << "error: " << httplib::to_string(err);
  if (req) {
    std::cerr << " (" << req->method << " " << req->path << ")";
  }
  std::cerr << std::endl;
});
```

The second argument `req` can be null — it happens when the failure occurred before the request was built. Always null-check before dereferencing.

## Use both together

A nice pattern is to log successes through one, failures through the other.

```cpp
cli.set_logger([](const auto &req, const auto &res) {
  std::cout << "[ok] " << req.method << " " << req.path
            << " " << res.status << std::endl;
});

cli.set_error_logger([](const auto &err, const auto *req) {
  std::cerr << "[ng] " << httplib::to_string(err);
  if (req) std::cerr << " " << req->method << " " << req->path;
  std::cerr << std::endl;
});
```

> **Note:** The log callbacks run synchronously on the same thread as the request. Heavy work inside them slows the request down — push it to a background queue if you need to do anything expensive.
