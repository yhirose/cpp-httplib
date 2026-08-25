---
title: "S01. Register GET / POST / PUT / DELETE Handlers"
order: 20
status: "draft"
---

With `httplib::Server`, you register a handler per HTTP method. Just pass a pattern and a lambda to `Get()`, `Post()`, `Put()`, or `Delete()`. For methods outside the built-in set, such as WebDAV's `PROPFIND`, use `CustomRoute()`.

## Basic usage

```cpp
#include <httplib.h>

int main() {
  httplib::Server svr;

  svr.Get("/hello", [](const httplib::Request &req, httplib::Response &res) {
    res.set_content("Hello, World!", "text/plain");
  });

  svr.Post("/api/items", [](const httplib::Request &req, httplib::Response &res) {
    // req.body holds the request body
    res.status = 201;
    res.set_content("Created", "text/plain");
  });

  svr.Put("/api/items/1", [](const httplib::Request &req, httplib::Response &res) {
    res.set_content("Updated", "text/plain");
  });

  svr.Delete("/api/items/1", [](const httplib::Request &req, httplib::Response &res) {
    res.status = 204;
  });

  svr.listen("0.0.0.0", 8080);
}
```

Handlers take `(const Request&, Response&)`. Use `res.set_content()` to set the body and Content-Type, and `res.status` for the status code. `listen()` starts the server and blocks.

## Read query parameters

```cpp
svr.Get("/search", [](const httplib::Request &req, httplib::Response &res) {
  auto q = req.get_param_value("q");
  auto limit = req.get_param_value("limit");
  res.set_content("q=" + q + ", limit=" + limit, "text/plain");
});
```

`req.get_param_value()` pulls a value from the query string. Use `req.has_param("q")` if you want to check existence first.

## Read request headers

```cpp
svr.Get("/me", [](const httplib::Request &req, httplib::Response &res) {
  auto ua = req.get_header_value("User-Agent");
  res.set_content("UA: " + ua, "text/plain");
});
```

To add a response header, use `res.set_header("Name", "Value")`.

## Handle HTTP methods outside the built-in set

The server rejects methods it does not know with `400 Bad Request`. To accept an extension method, such as the WebDAV methods of RFC 4918 or UPnP's `SUBSCRIBE`, register a handler with `CustomRoute()`. Registering the handler is what makes the server accept the method.

```cpp
svr.CustomRoute("PROPFIND", "/dav/:id",
                [](const httplib::Request &req, httplib::Response &res) {
                  // The request body is available as usual
                  auto id = req.path_params.at("id");
                  res.status = httplib::StatusCode::MultiStatus_207;
                  res.set_content(build_multistatus(req.body), "application/xml");
                });
```

Patterns work the same way as they do for `Get()`, so regular expressions and path parameters are both available. There is also a content reader overload, just like the one on `Post()`, for reading the body in chunks.

Five things to keep in mind:

- The method name has to be a valid HTTP method token (RFC 9110), and it must be registered before you call `listen()`
- `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `CONNECT`, `OPTIONS`, `TRACE`, `PATCH` and `PRI` cannot be registered here. Use the dedicated methods for those
- A rejected registration makes `is_valid()` return `false` and `listen()` fail, so the server never starts holding a handler that would never fire
- Static file serving and WebSocket upgrades stay `GET`/`HEAD` only
- `Allow` and WebDAV's `DAV:` header are not generated for you. Return them yourself with `Options()` if clients need them

> **Note:** `listen()` is a blocking call. To run it on a different thread, wrap it in `std::thread`. If you need non-blocking startup, see [S18. Control startup order with `listen_after_bind`](../s18-listen-after-bind).

> To use path parameters like `/users/:id`, see [S03. Use path parameters](../s03-path-params).
