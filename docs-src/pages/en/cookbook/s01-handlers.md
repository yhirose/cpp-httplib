---
title: "S01. Register GET / POST / PUT / DELETE Handlers"
order: 20
status: "draft"
---

With `httplib::Server`, you register a handler per HTTP method. Just pass a pattern and a lambda to `Get()`, `Post()`, `Put()`, or `Delete()`.

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

> **Note:** `listen()` is a blocking call. To run it on a different thread, wrap it in `std::thread`. If you need non-blocking startup, see [S18. Control startup order with `listen_after_bind`](s18-listen-after-bind).

> To use path parameters like `/users/:id`, see [S03. Use path parameters](s03-path-params).
