---
title: "S10. Add Response Headers with a Post-Routing Handler"
order: 29
status: "draft"
---

Sometimes you want to add shared headers to the response after the handler has run — CORS headers, security headers, a request ID, and so on. That's what `set_post_routing_handler()` is for.

## Basic usage

```cpp
svr.set_post_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    res.set_header("X-Request-ID", generate_request_id());
  });
```

The post-routing handler runs **after the route handler, before the response is sent**. From here you can call `res.set_header()` or `res.headers.erase()` to add or remove headers across every response in one place.

## Add CORS headers

CORS is a classic use case.

```cpp
svr.set_post_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  });
```

For the preflight `OPTIONS` requests, register a separate handler — or handle them in the pre-routing handler.

```cpp
svr.Options("/.*", [](const auto &req, auto &res) {
  res.status = 204;
});
```

## Bundle your security headers

Manage browser security headers in one spot.

```cpp
svr.set_post_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
  });
```

No matter which handler produced the response, the same headers get attached.

> **Note:** The post-routing handler also runs for responses that didn't match any route and for responses from error handlers. That's exactly what you want when you need certain headers on every response, guaranteed.
