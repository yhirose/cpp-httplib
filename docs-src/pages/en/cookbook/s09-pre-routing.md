---
title: "S09. Add Pre-Processing to All Routes"
order: 28
status: "draft"
---

Sometimes you want the same logic to run before every request — auth checks, logging, rate limiting. Register those with `set_pre_routing_handler()`.

## Basic usage

```cpp
svr.set_pre_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    std::cout << req.method << " " << req.path << std::endl;
    return httplib::Server::HandlerResponse::Unhandled;
  });
```

The pre-routing handler runs **before routing**. It catches every request — including ones that don't match any handler.

The `HandlerResponse` return value is key:

- Return `Unhandled` → continue normally (routing and the actual handler run)
- Return `Handled` → the response is considered complete, skip the rest

## Use it for authentication

Put your shared auth check in one place.

```cpp
svr.set_pre_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    if (req.path.rfind("/public", 0) == 0) {
      return httplib::Server::HandlerResponse::Unhandled; // no auth needed
    }

    auto auth = req.get_header_value("Authorization");
    if (auth.empty()) {
      res.status = 401;
      res.set_content("unauthorized", "text/plain");
      return httplib::Server::HandlerResponse::Handled;
    }

    return httplib::Server::HandlerResponse::Unhandled;
  });
```

If auth fails, return `Handled` to respond with 401 immediately. If it passes, return `Unhandled` and let routing take over.

## For per-route auth

If you want different auth rules per route rather than a single global check, `set_pre_request_handler()` is a better fit. See [S11. Authenticate per route with a pre-request handler](s11-pre-request).

> **Note:** If all you want is to modify the response, `set_post_routing_handler()` is the right tool. See [S10. Add response headers with a post-routing handler](s10-post-routing).
