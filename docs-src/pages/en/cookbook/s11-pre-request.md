---
title: "S11. Authenticate Per Route with a Pre-Request Handler"
order: 30
status: "draft"
---

The `set_pre_routing_handler()` from S09 runs **before routing**, so it has no idea which route matched. When you want per-route behavior, `set_pre_request_handler()` is what you need.

## Pre-routing vs. pre-request

| Hook | When it runs | Route info |
| --- | --- | --- |
| `set_pre_routing_handler` | Before routing | Not available |
| `set_pre_request_handler` | After routing, right before the route handler | Available via `req.matched_route` |

In a pre-request handler, `req.matched_route` holds the **pattern string** that matched. You can vary behavior based on the route definition itself.

## Switch auth per route

```cpp
svr.set_pre_request_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    // require auth for routes starting with /admin
    if (req.matched_route.rfind("/admin", 0) == 0) {
      auto token = req.get_header_value("Authorization");
      if (!is_admin_token(token)) {
        res.status = 403;
        res.set_content("forbidden", "text/plain");
        return httplib::Server::HandlerResponse::Handled;
      }
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });
```

`matched_route` is the pattern **before** path parameters are expanded (e.g. `/admin/users/:id`). You compare against the route definition, not the actual request path, so IDs or names don't throw you off.

## Return values

Same as pre-routing — return `HandlerResponse`.

- `Unhandled`: continue (the route handler runs)
- `Handled`: we're done, skip the route handler

## Passing auth info to the route handler

To pass decoded user info into the route handler, use `res.user_data`. See S12. Pass Data Between Handlers with `res.user_data`.
