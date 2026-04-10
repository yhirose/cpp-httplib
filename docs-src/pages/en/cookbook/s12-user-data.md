---
title: "S12. Pass Data Between Handlers with res.user_data"
order: 31
status: "draft"
---

Say your pre-request handler decodes an auth token and you want the route handler to use the result. That "data handoff between handlers" is what `res.user_data` is for — it holds values of arbitrary types.

## Basic usage

```cpp
struct AuthUser {
  std::string id;
  std::string name;
  bool is_admin;
};

svr.set_pre_request_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    auto token = req.get_header_value("Authorization");
    auto user = decode_token(token); // decode the auth token
    res.user_data.set("user", user);
    return httplib::Server::HandlerResponse::Unhandled;
  });

svr.Get("/me", [](const httplib::Request &req, httplib::Response &res) {
  auto *user = res.user_data.get<AuthUser>("user");
  if (!user) {
    res.status = 401;
    return;
  }
  res.set_content("Hello, " + user->name, "text/plain");
});
```

`user_data.set()` stores a value of any type, and `user_data.get<T>()` retrieves it. If you give the wrong type you get `nullptr` back — so be careful.

## Typical value types

Strings, numbers, structs, `std::shared_ptr` — anything copyable or movable works.

```cpp
res.user_data.set("user_id", std::string{"42"});
res.user_data.set("is_admin", true);
res.user_data.set("started_at", std::chrono::steady_clock::now());
```

## Where to set, where to read

The usual flow is: set it in `set_pre_routing_handler()` or `set_pre_request_handler()`, read it in the route handler. Pre-request runs after routing, so you can combine it with `req.matched_route` to set values only for specific routes.

## A gotcha

`user_data` lives on `Response`, not `Request`. That's because handlers get `Response&` (mutable) but only `const Request&`. It looks odd at first, but it makes sense once you think of it as "the mutable context shared between handlers."

> **Warning:** `user_data.get<T>()` returns `nullptr` when the type doesn't match. Use the exact same type on set and get. Storing as `AuthUser` and fetching as `const AuthUser` won't work.
