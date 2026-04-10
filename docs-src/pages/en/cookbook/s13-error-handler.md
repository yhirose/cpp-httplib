---
title: "S13. Return a Custom Error Page"
order: 32
status: "draft"
---

To customize the response for 4xx or 5xx errors, use `set_error_handler()`. You can replace the plain default error page with your own HTML or JSON.

## Basic usage

```cpp
svr.set_error_handler([](const httplib::Request &req, httplib::Response &res) {
  auto body = "<h1>Error " + std::to_string(res.status) + "</h1>";
  res.set_content(body, "text/html");
});
```

The error handler runs right before an error response is sent — any time `res.status` is 4xx or 5xx. Replace the body with `res.set_content()` and every error response uses the same template.

## Branch by status code

```cpp
svr.set_error_handler([](const httplib::Request &req, httplib::Response &res) {
  if (res.status == 404) {
    res.set_content("<h1>Not Found</h1><p>" + req.path + "</p>", "text/html");
  } else if (res.status >= 500) {
    res.set_content("<h1>Server Error</h1>", "text/html");
  }
});
```

Checking `res.status` lets you show a custom message for 404s and a "contact support" link for 5xx errors.

## JSON error responses

For an API server, you probably want errors as JSON.

```cpp
svr.set_error_handler([](const httplib::Request &req, httplib::Response &res) {
  nlohmann::json j = {
    {"error", true},
    {"status", res.status},
    {"path", req.path},
  };
  res.set_content(j.dump(), "application/json");
});
```

Now every error comes back in a consistent JSON shape.

> **Note:** `set_error_handler()` also fires for 500 responses caused by exceptions thrown from a route handler. To get at the exception itself, combine it with `set_exception_handler()`. See S14. Catch Exceptions.
