---
title: "S14. Catch Exceptions"
order: 33
status: "draft"
---

When a route handler throws, cpp-httplib keeps the server running and responds with 500. By default, though, very little of the error information reaches the client. `set_exception_handler()` lets you intercept exceptions and build your own response.

## Basic usage

```cpp
svr.set_exception_handler(
  [](const httplib::Request &req, httplib::Response &res,
     std::exception_ptr ep) {
    try {
      std::rethrow_exception(ep);
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(std::string("error: ") + e.what(), "text/plain");
    } catch (...) {
      res.status = 500;
      res.set_content("unknown error", "text/plain");
    }
  });
```

The handler receives a `std::exception_ptr`. The idiomatic move is to rethrow it with `std::rethrow_exception()` and catch by type. You can vary status code and message based on the exception type.

## Branch on custom exception types

If you throw your own exception types, you can map them to 400 or 404 responses.

```cpp
struct NotFound : std::runtime_error {
  using std::runtime_error::runtime_error;
};
struct BadRequest : std::runtime_error {
  using std::runtime_error::runtime_error;
};

svr.set_exception_handler(
  [](const auto &req, auto &res, std::exception_ptr ep) {
    try {
      std::rethrow_exception(ep);
    } catch (const NotFound &e) {
      res.status = 404;
      res.set_content(e.what(), "text/plain");
    } catch (const BadRequest &e) {
      res.status = 400;
      res.set_content(e.what(), "text/plain");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content("internal error", "text/plain");
    }
  });
```

Now throwing `NotFound("user not found")` inside a handler is enough to return 404. No per-handler try/catch needed.

## Relationship with set_error_handler

`set_exception_handler()` runs the moment the exception is thrown. After that, if `res.status` is 4xx or 5xx, `set_error_handler()` also runs. The order is `exception_handler` → `error_handler`. Think of their roles as:

- **Exception handler**: interpret the exception, set the status and message
- **Error handler**: see the status and wrap it in the shared template

> **Note:** Without an exception handler, cpp-httplib returns a default 500 response and the exception details never make it to logs. Always set one for anything you want to debug.
