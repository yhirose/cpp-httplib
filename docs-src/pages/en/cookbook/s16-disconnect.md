---
title: "S16. Detect When the Client Has Disconnected"
order: 35
status: "draft"
---

During a long-running response, the client might close the connection. There's no point continuing to do work no one's waiting for. In cpp-httplib, check `req.is_connection_closed()`.

## Basic usage

```cpp
svr.Get("/long-task", [](const httplib::Request &req, httplib::Response &res) {
  for (int i = 0; i < 1000; ++i) {
    if (req.is_connection_closed()) {
      std::cout << "client disconnected" << std::endl;
      return;
    }

    do_heavy_work(i);
  }

  res.set_content("done", "text/plain");
});
```

`is_connection_closed` is a `std::function<bool()>`, so call it with `()`. It returns `true` when the client is gone.

## With a streaming response

The same check works inside `set_chunked_content_provider()`. Capture the request by reference.

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/event-stream",
    [&req](size_t offset, httplib::DataSink &sink) {
      if (req.is_connection_closed()) {
        sink.done();
        return true;
      }

      auto event = generate_next_event();
      sink.write(event.data(), event.size());
      return true;
    });
});
```

When you detect a disconnect, call `sink.done()` to stop the provider from being called again.

## How often should you check?

The call itself is cheap, but calling it in a tight inner loop doesn't add much value. Check at **boundaries where interrupting is safe** — after producing a chunk, after a database query, etc.

> **Warning:** `is_connection_closed()` is not guaranteed to reflect reality instantly. Because of how TCP works, sometimes you only notice the disconnect when you try to send. Don't expect pixel-perfect real-time detection — think of it as "we'll notice eventually."
