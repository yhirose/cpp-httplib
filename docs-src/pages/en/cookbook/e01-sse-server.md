---
title: "E01. Implement an SSE Server"
order: 47
status: "draft"
---

Server-Sent Events (SSE) is a simple protocol for pushing events one-way from server to client. The connection stays open, and the server can send data whenever it wants. It's lighter than WebSocket and fits entirely within HTTP — a nice combination.

cpp-httplib doesn't have a dedicated SSE server API, but you can implement one with `set_chunked_content_provider()` and `text/event-stream`.

## Basic SSE server

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/event-stream",
    [](size_t offset, httplib::DataSink &sink) {
      std::string message = "data: hello\n\n";
      sink.write(message.data(), message.size());
      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true;
    });
});
```

Three things matter here:

1. Content-Type is `text/event-stream`
2. Messages follow the format `data: <content>\n\n` (the double newline separates events)
3. Each `sink.write()` delivers data to the client

The provider lambda keeps being called as long as the connection is alive.

## A continuous stream

Here's a simple example that sends the current time once per second.

```cpp
svr.Get("/time", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/event-stream",
    [&req](size_t offset, httplib::DataSink &sink) {
      if (req.is_connection_closed()) {
        sink.done();
        return true;
      }

      auto now = std::chrono::system_clock::now();
      auto t = std::chrono::system_clock::to_time_t(now);
      std::string msg = "data: " + std::string(std::ctime(&t)) + "\n";
      sink.write(msg.data(), msg.size());

      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true;
    });
});
```

When the client disconnects, call `sink.done()` to stop. Details in S16. Detect When the Client Has Disconnected.

## Heartbeats via comment lines

Lines starting with `:` are SSE comments — clients ignore them, but they **keep the connection alive**. Handy for preventing proxies and load balancers from closing idle connections.

```cpp
// heartbeat every 30 seconds
if (tick_count % 30 == 0) {
  std::string ping = ": ping\n\n";
  sink.write(ping.data(), ping.size());
}
```

## Relationship with the thread pool

SSE connections stay open, so each client holds a worker thread. For lots of concurrent connections, enable dynamic scaling on the thread pool.

```cpp
svr.new_task_queue = [] {
  return new httplib::ThreadPool(8, 128);
};
```

See S21. Configure the Thread Pool.

> **Note:** When `data:` contains newlines, split it into multiple `data:` lines — one per line. This is how the SSE spec requires multiline data to be transmitted.

> For event names, see E02. Use Named Events in SSE. For the client side, see E04. Receive SSE on the Client.
