---
title: "E02. Use Named Events in SSE"
order: 48
status: "draft"
---

SSE lets you send multiple kinds of events over the same stream. Give each one a name with the `event:` field, and the client can dispatch to a different handler per type. Great for things like "new message", "user joined", "user left" in a chat app.

## Send events with names

```cpp
auto send_event = [](httplib::DataSink &sink,
                     const std::string &event,
                     const std::string &data) {
  std::string msg = "event: " + event + "\n"
                  + "data: " + data + "\n\n";
  sink.write(msg.data(), msg.size());
};

svr.Get("/chat/stream", [&](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/event-stream",
    [&, send_event](size_t offset, httplib::DataSink &sink) {
      send_event(sink, "message", "Hello!");
      std::this_thread::sleep_for(std::chrono::seconds(2));
      send_event(sink, "join", "alice");
      std::this_thread::sleep_for(std::chrono::seconds(2));
      send_event(sink, "leave", "bob");
      std::this_thread::sleep_for(std::chrono::seconds(2));
      return true;
    });
});
```

A message is `event:` → `data:` → blank line. If you omit `event:`, the client treats it as a default `"message"` event.

## Attach IDs for reconnect

When you include an `id:` field, the client automatically sends it back as `Last-Event-ID` on reconnect, telling the server "here's how far I got."

```cpp
auto send_event = [](httplib::DataSink &sink,
                     const std::string &event,
                     const std::string &data,
                     const std::string &id) {
  std::string msg = "id: " + id + "\n"
                  + "event: " + event + "\n"
                  + "data: " + data + "\n\n";
  sink.write(msg.data(), msg.size());
};

send_event(sink, "message", "Hello!", "42");
```

The ID format is up to you. Monotonic counters or UUIDs both work — just pick something unique and orderable on the server side. See [E03. Handle SSE reconnection](e03-sse-reconnect) for details.

## JSON payloads in data

For structured data, the usual move is to put JSON in `data:`.

```cpp
nlohmann::json payload = {
  {"user", "alice"},
  {"text", "Hello!"},
};
send_event(sink, "message", payload.dump(), "42");
```

On the client, parse the incoming `data` as JSON to get the original object back.

## Data with newlines

If the data value contains newlines, split it across multiple `data:` lines.

```cpp
std::string msg = "data: line1\n"
                  "data: line2\n"
                  "data: line3\n\n";
sink.write(msg.data(), msg.size());
```

On the client side, these come back as a single `data` string with newlines.

> **Note:** Using `event:` makes client-side dispatch cleaner, but it also helps in the browser DevTools — events are easier to filter by type. That matters more than you'd expect while debugging.
