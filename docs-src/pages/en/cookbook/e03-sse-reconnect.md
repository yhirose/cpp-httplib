---
title: "E03. Handle SSE Reconnection"
order: 49
status: "draft"
---

SSE connections drop for all sorts of network reasons. Clients automatically try to reconnect, so it's a good idea to make your server resume from where it left off.

## Read `Last-Event-ID`

When the client reconnects, it sends the ID of the last event it received in the `Last-Event-ID` header. The server reads that and picks up from the next one.

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  auto last_id = req.get_header_value("Last-Event-ID");
  int start = last_id.empty() ? 0 : std::stoi(last_id) + 1;

  res.set_chunked_content_provider(
    "text/event-stream",
    [start](size_t offset, httplib::DataSink &sink) mutable {
      static int next_id = 0;
      if (next_id < start) { next_id = start; }

      std::string msg = "id: " + std::to_string(next_id) + "\n"
                      + "data: event " + std::to_string(next_id) + "\n\n";
      sink.write(msg.data(), msg.size());
      ++next_id;

      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true;
    });
});
```

On the first connect, `Last-Event-ID` is empty, so start from `0`. On reconnect, resume from the next ID. Event history is the server's responsibility — you need to keep recent events around somewhere.

## Set the reconnect interval

Sending a `retry:` field tells the client how long to wait before reconnecting, in milliseconds.

```cpp
std::string msg = "retry: 5000\n\n";  // reconnect after 5 seconds
sink.write(msg.data(), msg.size());
```

Usually you send this once at the start. During peak load or maintenance windows, a longer retry interval helps reduce reconnect storms.

## Buffer recent events

To support reconnection, keep a rolling buffer of recent events on the server.

```cpp
struct EventBuffer {
  std::mutex mu;
  std::deque<std::pair<int, std::string>> events; // {id, data}
  int next_id = 0;

  void push(const std::string &data) {
    std::lock_guard<std::mutex> lock(mu);
    events.push_back({next_id++, data});
    if (events.size() > 1000) { events.pop_front(); }
  }

  std::vector<std::pair<int, std::string>> since(int id) {
    std::lock_guard<std::mutex> lock(mu);
    std::vector<std::pair<int, std::string>> out;
    for (const auto &e : events) {
      if (e.first >= id) { out.push_back(e); }
    }
    return out;
  }
};
```

When a client reconnects, call `since(last_id)` to send any events it missed.

## How much to keep

The buffer size is a tradeoff between memory and how far back a client can resume. It depends on the use case:

- Real-time chat: a few minutes to half an hour
- Notifications: the last N items
- Trading data: persist to a database and pull from there

> **Warning:** `Last-Event-ID` is a client-provided value — don't trust it blindly. If you read it as a number, validate the range. If it's a string, sanitize it.
