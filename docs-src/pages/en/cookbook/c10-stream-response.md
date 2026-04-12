---
title: "C10. Receive a Response as a Stream"
order: 10
status: "draft"
---

To receive a response body chunk by chunk, use a `ContentReceiver`. It's the obvious choice for large files, but it's equally handy for NDJSON (newline-delimited JSON) or log streams where you want to start processing data as it arrives.

## Process each chunk

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Get("/logs/stream",
  [](const char *data, size_t len) {
    std::cout.write(data, len);
    std::cout.flush();
    return true; // return false to stop receiving
  });
```

Data arrives in the lambda in the order it's received from the server. Return `false` from the callback to stop the download partway through.

## Parse NDJSON line by line

Here's a buffered approach for processing newline-delimited JSON one line at a time.

```cpp
std::string buffer;

auto res = cli.Get("/events",
  [&](const char *data, size_t len) {
    buffer.append(data, len);
    size_t pos;
    while ((pos = buffer.find('\n')) != std::string::npos) {
      auto line = buffer.substr(0, pos);
      buffer.erase(0, pos + 1);
      if (!line.empty()) {
        auto j = nlohmann::json::parse(line);
        handle_event(j);
      }
    }
    return true;
  });
```

Accumulate into a buffer, then pull out and parse one line each time you see a newline. This is the standard pattern for consuming a streaming API in real time.

> **Warning:** When you pass a `ContentReceiver`, `res->body` stays **empty**. Store or process the body inside the callback yourself.

> To track download progress, combine this with [C11. Use the progress callback](c11-progress-callback).
> For Server-Sent Events (SSE), see [E04. Receive SSE on the client](e04-sse-client).
