---
title: "C10. 以流的形式接收响应"
order: 10
status: "draft"
---

要逐块接收响应体，请使用 `ContentReceiver`。它对大文件来说是显而易见的选择，但对于 NDJSON（换行分隔的 JSON）或日志流同样方便——在这些场景中，你希望数据一到就开始处理。

## 处理每个数据块

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Get("/logs/stream",
  [](const char *data, size_t len) {
    std::cout.write(data, len);
    std::cout.flush();
    return true; // 返回 false 可停止接收
  });
```

数据会按从服务器接收到的顺序进入 lambda。从回调中返回 `false` 可以在下载中途停止。

## 逐行解析 NDJSON

下面是一种带缓冲的做法，用于一次处理一行换行分隔的 JSON。

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

累积到缓冲区中，然后每次遇到换行时取出一行并解析。这是实时消费流式 API 的标准模式。

> **警告：** 当你传入 `ContentReceiver` 时，`res->body` 会保持为**空**。你需要在回调内部自行存储或处理响应体。

> 要跟踪下载进度，可以把它与 [C11. 使用进度回调](../c11-progress-callback) 结合使用。
> 关于 Server-Sent Events（SSE），请参见 [E04. 在客户端接收 SSE](../e04-sse-client)。
