---
title: "E02. 在 SSE 中使用命名事件"
order: 49
status: "draft"
---

SSE 允许你在同一条流上发送多种类型的事件。用 `event:` 字段给每个事件起一个名字，客户端就能按类型分发到不同的处理器。这在聊天应用中的“新消息”、“用户加入”、“用户离开”之类场景中非常好用。

## 发送带名称的事件

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

一条消息的结构是 `event:` → `data:` → 空行。如果你省略 `event:`，客户端会把它当作默认的 `"message"` 事件来处理。

## 为重连附加 ID

当你包含 `id:` 字段时，客户端会在重连时自动把它作为 `Last-Event-ID` 发回来，告诉服务器“我读到这里了”。

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

ID 的格式由你决定。单调递增的计数器或 UUID 都可以 —— 只要在服务器侧选择唯一且可排序的值即可。详情见 [E03. 处理 SSE 重连](../e03-sse-reconnect)。

## 在 data 中使用 JSON 负载

对于结构化数据，通常的做法是把 JSON 放进 `data:`。

```cpp
nlohmann::json payload = {
  {"user", "alice"},
  {"text", "Hello!"},
};
send_event(sink, "message", payload.dump(), "42");
```

在客户端，把收到的 `data` 解析为 JSON，就能还原出原来的对象。

## 包含换行的数据

如果数据值中包含换行，请把它拆分成多个 `data:` 行。

```cpp
std::string msg = "data: line1\n"
                  "data: line2\n"
                  "data: line3\n\n";
sink.write(msg.data(), msg.size());
```

在客户端侧，这些内容会作为一个带换行的 `data` 字符串返回。

> **注意：** 使用 `event:` 可以让客户端侧的分发更清晰，它也有助于在浏览器 DevTools 中调试 —— 事件更容易按类型过滤。这在调试时比你想象的更重要。
