---
title: "E01. 实现 SSE 服务器"
order: 48
status: "draft"
---

Server-Sent Events (SSE) 是一种从服务器向客户端单向推送事件的简单协议。连接保持打开，服务器可以随时发送数据。它比 WebSocket 更轻量，并且完全在 HTTP 之内 —— 这是一个很好的组合。

cpp-httplib 没有专门的 SSE 服务器 API，但你可以用 `set_chunked_content_provider()` 和 `text/event-stream` 自己实现一个。

## 基本的 SSE 服务器

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

这里有三个要点：

1. Content-Type 是 `text/event-stream`
2. 消息格式为 `data: <content>\n\n`（两个换行用于分隔事件）
3. 每次 `sink.write()` 都会把数据交付给客户端

只要连接还活着，这个提供者 lambda 就会被持续调用。

## 连续不断的流

下面是一个简单的示例，每秒发送一次当前时间。

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

当客户端断开连接时，调用 `sink.done()` 来停止。详情见 [S16. 检测客户端断开连接](../s16-disconnect)。

## 通过注释行发送心跳

以 `:` 开头的行是 SSE 注释 —— 客户端会忽略它们，但它们能**让连接保持存活**。这对于防止代理和负载均衡器关闭空闲连接非常方便。

```cpp
// 每 30 秒一次心跳
if (tick_count % 30 == 0) {
  std::string ping = ": ping\n\n";
  sink.write(ping.data(), ping.size());
}
```

## 与线程池的关系

SSE 连接会保持打开，因此每个客户端都会占用一个工作线程。对于大量并发连接，请在线程池上启用动态伸缩。

```cpp
svr.new_task_queue = [] {
  return new httplib::ThreadPool(8, 128);
};
```

参见 [S21. 配置线程池](../s21-thread-pool)。

> **注意：** 当 `data:` 中包含换行时，请把它拆分成多个 `data:` 行 —— 每行一个。SSE 规范要求多行数据必须以这种方式传输。

> 关于事件名称，请参阅 [E02. 在 SSE 中使用命名事件](../e02-sse-event-names)。关于客户端侧，请参阅 [E04. 在客户端接收 SSE](../e04-sse-client)。
