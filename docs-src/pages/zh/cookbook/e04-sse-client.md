---
title: "E04. 在客户端接收 SSE"
order: 51
status: "draft"
---

cpp-httplib 自带一个专用的 `sse::SSEClient` 类。它会替你处理自动重连、按事件名分发以及 `Last-Event-ID` 跟踪 —— 因此接收 SSE 毫不费力。

## 基本用法

```cpp
#include <httplib.h>

httplib::Client cli("http://localhost:8080");
httplib::sse::SSEClient sse(cli, "/events");

sse.on_message([](const httplib::sse::SSEMessage &msg) {
  std::cout << "data: " << msg.data << std::endl;
});

sse.start(); // 阻塞
```

用一个 `Client` 和一个路径构造 `SSEClient`，用 `on_message()` 注册回调，然后调用 `start()`。事件循环随即启动，并在连接断开时自动重连。

## 按事件名分发

当服务器发送带有 `event:` 字段的事件时，可以通过 `on_event()` 为每个名称注册一个处理器。

```cpp
sse.on_event("message", [](const auto &msg) {
  std::cout << "chat: " << msg.data << std::endl;
});

sse.on_event("join", [](const auto &msg) {
  std::cout << msg.data << " joined" << std::endl;
});

sse.on_event("leave", [](const auto &msg) {
  std::cout << msg.data << " left" << std::endl;
});
```

`on_message()` 充当无名事件（默认的 `message` 类型）的通用兜底处理。

## 连接生命周期与错误

```cpp
sse.on_open([] {
  std::cout << "connected" << std::endl;
});

sse.on_error([](httplib::Error err) {
  std::cerr << "error: " << httplib::to_string(err) << std::endl;
});
```

可以挂钩连接打开和错误事件。即使错误处理器被触发，`SSEClient` 也会在后台持续尝试重连。

## 异步运行

如果你不想阻塞主线程，请使用 `start_async()`。

```cpp
sse.start_async();

// 主线程继续做其他事情
do_other_work();

// 完成后停止它
sse.stop();
```

`start_async()` 会派生一个后台线程来运行事件循环。使用 `stop()` 干净地关闭它。

## 配置重连

你可以调节重连间隔和最大重试次数。

```cpp
sse.set_reconnect_interval(5000);    // 5 秒
sse.set_max_reconnect_attempts(10);  // 最多 10 次（0 = 不限）
```

如果服务器发送了 `retry:` 字段，则以该字段为准。

## 自动的 Last-Event-ID

`SSEClient` 会在内部跟踪每个收到事件的 `id`，并在重连时把它作为 `Last-Event-ID` 发回。只要服务器发送的事件带有 `id:`，这一切都会自动生效。

```cpp
std::cout << "last id: " << sse.last_event_id() << std::endl;
```

使用 `last_event_id()` 读取当前值。

> **注意：** `SSEClient::start()` 会阻塞，这对于一次性的命令行工具来说没问题。对于 GUI 应用或嵌入到服务器中的场景，`start_async()` + `stop()` 这一对是常见的用法。

> 关于服务器侧，请参阅 [E01. 实现 SSE 服务器](../e01-sse-server)。
