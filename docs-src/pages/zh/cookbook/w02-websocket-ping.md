---
title: "W02. 设置 WebSocket 心跳"
order: 53
status: "draft"
---

WebSocket 连接会长时间保持打开，代理或负载均衡器有时会因为连接“空闲”而将其断开。为防止这种情况，你周期性地发送 Ping 帧来保活。cpp-httplib 可以为你自动完成这件事。

## 服务器端

```cpp
svr.set_websocket_ping_interval(30); // 每 30 秒 ping 一次

svr.WebSocket("/chat", [](const auto &req, auto &ws) {
  // ...
});
```

只需传入以秒为单位的间隔。该服务器接受的每个 WebSocket 连接都会按此间隔被 ping。

还有一个 `std::chrono` 重载。

```cpp
using namespace std::chrono_literals;
svr.set_websocket_ping_interval(30s);
```

## 客户端

客户端有相同的 API。

```cpp
httplib::ws::WebSocketClient cli("ws://localhost:8080/chat");
cli.set_websocket_ping_interval(30);
cli.connect();
```

在 `connect()` 之前调用它。

## 默认值

默认间隔由编译时宏 `CPPHTTPLIB_WEBSOCKET_PING_INTERVAL_SECOND` 设置。通常你无需修改它，但如果你面对的是较为激进的代理，可以调小。

## Pong 呢？

WebSocket 协议要求 Ping 帧必须用 Pong 帧应答。cpp-httplib 会自动响应 Ping——你在应用代码中无需考虑这一点。

## 如何选择间隔

| 环境 | 建议值 |
| --- | --- |
| 普通互联网 | 30–60 秒 |
| 严格的代理（例如 AWS ALB） | 15–30 秒 |
| 移动网络 | 60 秒以上（太短会耗电） |

间隔太短会浪费带宽；太长则连接会被断开。经验法则是，以你和客户端之间任意一方的空闲超时的**一半**为目标。

> **警告：** 极短的 ping 间隔会为每个连接产生后台工作并增加 CPU 占用。对于连接数很多的服务器，请保持间隔适中。

## 检测无响应的对端

如果对端只是悄无声息地死掉，光发送 ping 并不能告诉你任何事——TCP socket 可能看起来仍然打开，而对端的进程早已消失。要捕捉这种情况，请启用最大未响应 pong 检查：如果连续 N 次 ping 都没有得到应答，就关闭连接。

```cpp
cli.set_websocket_max_missed_pongs(2); // 连续 2 次 ping 未确认后关闭
```

服务器端也有相同的 `set_websocket_max_missed_pongs()`。

在 30 秒的 ping 间隔和 `max_missed_pongs = 2` 下，死掉的对端大约会在 60 秒内被检测到，连接会以 `CloseStatus::GoingAway` 和原因 `"pong timeout"` 关闭。

只要 `read()` 消费了一个传入的 Pong 帧，计数器就会重置，因此只有你的代码在循环中主动调用 `read()` 时这才会生效——而正常的 WebSocket 客户端本来就会这样做。

### 为什么默认值是 0

`max_missed_pongs` 默认为 `0`，意思是“绝不因缺少 pong 而关闭连接”。Ping 仍会按心跳间隔发送，但不会检查其响应。如果你想要检测无响应的对端，请显式地将其设置为 `1` 或更高。

在服务器端，即使设置为 `0`，死连接也不会永远滞留：当处理器处于 `read()` 内部时，`CPPHTTPLIB_WEBSOCKET_SERVER_READ_TIMEOUT_SECOND`（默认 **300 秒 = 5 分钟**）充当兜底。客户端自身没有兜底——除非你设置读超时，否则它会一直等待——所以在客户端，`max_missed_pongs` 是唯一能察觉对端无响应的手段。在两端，它也是让你比那 5 分钟兜底**更快**察觉的手段。

> 关于处理已关闭的连接，参见 [W03. 处理连接关闭](../w03-websocket-close)。
