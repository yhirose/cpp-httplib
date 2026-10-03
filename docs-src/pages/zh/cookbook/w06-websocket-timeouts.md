---
title: "W06. 设置超时"
order: 57
status: "draft"
---

`ws::WebSocketClient` 有与 `Client` 相同的三种超时，含义也相同。

| 类型 | API | 默认值 |
| --- | --- | --- |
| 连接 | `set_connection_timeout` | 300 秒 |
| 读 | `set_read_timeout` | 无——永远等待（`CPPHTTPLIB_WEBSOCKET_CLIENT_READ_TIMEOUT_SECOND`） |
| 写 | `set_write_timeout` | 5 秒 |

## 基本用法

```cpp
httplib::ws::WebSocketClient ws("ws://localhost:8080/ws");

ws.set_connection_timeout(5, 0);  // 5 秒
ws.set_read_timeout(30, 0);       // 30 秒
ws.set_write_timeout(10, 0);      // 10 秒

if (ws.connect()) {
  ws.send("hello");
}
```

在调用 `connect()` 之前设置连接超时和写超时。读超时可以随时更改——在已打开的连接上设置它会在下一次 `read()` 时生效。

## 使用 `std::chrono`

与 `Client` 一样，有一个直接接受 `std::chrono` 时长的重载。

```cpp
using namespace std::chrono_literals;

ws.set_connection_timeout(5s);
ws.set_read_timeout(30s);
ws.set_write_timeout(10s);
```

## 读超时的含义

`set_read_timeout()` 作用于单次 `read()` 调用。如果在这段时间内没有消息到达，`read()` 返回 `ReadResult::Timeout`：**连接仍然打开**，且没有消费任何内容，因此你可以继续在其上发送并再次读取。这正是它与 `ReadResult::Fail` 的区别——后者意味着连接已经不存在了。

正是这一点让单个线程可以双向地持有连接：

```cpp
using namespace std::chrono_literals;

ws.set_read_timeout(100ms);
std::string msg;
while (ws.is_open()) {
  auto r = ws.read(msg);
  if (r == httplib::ws::Timeout) {
    flush_outgoing(ws);  // 没有消息到达——把队列中的内容发出去
    continue;
  }
  if (r == httplib::ws::Fail) { break; }
  handle(msg);
}
```

如果没有读超时，`read()` 会阻塞直到有消息到达，因此持有连接的线程永远没有机会执行写操作。

关于 `Timeout`，有两点需要知道：

- 它不会改动 `msg`，并且其值非零。所以一旦设置了读超时，`while (ws.read(msg))` 就不能用了——循环会一直运行，而 `msg` 中仍是*上一条*消息。
- 它只在消息边界上报告。如果超时在一条分片消息的中途到期，该消息无法继续，`read()` 会返回 `Fail`。

对于长时间空闲属于常态的连接——例如等待通知——要么不设置读超时，要么把 `Timeout` 当作它本来的空操作并继续循环。

## 服务器端

处理器的 `ws::WebSocket` 也有 `set_read_timeout()`，上面的模式就是处理器在连接之间进行转发、而不是停在 `read()` 中的方式。

服务器默认值是 300 秒（`CPPHTTPLIB_WEBSOCKET_SERVER_READ_TIMEOUT_SECOND`），而不是“永远”：它是一个兜底机制，用于从已沉默的对端手中回收工作线程，因为一个 WebSocket 处理器会在连接的整个生命周期内占用其工作线程。

由于它是兜底机制，而非处理器主动要求的，它不会以 `Timeout` 的形式出现。当它到期时，`read()` 返回 `Fail` 并关闭连接，因此写成 `while (ws.read(msg))` 的处理器会像以往一样结束。只有处理器自己通过 `set_read_timeout()` 设置的超时才会以 `Timeout` 返回。

> 通过 Ping/Pong 检测无响应对端是一种独立的机制。详情参见 [W02. 设置 WebSocket 心跳](../w02-websocket-ping)。

## 与 `Client` 的区别

关于 `Client` 的超时配置，参见 [C12. 设置超时](../c12-timeouts)。行为和 API 几乎完全相同，但 `WebSocketClient` 没有与 `set_max_timeout()` 等价的东西来为整个请求设定上限——一旦连接，只要你持续调用 `read()`，连接就会一直保持打开。
