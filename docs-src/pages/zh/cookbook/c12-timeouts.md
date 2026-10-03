---
title: "C12. 设置超时"
order: 12
status: "draft"
---

客户端有三种超时，各自独立设置。

| 类型 | API | 默认值 | 含义 |
| --- | --- | --- | --- |
| Connection | `set_connection_timeout` | 300s | 等待 TCP 连接建立的时间 |
| Read | `set_read_timeout` | 300s | 接收响应时等待单次 `recv` 的时间 |
| Write | `set_write_timeout` | 5s | 发送请求时等待单次 `send` 的时间 |

## 基本用法

```cpp
httplib::Client cli("http://localhost:8080");

cli.set_connection_timeout(5, 0);  // 5 秒
cli.set_read_timeout(10, 0);       // 10 秒
cli.set_write_timeout(10, 0);      // 10 秒

auto res = cli.Get("/api/data");
```

以两个参数传入秒和微秒。如果不需要亚秒部分，可以省略第二个参数。

## 使用 `std::chrono`

还有一个直接接受 `std::chrono` 时长（duration）的重载。它更易读——推荐使用。

```cpp
using namespace std::chrono_literals;

cli.set_connection_timeout(5s);
cli.set_read_timeout(10s);
cli.set_write_timeout(500ms);
```

## 注意长达 300s 的默认值

连接和读取超时默认是 **300 秒（5 分钟）**。如果服务器挂起，默认情况下你要等五分钟。通常设置更短的值是更好的选择。

```cpp
cli.set_connection_timeout(3s);
cli.set_read_timeout(10s);
```

> **警告：** 读取超时只覆盖单次接收调用——而不是整个请求。如果在大文件下载过程中数据一直断断续续地到达，请求可能持续半小时也不会触发超时。要限制请求的总时间，请使用 [C13. 设置整体超时](../c13-max-timeout)。

> 关于 WebSocket 客户端的超时，请参见 [W06. 设置超时](../w06-websocket-timeouts)。
