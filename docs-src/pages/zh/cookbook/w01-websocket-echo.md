---
title: "W01. 实现 WebSocket 回显服务器与客户端"
order: 52
status: "draft"
---

WebSocket 是一种用于客户端与服务器之间**双向**消息传递的协议。cpp-httplib 为两端都提供了 API。让我们从最简单的例子开始：回显服务器。

## 服务器：回显服务器

```cpp
#include <httplib.h>

int main() {
  httplib::Server svr;

  svr.WebSocket("/echo", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    std::string msg;
    while (ws.is_open()) {
      auto result = ws.read(msg);
      if (result == httplib::ws::ReadResult::Fail) {
        break;
      }
      ws.send(msg); // 把收到的内容回显回去
    }
  });

  svr.listen("0.0.0.0", 8080);
}
```

用 `svr.WebSocket()` 注册 WebSocket 处理器。当处理器运行时，WebSocket 握手已经完成。在循环内部，只需 `ws.read()` 和 `ws.send()` 就能得到可用的回显。

`read()` 的返回值是 `ReadResult` 枚举：

- `ReadResult::Text`：收到一条文本消息
- `ReadResult::Binary`：收到一条二进制消息
- `ReadResult::Fail`：出错，或连接已关闭
- `ReadResult::Timeout`：你通过 `set_read_timeout()` 设置的读超时已过且没有收到任何内容；连接仍然打开。编译时的默认超时会关闭连接并改为以 `Fail` 报告——参见 [W06. 设置超时](../w06-websocket-timeouts)

## 客户端：与回显服务器通信

```cpp
#include <httplib.h>

int main() {
  httplib::ws::WebSocketClient cli("ws://localhost:8080/echo");
  if (!cli.connect()) {
    std::cerr << "failed to connect" << std::endl;
    return 1;
  }

  cli.send("Hello, WebSocket!");

  std::string msg;
  if (cli.read(msg) != httplib::ws::ReadResult::Fail) {
    std::cout << "received: " << msg << std::endl;
  }

  cli.close();
}
```

使用 `ws://`（明文）或 `wss://`（TLS）URL。调用 `connect()` 完成握手，之后 `send()` 和 `read()` 的用法与服务器端相同。

## 文本与二进制

`send()` 有两个重载，让你选择帧类型。

```cpp
ws.send("Hello");                        // 文本帧
ws.send(binary_data, binary_data_size);  // 二进制帧
```

`std::string` 重载以**文本**发送；`const char*` + 长度重载以**二进制**发送。有点微妙，但一旦了解就很直观。详情参见 [W04. 发送和接收二进制帧](../w04-websocket-binary)。

## 线程池的影响

WebSocket 处理器在整个连接生命周期内一直占用其工作线程——每个连接一个线程。要应对大量并发客户端，请配置动态线程池。

```cpp
svr.new_task_queue = [] {
  return new httplib::ThreadPool(8, 128);
};
```

参见 [S21. 配置线程池](../s21-thread-pool)。

> **注意：** 要通过 HTTPS 运行 WebSocket，请使用 `httplib::SSLServer` 而非 `httplib::Server`——同样的 `WebSocket()` 处理器可直接使用。在客户端，使用 `wss://` URL。关于 CA 和客户端证书配置，参见 [W05. 为 wss:// 连接配置 TLS](../w05-websocket-tls)。
