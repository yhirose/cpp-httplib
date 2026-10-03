---
title: "WebSocket"
order: 8
---

cpp-httplib 也支持 WebSocket。与 HTTP 的请求/响应不同，WebSocket 允许服务器和客户端双向交换消息，非常适合聊天应用和实时通知。

让我们马上构建一个回显服务器和客户端。

## 回显服务器

下面是一个回显服务器，它会原样发回收到的任何消息。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.WebSocket("/ws", [](const httplib::Request &, httplib::ws::WebSocket &ws) {
        std::string msg;
        while (ws.read(msg)) {
            ws.send(msg);  // 原样发回收到的消息
        }
    });

    std::cout << "Listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);
}
```

使用 `svr.WebSocket()` 注册 WebSocket 处理器。它的用法与第 3 章的 `svr.Get()` 和 `svr.Post()` 一样。

在处理器内部，`ws.read(msg)` 会等待消息。连接关闭时，`read()` 返回 `false`，循环随之退出。`ws.send(msg)` 则把消息发送回去。

## 从客户端连接

让我们使用 `httplib::ws::WebSocketClient` 连接到服务器。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::ws::WebSocketClient client("ws://localhost:8080/ws");

    if (!client.connect()) {
        std::cout << "Connection failed" << std::endl;
        return 1;
    }

    // 发送消息
    client.send("Hello, WebSocket!");

    // 接收来自服务器的响应
    std::string msg;
    if (client.read(msg)) {
        std::cout << msg << std::endl;  // Hello, WebSocket!
    }

    client.close();
}
```

向构造函数传入 `ws://host:port/path` 格式的 URL。调用 `connect()` 开始连接，然后使用 `send()` 和 `read()` 交换消息。

## 文本与二进制

WebSocket 有两种类型的消息：文本和二进制。你可以通过 `read()` 的返回值来区分它们。

```cpp
svr.WebSocket("/ws", [](const httplib::Request &, httplib::ws::WebSocket &ws) {
    std::string msg;
    httplib::ws::ReadResult ret;
    while ((ret = ws.read(msg))) {
        if (ret == httplib::ws::Binary) {
            ws.send(msg.data(), msg.size());  // 作为二进制发送
        } else {
            ws.send(msg);  // 作为文本发送
        }
    }
});
```

- `ws.send(const std::string &)` —— 作为文本消息发送
- `ws.send(const char *, size_t)` —— 作为二进制消息发送

客户端的 API 也相同。

## 访问请求信息

你可以通过处理器的第一个参数 `req` 读取握手时的 HTTP 请求信息。这在检查认证令牌时很方便。

```cpp
svr.WebSocket("/ws", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    auto token = req.get_header_value("Authorization");
    if (token.empty()) {
        ws.close(httplib::ws::CloseStatus::PolicyViolation, "unauthorized");
        return;
    }

    std::string msg;
    while (ws.read(msg)) {
        ws.send(msg);
    }
});
```

处理器内部的检查会在握手完成之后执行。如果想在升级之前用 401 之类的 HTTP 状态码拒绝连接，请改用 `set_pre_request_handler()`。它也会对 WebSocket 路由生效。参见 [S11. 使用前置请求处理器按路由进行认证](../../cookbook/s11-pre-request)。

## 使用 WSS

基于 HTTPS 的 WebSocket（WSS）也受支持。在服务器端，只需在 `httplib::SSLServer` 上注册 WebSocket 处理器。

```cpp
httplib::SSLServer svr("cert.pem", "key.pem");

svr.WebSocket("/ws", [](const httplib::Request &, httplib::ws::WebSocket &ws) {
    std::string msg;
    while (ws.read(msg)) {
        ws.send(msg);
    }
});

svr.listen("0.0.0.0", 8443);
```

在客户端，使用 `wss://` 方案。

```cpp
httplib::ws::WebSocketClient client("wss://localhost:8443/ws");
```

## 下一步

现在你已经了解了 WebSocket 的基础知识。本教程到此结束。

下一页将为你总结教程中未涉及的功能。

**下一章：** [What's Next](../09-whats-next)
