---
title: "W03. 处理连接关闭"
order: 54
status: "draft"
---

WebSocket 在任一端显式关闭它，或网络中断时结束。干净地处理关闭，你的清理与重连逻辑就能保持整洁。

## 检测已关闭的连接

当 `ws.read()` 返回 `ReadResult::Fail` 时，连接已经不存在了——无论是正常关闭还是发生错误。跳出循环，处理器随即结束。

```cpp
svr.WebSocket("/chat", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
  std::string msg;
  while (ws.is_open()) {
    auto result = ws.read(msg);
    if (result == httplib::ws::ReadResult::Fail) {
      std::cout << "disconnected" << std::endl;
      break;
    }
    handle_message(ws, msg);
  }

  // 跳出循环后执行清理
  cleanup_user_session(req);
});
```

你也可以检查 `ws.is_open()`——这是同一个信号的另一个角度。

## 从服务器端关闭

要显式关闭，调用 `close()`。

```cpp
ws.close(httplib::ws::CloseStatus::Normal, "bye");
```

第一个参数是关闭状态；第二个是可选的关闭原因。常见的 `CloseStatus` 值：

| 值 | 含义 |
| --- | --- |
| `Normal` (1000) | 正常关闭 |
| `GoingAway` (1001) | 服务器正在关闭 |
| `ProtocolError` (1002) | 检测到协议违规 |
| `UnsupportedData` (1003) | 收到无法处理的数据 |
| `PolicyViolation` (1008) | 违反了策略 |
| `MessageTooBig` (1009) | 消息过大 |
| `InternalError` (1011) | 服务器端错误 |

## 从客户端关闭

客户端 API 完全相同。

```cpp
cli.close(httplib::ws::CloseStatus::Normal);
```

销毁客户端也会关闭连接，但显式调用 `close()` 能让意图更清晰。

## 优雅关闭

要通知在途的客户端服务器即将下线，使用 `GoingAway`。

```cpp
ws.close(httplib::ws::CloseStatus::GoingAway, "server restarting");
```

客户端可以检查该状态，并决定是否重连。

## 示例：带退出命令的小型聊天

```cpp
svr.WebSocket("/chat", [](const auto &req, auto &ws) {
  std::string msg;
  while (ws.is_open()) {
    if (ws.read(msg) == httplib::ws::ReadResult::Fail) break;

    if (msg == "/quit") {
      ws.send("goodbye");
      ws.close(httplib::ws::CloseStatus::Normal, "user quit");
      break;
    }

    ws.send("echo: " + msg);
  }
});
```

> **注意：** 在网络突然中断时，`read()` 会返回 `Fail`，此时没有机会调用 `close()`。把清理逻辑放在处理器末尾，这样两条路径——正常关闭和突然断开——最终都会走到同一个地方。
