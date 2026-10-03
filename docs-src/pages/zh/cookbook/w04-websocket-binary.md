---
title: "W04. 发送和接收二进制帧"
order: 55
status: "draft"
---

WebSocket 有两种帧类型：文本和二进制。JSON 和纯文本使用文本帧；图像和原始协议字节使用二进制帧。在 cpp-httplib 中，`send()` 通过重载来选择正确的类型。

## 如何选择帧类型

```cpp
ws.send(std::string("Hello"));           // 文本
ws.send("Hello", 5);                      // 二进制
ws.send(binary_data, binary_data_size);   // 二进制
```

`std::string` 重载以**文本**发送。`const char*` + 长度重载以**二进制**发送。有点微妙，但一旦了解就忘不掉。

如果你有一个 `std::string` 想以二进制发送，请显式传入 `.data()` 和 `.size()`。

```cpp
std::string raw = build_binary_payload();
ws.send(raw.data(), raw.size()); // 二进制帧
```

## 接收时检测帧类型

`ws.read()` 的返回值告诉你收到的帧是文本还是二进制。

```cpp
std::string msg;
auto result = ws.read(msg);

switch (result) {
  case httplib::ws::ReadResult::Text:
    std::cout << "text: " << msg << std::endl;
    break;
  case httplib::ws::ReadResult::Binary:
    std::cout << "binary: " << msg.size() << " bytes" << std::endl;
    handle_binary(msg.data(), msg.size());
    break;
  case httplib::ws::ReadResult::Fail:
    // 出错或已关闭
    break;
  case httplib::ws::ReadResult::Timeout:
    // 读超时已过；连接仍然打开
    break;
}
```

二进制帧仍然以 `std::string` 返回，但要把它的内容当作原始字节来处理——使用 `msg.data()` 和 `msg.size()`。

## 什么情况下该用二进制

- **图像、视频、音频**：没有 Base64 开销
- **自定义协议**：protobuf、MessagePack 或任何结构化二进制格式
- **游戏网络**：延迟至关重要时
- **传感器数据流**：直接推送数值数组

## Ping 类似二进制，但被隐藏了

在操作码层面，WebSocket 的 Ping/Pong 帧与二进制帧是近亲，但 cpp-httplib 会自动处理它们——你无需接触。参见 [W02. 设置 WebSocket 心跳](../w02-websocket-ping)。

## 示例：发送图像

```cpp
// 服务器：推送一张图像
svr.WebSocket("/image", [](const auto &req, auto &ws) {
  auto img = read_image_file("logo.png");
  ws.send(img.data(), img.size());
});
```

```cpp
// 客户端：接收并保存
httplib::ws::WebSocketClient cli("ws://localhost:8080/image");
cli.connect();

std::string buf;
if (cli.read(buf) == httplib::ws::ReadResult::Binary) {
  std::ofstream ofs("received.png", std::ios::binary);
  ofs.write(buf.data(), buf.size());
}
```

你可以在同一个连接中混用文本和二进制。常见模式：用 JSON 作为控制消息，用二进制承载实际数据——这样元数据和负载都能得到高效处理。

> **注意：** WebSocket 帧没有无限的大小限制。对于非常大的数据，请在应用代码中分块。cpp-httplib 可以一次性处理大帧，但它确实会一次性把整个帧加载进内存。
