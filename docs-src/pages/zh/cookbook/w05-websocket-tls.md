---
title: "W05. 为 wss:// 连接配置 TLS"
order: 56
status: "draft"
---

`wss://`（基于 TLS 的 WebSocket）连接的客户端侧 TLS 配置使用与 `SSLClient` 几乎相同的 API。`ws::WebSocketClient` 通过同一个类同时处理 `ws://` 和 `wss://`，因此不像 `SSLClient` 那样需要切换到单独的类。

```cpp
httplib::ws::WebSocketClient ws1("ws://localhost:8080/ws");   // 明文
httplib::ws::WebSocketClient ws2("wss://localhost:8443/ws");  // TLS
```

## 验证服务器证书

使用 `set_ca_cert_path()` 指向你自己的 CA 证书。签名与 `SSLClient` 一致：第一个参数是 CA 证书文件，第二个是可选的 CA 目录。

```cpp
httplib::ws::WebSocketClient ws("wss://internal.example.com/ws");
ws.set_ca_cert_path("/etc/ssl/certs/internal-ca.pem");

if (ws.connect()) {
  ws.send("hello");
}
```

要完全禁用证书验证，使用 `enable_server_certificate_verification(false)`。关于该行为的详情，参见 [T02. 控制 SSL 证书验证](../t02-cert-verification)。

## 出示客户端证书（mTLS）

`ws::WebSocketClient` 有一个接受 `PemMemory` 结构体的构造函数重载，让 `wss://` 连接可以出示客户端证书。

```cpp
httplib::ws::WebSocketClient::PemMemory pem{};
pem.cert_pem = client_cert.data();
pem.cert_pem_len = client_cert.size();
pem.key_pem = client_key.data();
pem.key_pem_len = client_key.size();

httplib::ws::WebSocketClient ws("wss://api.example.com/ws", pem);

if (ws.connect()) {
  ws.send("hello");
}
```

将 `PemMemory` 传给 `ws://`（非 TLS）URL 会被静默忽略。没有直接读取证书文件的构造函数，因此与 `SSLClient` 不同，你总是需要自己先把 PEM 加载到内存中再传入。

关于 mTLS 的完整全貌，包括服务器端设置和使用场景，参见 [T04. 配置 mTLS](../t04-mtls)。
