---
title: "T04. 配置 mTLS"
order: 46
status: "draft"
---

常规 TLS 只验证服务器证书。**mTLS**（双向 TLS）增加了另一个方向：客户端也出示证书，由服务器进行验证。这在零信任的 API 到 API 流量以及内部系统认证中很常见。

## 服务器端

将用于验证客户端证书的 CA 作为第三个（以及第四个）参数传给 `SSLServer`。

```cpp
httplib::SSLServer svr(
  "server-cert.pem",    // 服务器证书
  "server-key.pem",     // 服务器私钥
  "client-ca.pem",      // 签发有效客户端证书的 CA
  nullptr               // CA 目录（无）
);

svr.Get("/", [](const httplib::Request &req, httplib::Response &res) {
  res.set_content("authenticated", "text/plain");
});

svr.listen("0.0.0.0", 443);
```

这样，任何客户端证书不是由 `client-ca.pem` 签名的连接都会在握手阶段被拒绝。等到处理器运行时，客户端已经通过认证。

## 使用内存中的 PEM 进行配置

```cpp
httplib::SSLServer::PemMemory pem{};
pem.cert_pem = server_cert.data();
pem.cert_pem_len = server_cert.size();
pem.key_pem = server_key.data();
pem.key_pem_len = server_key.size();
pem.client_ca_pem = client_ca.data();
pem.client_ca_pem_len = client_ca.size();

httplib::SSLServer svr(pem);
```

当你从环境变量或密钥管理服务加载证书时，这是最简洁的方式。

## 客户端

在客户端，将客户端证书和密钥传给 `SSLClient`。

```cpp
httplib::SSLClient cli("api.example.com", 443,
                       "client-cert.pem",
                       "client-key.pem");

auto res = cli.Get("/");
```

注意这里直接使用的是 `SSLClient`，而不是 `Client`。如果私钥有密码，将其作为第五个参数传入。

客户端也有相同的 `PemMemory` 结构体，让你可以从内存中的 PEM 设置客户端证书。

```cpp
httplib::SSLClient::PemMemory pem{};
pem.cert_pem = client_cert.data();
pem.cert_pem_len = client_cert.size();
pem.key_pem = client_key.data();
pem.key_pem_len = client_key.size();

httplib::SSLClient cli("api.example.com", 443, pem);

auto res = cli.Get("/");
```

> 关于 WebSocket 客户端（`wss://`）的 mTLS，参见 [W05. 为 wss:// 连接配置 TLS](../w05-websocket-tls)。

## 在处理器中读取客户端信息

要在处理器内部查看是哪个客户端连入，使用 `req.peer_cert()`。详情参见 [T05. 在服务器端访问对端证书](../t05-peer-cert)。

## 使用场景

- **微服务之间的调用**：为每个服务签发证书，将证书用作身份
- **IoT 设备管理**：将证书烧录到每台设备，用它来把关 API 访问
- **内部 VPN 的替代方案**：在公网端点前加上基于证书的认证，从而安全地访问内部资源

> **注意：** 签发和吊销客户端证书比基于密码的认证需要更多的运维工作。你需要搭建内部 PKI，或者使用 ACME 系列工具建立自动化流程。
