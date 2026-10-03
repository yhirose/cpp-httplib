---
title: "T05. 在服务器端访问对端证书"
order: 47
status: "draft"
---

在 mTLS 环境中，你可以在处理器内部读取客户端证书。提取其中的 CN 或 SAN 来识别用户，或者记录请求日志。

## 基本用法

```cpp
svr.Get("/me", [](const httplib::Request &req, httplib::Response &res) {
  auto cert = req.peer_cert();
  if (!cert) {
    res.status = 401;
    res.set_content("no client certificate", "text/plain");
    return;
  }

  auto cn = cert.subject_cn();
  res.set_content("hello, " + cn, "text/plain");
});
```

`req.peer_cert()` 返回一个 `tls::PeerCert`。它可以转换为 `bool`，所以在使用之前先检查证书是否存在。

## 可用字段

从 `PeerCert` 可以获取：

```cpp
auto cert = req.peer_cert();

std::string cn = cert.subject_cn();        // CN
std::string issuer = cert.issuer_name();   // 签发者
std::string serial = cert.serial();        // 序列号

time_t not_before, not_after;
cert.validity(not_before, not_after);      // 有效期

auto sans = cert.sans();                   // SAN
for (const auto &san : sans) {
  std::cout << san.value << std::endl;
}
```

还有一个用于检查主机名是否被 SAN 列表覆盖的辅助函数：

```cpp
if (cert.check_hostname("alice.corp.example.com")) {
  // 匹配
}
```

## 基于证书的授权

你可以按 CN 或 SAN 来把关路由。

```cpp
svr.set_pre_request_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    auto cert = req.peer_cert();
    if (!cert) {
      res.status = 401;
      return httplib::Server::HandlerResponse::Handled;
    }

    if (req.matched_route.rfind("/admin", 0) == 0) {
      auto cn = cert.subject_cn();
      if (!is_admin_cn(cn)) {
        res.status = 403;
        return httplib::Server::HandlerResponse::Handled;
      }
    }

    return httplib::Server::HandlerResponse::Unhandled;
  });
```

结合预请求处理器，你可以把所有授权逻辑集中在一处。参见 [S11. 用预请求处理器按路由进行认证](../s11-pre-request)。

## SNI（服务器名称指示）

cpp-httplib 会自动处理 SNI。如果一个服务器托管多个域名，底层会使用 SNI——但通常情况下处理器无需关心。

> **警告：** 只有当启用 mTLS 且客户端实际出示了证书时，`req.peer_cert()` 才会返回有意义的值。对于普通 TLS，你会得到一个空的 `PeerCert`。使用前始终要做 `bool` 检查。

> 关于如何搭建 mTLS，参见 [T04. 配置 mTLS](../t04-mtls)。
