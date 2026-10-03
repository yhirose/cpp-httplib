---
title: "T03. 启动 SSL/TLS 服务器"
order: 45
status: "draft"
---

要搭建 HTTPS 服务器，请使用 `httplib::SSLServer` 而非 `httplib::Server`。向构造函数传入证书和私钥，你就能得到一个与 `Server` 使用方式完全相同的对象。

## 基本用法

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

int main() {
  httplib::SSLServer svr("cert.pem", "key.pem");

  svr.Get("/", [](const auto &req, auto &res) {
    res.set_content("hello over TLS", "text/plain");
  });

  svr.listen("0.0.0.0", 443);
}
```

向构造函数传入服务器证书（PEM 格式）和私钥文件路径。这就是启用 TLS 的服务器所需的全部内容。注册处理器和调用 `listen()` 的方式与使用 `Server` 时相同。

## 受密码保护的私钥

第五个参数是私钥密码。

```cpp
httplib::SSLServer svr("cert.pem", "key.pem",
                       nullptr, nullptr, "password");
```

第三个和第四个参数用于客户端证书验证（mTLS，参见 [T04. 配置 mTLS](../t04-mtls)）。目前先传入 `nullptr`。

## 从内存加载 PEM 数据

当你想从内存而非文件加载证书时，使用 `PemMemory` 结构体。

```cpp
httplib::SSLServer::PemMemory pem{};
pem.cert_pem = cert_data.data();
pem.cert_pem_len = cert_data.size();
pem.key_pem = key_data.data();
pem.key_pem_len = key_data.size();

httplib::SSLServer svr(pem);
```

当你从环境变量或密钥管理服务获取证书时会很方便。

## 轮换证书

在证书过期之前，你可能希望在不重启服务器的情况下更换它。这正是 `update_certs_pem()` 的用途。

```cpp
svr.update_certs_pem(new_cert_pem, new_key_pem);
```

已建立的连接继续使用旧证书；新连接使用新证书。

## 生成测试证书

要生成一个一次性的自签名证书，可使用 `openssl` CLI。

```sh
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout key.pem -out cert.pem -subj "/CN=localhost"
```

在生产环境中，请使用来自 Let's Encrypt 或你的内部 CA 的证书。

> **警告：** 将 HTTPS 服务器绑定到 443 端口需要 root 权限。要安全地做到这一点，参见 [S18. 用 `listen_after_bind` 控制启动顺序](../s18-listen-after-bind) 中的降权模式。

> 关于双向 TLS（客户端证书），参见 [T04. 配置 mTLS](../t04-mtls)。
