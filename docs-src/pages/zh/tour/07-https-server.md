---
title: "HTTPS 服务器"
order: 7
---

在上一章中，你使用了 HTTPS 客户端。现在让我们搭建你自己的 HTTPS 服务器。只需把第 3 章的 `httplib::Server` 换成 `httplib::SSLServer`。

不过，TLS 服务器需要服务器证书和私钥。让我们先准备好它们。

## 创建自签名证书

对于开发和测试来说，自签名证书完全够用。你可以用一条 OpenSSL 命令快速生成一个。

```sh
openssl req -x509 -noenc -keyout key.pem -out cert.pem -subj /CN=localhost
```

这会创建两个文件：

- **`cert.pem`** —— 服务器证书
- **`key.pem`** —— 私钥

## 最小 HTTPS 服务器

拿到证书后，让我们来编写服务器。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::SSLServer svr("cert.pem", "key.pem");

    svr.Get("/", [](const auto &, auto &res) {
        res.set_content("Hello, HTTPS!", "text/plain");
    });

    std::cout << "Listening on https://localhost:8443" << std::endl;
    svr.listen("0.0.0.0", 8443);
}
```

只需把证书和私钥的路径传给 `httplib::SSLServer` 构造函数。路由 API 与第 3 章的 `httplib::Server` 完全相同。

编译并启动它。

## 测试一下

服务器运行起来后，试着用 `curl` 访问它。由于我们使用的是自签名证书，请加上 `-k` 选项来跳过证书验证。

```sh
curl -k https://localhost:8443/
# Hello, HTTPS!
```

如果你在浏览器中打开 `https://localhost:8443`，会看到“此连接不安全”的警告。使用自签名证书时这是正常现象，直接继续访问即可。

## 从客户端连接

让我们用上一章的 `httplib::Client` 来连接。连接到使用自签名证书的服务器有两种方式。

### 方式 1：禁用证书验证

这是开发时快捷简便的方法。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://localhost:8443");
    cli.enable_server_certificate_verification(false);

    auto res = cli.Get("/");
    if (res) {
        std::cout << res->body << std::endl;  // Hello, HTTPS!
    }
}
```

### 方式 2：把自签名证书指定为 CA 证书

这是更安全的方法。你让客户端把 `cert.pem` 作为 CA 证书来信任。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://localhost:8443");
    cli.set_ca_cert_path("cert.pem");

    auto res = cli.Get("/");
    if (res) {
        std::cout << res->body << std::endl;  // Hello, HTTPS!
    }
}
```

这样一来，只允许连接到使用该特定证书的服务器，从而防止身份冒充。请尽可能使用这种方法，即使在测试环境中也是如此。

## 比较 Server 与 SSLServer

你在第 3 章学到的 `httplib::Server` API 在 `httplib::SSLServer` 上可以完全相同地工作。唯一的区别在于构造函数。

| | `httplib::Server` | `httplib::SSLServer` |
| -- | ------------------ | -------------------- |
| 构造函数 | 无参数 | 证书和私钥的路径 |
| 协议 | HTTP | HTTPS |
| 端口（惯例） | 8080 | 8443 |
| 路由 | 相同 | 相同 |

要把 HTTP 服务器切换到 HTTPS，只需更改构造函数。

## 下一步

你的 HTTPS 服务器已经运行起来了。现在你已经掌握了 HTTP/HTTPS 客户端和服务器的基础知识。

接下来，让我们看看最近添加到 cpp-httplib 中的 WebSocket 支持。

**下一章：** [WebSocket](../08-websocket)
