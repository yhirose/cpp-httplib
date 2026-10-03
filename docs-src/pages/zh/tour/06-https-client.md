---
title: "HTTPS 客户端"
order: 6
---

在上一章中，你设置了 OpenSSL。现在让我们把它用在一个 HTTPS 客户端上。你可以使用第 2 章中同样的 `httplib::Client`，只需在构造函数中传入带有 `https://` 方案的 URL。

## GET 请求

让我们试着访问一个真实的 HTTPS 网站。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://nghttp2.org");

    auto res = cli.Get("/");
    if (res) {
        std::cout << res->status << std::endl;           // 200
        std::cout << res->body.substr(0, 100) << std::endl;  // HTML 的前 100 个字符
    } else {
        std::cout << "Error: " << httplib::to_string(res.error()) << std::endl;
    }
}
```

在第 2 章中，你写的是 `httplib::Client cli("http://localhost:8080")`。你只需要把方案改成 `https://`。你在第 2 章学到的每一个 API —— `Get()`、`Post()` 等等 —— 都以完全相同的方式工作。

```sh
curl https://nghttp2.org/
```

## 指定端口

HTTPS 的默认端口是 443。如果你需要其他端口，请把它包含在 URL 中。

```cpp
httplib::Client cli("https://localhost:8443");
```

## CA 证书验证

通过 HTTPS 连接时，`httplib::Client` 默认会验证服务器证书。它只连接到证书由受信任的 CA（证书颁发机构）颁发的服务器。

在 macOS 上，CA 证书会从 Keychain 自动加载；在 Linux 上从系统 CA 证书存储加载；在 Windows 上从 Windows 证书存储加载。大多数情况下，无需额外配置。

### 指定 CA 证书文件

在某些环境中，可能找不到系统 CA 证书。这种情况下，请使用 `set_ca_cert_path()` 直接指定路径。

```cpp
httplib::Client cli("https://nghttp2.org");
cli.set_ca_cert_path("/etc/ssl/certs/ca-certificates.crt");

auto res = cli.Get("/");
```

```sh
curl --cacert /etc/ssl/certs/ca-certificates.crt https://nghttp2.org/
```

### 禁用证书验证

在开发过程中，你可能想连接到使用自签名证书的服务器。为此你可以禁用验证。

```cpp
httplib::Client cli("https://localhost:8443");
cli.enable_server_certificate_verification(false);

auto res = cli.Get("/");
```

```sh
curl -k https://localhost:8443/
```

绝不要在生产环境中禁用此功能。它会使你面临中间人攻击的风险。

## 跟随重定向

访问 HTTPS 网站时，你经常会遇到重定向。例如，从 `http://` 到 `https://`，或者从裸域名到 `www`。

默认情况下不会跟随重定向。你可以在 `Location` 响应头中查看重定向目标。

```cpp
httplib::Client cli("https://nghttp2.org");

auto res = cli.Get("/httpbin/redirect/3");
if (res) {
    std::cout << res->status << std::endl;  // 302
    std::cout << res->get_header_value("Location") << std::endl;
}
```

```sh
curl https://nghttp2.org/httpbin/redirect/3
```

调用 `set_follow_location(true)` 可以自动跟随重定向并获取最终响应。

```cpp
httplib::Client cli("https://nghttp2.org");
cli.set_follow_location(true);

auto res = cli.Get("/httpbin/redirect/3");
if (res) {
    std::cout << res->status << std::endl;  // 200（最终响应）
}
```

```sh
curl -L https://nghttp2.org/httpbin/redirect/3
```

## 下一步

现在你已经知道如何使用 HTTPS 客户端了。接下来，让我们搭建你自己的 HTTPS 服务器。我们会先从创建自签名证书开始。

**下一章：** [HTTPS Server](../07-https-server)
