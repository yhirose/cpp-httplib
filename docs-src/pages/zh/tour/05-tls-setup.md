---
title: "TLS 设置"
order: 5
---

到目前为止，我们一直使用普通的 HTTP，但在实际应用中，HTTPS 才是常态。要在 cpp-httplib 中使用 HTTPS，你需要一个 TLS 库。

在本教程中，我们将使用 OpenSSL。它是使用最广泛的选项，你也能在网上找到大量资料。

## 安装 OpenSSL

请根据你的操作系统进行安装。

| 操作系统 | 安装方式 |
| -- | -------------- |
| macOS | [Homebrew](https://brew.sh/)（`brew install openssl`） |
| Ubuntu / Debian | `sudo apt install libssl-dev` |
| Windows | [vcpkg](https://vcpkg.io/)（`vcpkg install openssl`） |

## 编译选项

要启用 TLS，请在编译时定义 `CPPHTTPLIB_OPENSSL_SUPPORT` 宏。与前面几章相比，你需要额外添加几个选项。

```sh
# macOS (Homebrew)
clang++ -std=c++17 -DCPPHTTPLIB_OPENSSL_SUPPORT \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -lssl -lcrypto \
    -framework CoreFoundation -framework Security \
    -o server server.cpp

# Linux
clang++ -std=c++17 -pthread -DCPPHTTPLIB_OPENSSL_SUPPORT \
    -lssl -lcrypto \
    -o server server.cpp

# Windows (Developer Command Prompt)
cl /EHsc /std:c++17 /DCPPHTTPLIB_OPENSSL_SUPPORT server.cpp libssl.lib libcrypto.lib
```

让我们看看每个选项的作用。

- **`-DCPPHTTPLIB_OPENSSL_SUPPORT`** —— 定义启用 TLS 支持的宏
- **`-lssl -lcrypto`** —— 链接 OpenSSL 库
- **`-I` / `-L`**（仅 macOS）—— 指定 Homebrew 版 OpenSSL 的路径
- **`-framework CoreFoundation -framework Security`**（仅 macOS）—— 用于从 Keychain 自动加载系统证书

## 验证设置

让我们确认一切正常。下面是一个简单的程序，它把 HTTPS URL 传给 `httplib::Client`。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://www.google.com");

    auto res = cli.Get("/");
    if (res) {
        std::cout << "Status: " << res->status << std::endl;
    } else {
        std::cout << "Error: " << httplib::to_string(res.error()) << std::endl;
    }
}
```

编译并运行它。如果看到 `Status: 200`，说明你的设置已经完成。

## 其他 TLS 后端

除了 OpenSSL，cpp-httplib 还支持 Mbed TLS 和 wolfSSL。只需更改宏定义和链接的库，就可以在它们之间切换。

| 后端 | 宏 | 要链接的库 |
| :--- | :--- | :--- |
| OpenSSL | `CPPHTTPLIB_OPENSSL_SUPPORT` | `libssl`, `libcrypto` |
| Mbed TLS | `CPPHTTPLIB_MBEDTLS_SUPPORT` | `libmbedtls`, `libmbedx509`, `libmbedcrypto` |
| wolfSSL | `CPPHTTPLIB_WOLFSSL_SUPPORT` | `libwolfssl` |

Mbed TLS 2.x、3.x 和 4.x 均受支持并可自动检测。注意，Mbed TLS 4.x 把 `libmbedcrypto` 重命名为 `libtfpsacrypto`，因此请改为链接后者。

本教程以 OpenSSL 为前提，但无论选择哪个后端，API 都是相同的。

## 下一步

TLS 已经准备就绪。接下来，让我们向一个 HTTPS 网站发送请求。

**下一章：** [HTTPS Client](../06-https-client)
