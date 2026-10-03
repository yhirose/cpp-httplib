---
title: "T01. 在 OpenSSL、mbedTLS 和 wolfSSL 之间选择"
order: 43
status: "draft"
---

cpp-httplib 并不自带 TLS 实现——它使用三种后端之一，你在编译时通过宏来选择。

| 后端 | 宏 | 特点 |
| --- | --- | --- |
| OpenSSL | `CPPHTTPLIB_OPENSSL_SUPPORT` | 使用最广泛，功能最丰富 |
| mbedTLS | `CPPHTTPLIB_MBEDTLS_SUPPORT` | 轻量，面向嵌入式 |
| wolfSSL | `CPPHTTPLIB_WOLFSSL_SUPPORT` | 对嵌入式友好，可提供商业支持 |

## 编译时选择

在包含 `httplib.h` 之前，为你选择的后端定义相应的宏：

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
```

你还需要链接对应后端的库（`libssl`、`libcrypto`、`libmbedtls`、`libwolfssl` 等）。

## 该选哪个

**拿不准就用 OpenSSL**  
它的功能最多，文档也最完善。对于普通的服务器用途或 Linux 桌面应用，从它开始就好——你多半不需要别的东西。

**想要缩小二进制体积或面向嵌入式**  
mbedTLS 或 wolfSSL 更合适。它们比 OpenSSL 紧凑得多，能在内存受限的设备上运行。

**需要商业支持**  
wolfSSL 提供商业许可与支持。如果你要将其用于产品交付，值得考虑。

## 支持多个后端

通常的做法是把每个后端当作一种编译变体，用不同的宏重新编译同一份源码。cpp-httplib 抹平了大部分 API 差异，但各后端并非 100% 一致——务必测试。

## 在所有后端上通用的 API

证书验证控制、启动 SSLServer、读取对端证书——这些在所有后端上都使用相同的 API：

- [T02. 控制 SSL 证书验证](../t02-cert-verification)
- [T03. 启动 SSL/TLS 服务器](../t03-ssl-server)
- [T05. 在服务器端访问对端证书](../t05-peer-cert)

> **注意：** 在 macOS 上使用 OpenSSL 系列后端时，cpp-httplib 会自动从系统钥匙串加载根证书（通过 `CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN`，默认开启）。要禁用此行为，请定义 `CPPHTTPLIB_DISABLE_MACOSX_AUTOMATIC_ROOT_CERTIFICATES`。
