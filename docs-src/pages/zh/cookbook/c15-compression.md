---
title: "C15. 启用压缩"
order: 15
status: "draft"
---

cpp-httplib 支持发送时压缩、接收时解压。你只需在构建时启用 zlib 或 Brotli 即可。

## 构建时设置

要使用压缩功能，请在包含 `httplib.h` 之前定义以下宏：

```cpp
#define CPPHTTPLIB_ZLIB_SUPPORT    // gzip / deflate
#define CPPHTTPLIB_BROTLI_SUPPORT  // brotli
#include <httplib.h>
```

你还需要链接 `zlib` 或 `brotli`。

## 压缩请求体

```cpp
httplib::Client cli("https://api.example.com");
cli.set_compress(true);

std::string big_payload = build_payload();
auto res = cli.Post("/api/data", big_payload, "application/json");
```

使用 `set_compress(true)` 后，POST 或 PUT 请求的请求体在发送前会被 gzip 压缩。服务器也需要能够处理压缩后的请求体。

## 解压响应

```cpp
httplib::Client cli("https://api.example.com");
cli.set_decompress(true); // 默认开启

auto res = cli.Get("/api/data");
std::cout << res->body << std::endl;
```

使用 `set_decompress(true)` 后，客户端会自动解压带有 `Content-Encoding: gzip` 或类似响应头的响应。`res->body` 中保存的是解压后的数据。

它默认是开启的，所以通常你什么都不需要做。只有当你想获得原始的压缩字节时才需要把它设为 `false`。

> **警告：** 如果在构建时未定义 `CPPHTTPLIB_ZLIB_SUPPORT`，调用 `set_compress()` 或 `set_decompress()` 将不会产生任何效果。如果压缩不起作用，请先检查宏定义。
