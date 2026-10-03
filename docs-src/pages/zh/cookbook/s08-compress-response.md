---
title: "S08. 返回压缩响应"
order: 27
status: "draft"
---

当客户端通过 `Accept-Encoding` 表示支持时，cpp-httplib 会自动压缩响应体。处理器无需做任何特殊处理。支持的编码有 gzip、Brotli 和 Zstd。

## 构建时设置

要启用压缩，请在包含 `httplib.h` 之前定义相关宏：

```cpp
#define CPPHTTPLIB_ZLIB_SUPPORT     // gzip
#define CPPHTTPLIB_BROTLI_SUPPORT   // brotli
#define CPPHTTPLIB_ZSTD_SUPPORT     // zstd
#include <httplib.h>
```

你还需要分别链接 `zlib`、`brotli` 和 `zstd`。只启用你需要的即可。

## 用法

```cpp
svr.Get("/api/data", [](const httplib::Request &req, httplib::Response &res) {
  std::string body = build_large_response();
  res.set_content(body, "application/json");
});
```

就是这样。如果客户端发送了 `Accept-Encoding: gzip`，cpp-httplib 会自动用 gzip 压缩响应，并为你添加 `Content-Encoding: gzip` 和 `Vary: Accept-Encoding`。

## 编码优先级

当客户端接受多种编码时，cpp-httplib 会按以下顺序选择（在构建时启用的编码中）：Brotli → Zstd → gzip。你的代码无需关心——你总是会得到可用的最高效选项。

## 流式响应也会被压缩

通过 `set_chunked_content_provider()` 的流式响应会获得相同的自动压缩。

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/plain",
    [](size_t offset, httplib::DataSink &sink) {
      // ...
    });
});
```

## 静态文件需要手动启用

通过 `set_mount_point()` 或 `Response::set_file_content()` 原样提供的文件默认不会被压缩。使用以下方式启用：

```cpp
svr.set_static_file_compression(true);
```

只有处于某个大小范围内的文件才会被压缩，并且该范围的上下界都可以调整：

```cpp
svr.set_static_file_compression_min_length(512);
svr.set_static_file_compression_max_length(1024 * 1024);
```

下界默认为 1400 字节。一个已经能放进单个 1500 字节 MTU 的响应并不会因为变小而传输得更快，而只有几个字节的文件在返回时会比传入时更大，因为 gzip 的头部和尾部开销超过了 deflate 节省的部分。

上界默认为 4MB，其存在的原因不同：文件会在每次请求时被压缩，而压缩后的字节会一直驻留在内存中，直到响应写完，因此峰值开销会随进行中请求的数量而增长。它限制的是单个请求可能产生的开销，并不说明大文件的压缩效果如何，因此当文件内容已知而流量未知时，提高它是合理的。

任一界设为 `0` 都会将其关闭，并且各自都有编译期默认值（`CPPHTTPLIB_STATIC_FILE_COMPRESSION_MIN_LENGTH`、`CPPHTTPLIB_STATIC_FILE_COMPRESSION_MAX_LENGTH`）。

压缩后的响应会保留其 `Content-Length`，因此 `HEAD` 报告的大小与 `GET` 相同。有两点细节需要了解：范围请求会基于未压缩的表示来响应，而 `ETag` 会带上它所属的编码，例如 `W/"...-gzip"`。

使用 `set_content_provider()` 注册的 content provider 不在覆盖范围内。将其经过压缩器会阻止每次写入，直到内部缓冲区填满，这会让逐块构建响应体的 provider 停滞。要压缩生成的响应体，请使用 `set_chunked_content_provider()`。

> **注意：** 该大小范围仅适用于静态文件。传给 `set_content()` 的响应体，只要客户端接受且 MIME 类型可压缩，无论多小都会被压缩，因此几字节的响应最终会比原来更大。如果你想避免这种情况，请在处理器中做出判断。

> 关于客户端的对应内容，请参阅 [C15. 启用压缩](../c15-compression)。
