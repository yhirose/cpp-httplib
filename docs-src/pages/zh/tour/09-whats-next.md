---
title: "接下来"
order: 9
---

恭喜你完成了本教程！现在你已经扎实掌握了 cpp-httplib 的基础知识。但还有更多内容值得探索。下面按类别简要介绍教程中未涉及的功能。

## Streaming API

在处理 LLM 流式响应或下载大文件时，你不会希望把整个响应都加载到内存中。使用 `stream::Get()` 可以逐块处理数据。

```cpp
httplib::Client cli("http://localhost:11434");

auto result = httplib::stream::Get(cli, "/api/generate");

if (result) {
    while (result.next()) {
        std::cout.write(result.data(), result.size());
    }
}
```

你也可以向 `Get()` 传入 `content_receiver` 回调。这种方式可以与 Keep-Alive 一起使用。

```cpp
httplib::Client cli("http://localhost:8080");

cli.Get("/stream", [](const char *data, size_t len) {
    std::cout.write(data, len);
    return true;
});
```

在服务器端，有 `set_content_provider()` 和 `set_chunked_content_provider()`。当你知道大小时使用前者，不知道时使用后者。

```cpp
// 已知大小（会设置 Content-Length）
svr.Get("/file", [](const auto &, auto &res) {
    auto size = get_file_size("large.bin");
    res.set_content_provider(size, "application/octet-stream",
        [](size_t offset, size_t length, httplib::DataSink &sink) {
            // 从 offset 开始发送 length 字节
            return true;
        });
});

// 未知大小（Chunked Transfer Encoding）
svr.Get("/stream", [](const auto &, auto &res) {
    res.set_chunked_content_provider("text/plain",
        [](size_t offset, httplib::DataSink &sink) {
            sink.write("chunk\n", 6);
            return true;  // 返回 false 表示结束
        });
});
```

上传大文件时，`make_file_provider()` 会派上用场。它会对文件进行流式传输，而不是把整个文件加载到内存中。

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Post("/upload", {}, {}, {
    httplib::make_file_provider("file", "/path/to/large-file.zip")
});
```

## Server-Sent Events (SSE)

我们也提供了 SSE 客户端。它支持自动重连以及通过 `Last-Event-ID` 恢复。

```cpp
httplib::Client cli("http://localhost:8080");
httplib::sse::SSEClient sse(cli, "/events");

sse.on_message([](const httplib::sse::SSEMessage &msg) {
    std::cout << msg.event << ": " << msg.data << std::endl;
});

sse.start();  // 阻塞式，带自动重连
```

你也可以为每种事件类型设置单独的处理器。

```cpp
sse.on_event("update", [](const httplib::sse::SSEMessage &msg) {
    // 仅处理 "update" 事件
});
```

## 认证

客户端提供了 Basic 认证、Bearer Token 认证和 Digest 认证的辅助方法。

```cpp
httplib::Client cli("https://api.example.com");
cli.set_basic_auth("user", "password");
cli.set_bearer_token_auth("my-token");
```

## 压缩

我们支持使用 gzip、Brotli 和 Zstandard 进行压缩与解压缩。编译时请定义相应的宏。

| 压缩方式 | 宏 |
| -- | -- |
| gzip | `CPPHTTPLIB_ZLIB_SUPPORT` |
| Brotli | `CPPHTTPLIB_BROTLI_SUPPORT` |
| Zstandard | `CPPHTTPLIB_ZSTD_SUPPORT` |

```cpp
httplib::Client cli("https://example.com");
cli.set_compress(true);    // 压缩请求体
cli.set_decompress(true);  // 解压缩响应体
```

## 代理

你可以通过 HTTP 代理进行连接。

```cpp
httplib::Client cli("https://example.com");
cli.set_proxy("proxy.example.com", 8080);
cli.set_proxy_basic_auth("user", "password");
```

## 超时

你可以分别设置连接、读取和写入超时。

```cpp
httplib::Client cli("https://example.com");
cli.set_connection_timeout(5, 0);  // 5 秒
cli.set_read_timeout(10, 0);       // 10 秒
cli.set_write_timeout(10, 0);      // 10 秒
```

## Keep-Alive

如果你要向同一台服务器发送多个请求，请启用 Keep-Alive。它会复用 TCP 连接，效率高得多。

```cpp
httplib::Client cli("https://example.com");
cli.set_keep_alive(true);
```

## 服务器中间件

你可以在处理器运行前后挂钩到请求处理流程中。

```cpp
svr.set_pre_routing_handler([](const auto &req, auto &res) {
    // 在每个请求之前运行
    return httplib::Server::HandlerResponse::Unhandled;  // 继续正常路由
});

svr.set_post_routing_handler([](const auto &req, auto &res) {
    // 在响应发送之后运行
    res.set_header("X-Server", "cpp-httplib");
});
```

使用 `res.user_data` 可以把数据从中间件传递给处理器。这对于共享解码后的认证令牌等内容很有用。

```cpp
svr.set_pre_routing_handler([](const auto &req, auto &res) {
    res.user_data.set("auth_user", std::string("alice"));
    return httplib::Server::HandlerResponse::Unhandled;
});

svr.Get("/me", [](const auto &req, auto &res) {
    auto *user = res.user_data.get<std::string>("auth_user");
    res.set_content("Hello, " + *user, "text/plain");
});
```

你也可以自定义错误处理器和异常处理器。

```cpp
svr.set_error_handler([](const auto &req, auto &res) {
    res.set_content("Custom Error Page", "text/html");
});

svr.set_exception_handler([](const auto &req, auto &res, std::exception_ptr ep) {
    res.status = 500;
    res.set_content("Internal Server Error", "text/plain");
});
```

## 日志

你可以在服务器和客户端上都设置日志记录器。

```cpp
svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " " << res.status << std::endl;
});
```

## Unix Domain Socket

除 TCP 之外，我们还支持 Unix Domain Socket。你可以用它在同一台机器上进行进程间通信。

```cpp
// 服务器
httplib::Server svr;
svr.set_address_family(AF_UNIX);
svr.listen("/tmp/httplib.sock", 0);
```

```cpp
// 客户端
httplib::Client cli("http://localhost");
cli.set_address_family(AF_UNIX);
cli.set_hostname_addr_map({{"localhost", "/tmp/httplib.sock"}});

auto res = cli.Get("/");
```

## 了解更多

想深入了解？请查看以下资源。

- Cookbook —— 常见用例的做法合集
- [README](https://github.com/yhirose/cpp-httplib/blob/master/README.md) —— 完整的 API 参考
- [README-sse](https://github.com/yhirose/cpp-httplib/blob/master/README-sse.md) —— 如何使用 Server-Sent Events
- [README-stream](https://github.com/yhirose/cpp-httplib/blob/master/README-stream.md) —— 如何使用 Streaming API
- [README-websocket](https://github.com/yhirose/cpp-httplib/blob/master/README-websocket.md) —— 如何使用 WebSocket 服务器
