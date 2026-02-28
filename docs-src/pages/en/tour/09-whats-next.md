---
title: "What's Next"
order: 9
---

Great job finishing the Tour! You now have a solid grasp of the cpp-httplib basics. But there's a lot more to explore. Here's a quick overview of features we didn't cover in the Tour, organized by category.

## Streaming API

When you're working with LLM streaming responses or downloading large files, you don't want to load the entire response into memory. Use `stream::Get()` to process data chunk by chunk.

```cpp
httplib::Client cli("http://localhost:11434");

auto result = httplib::stream::Get(cli, "/api/generate");

if (result) {
    while (result.next()) {
        std::cout.write(result.data(), result.size());
    }
}
```

You can also pass a `content_receiver` callback to `Get()`. This approach works with Keep-Alive.

```cpp
httplib::Client cli("http://localhost:8080");

cli.Get("/stream", [](const char *data, size_t len) {
    std::cout.write(data, len);
    return true;
});
```

On the server side, you have `set_content_provider()` and `set_chunked_content_provider()`. Use the former when you know the size, and the latter when you don't.

```cpp
// With known size (sets Content-Length)
svr.Get("/file", [](const auto &, auto &res) {
    auto size = get_file_size("large.bin");
    res.set_content_provider(size, "application/octet-stream",
        [](size_t offset, size_t length, httplib::DataSink &sink) {
            // Send 'length' bytes starting from 'offset'
            return true;
        });
});

// Unknown size (Chunked Transfer Encoding)
svr.Get("/stream", [](const auto &, auto &res) {
    res.set_chunked_content_provider("text/plain",
        [](size_t offset, httplib::DataSink &sink) {
            sink.write("chunk\n", 6);
            return true;  // Return false to finish
        });
});
```

For uploading large files, `make_file_provider()` comes in handy. It streams the file instead of loading it all into memory.

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Post("/upload", {}, {
    httplib::make_file_provider("file", "/path/to/large-file.zip")
});
```

## Server-Sent Events (SSE)

We provide an SSE client as well. It supports automatic reconnection and resuming via `Last-Event-ID`.

```cpp
httplib::Client cli("http://localhost:8080");
httplib::sse::SSEClient sse(cli, "/events");

sse.on_message([](const httplib::sse::SSEMessage &msg) {
    std::cout << msg.event << ": " << msg.data << std::endl;
});

sse.start();  // Blocking, with auto-reconnection
```

You can also set separate handlers for each event type.

```cpp
sse.on_event("update", [](const httplib::sse::SSEMessage &msg) {
    // Only handles "update" events
});
```

## Authentication

The client has helpers for Basic auth, Bearer Token auth, and Digest auth.

```cpp
httplib::Client cli("https://api.example.com");
cli.set_basic_auth("user", "password");
cli.set_bearer_token_auth("my-token");
```

## Compression

We support compression and decompression with gzip, Brotli, and Zstandard. Define the corresponding macro when you compile.

| Method | Macro |
| -- | -- |
| gzip | `CPPHTTPLIB_ZLIB_SUPPORT` |
| Brotli | `CPPHTTPLIB_BROTLI_SUPPORT` |
| Zstandard | `CPPHTTPLIB_ZSTD_SUPPORT` |

```cpp
httplib::Client cli("https://example.com");
cli.set_compress(true);    // Compress request body
cli.set_decompress(true);  // Decompress response body
```

## Proxy

You can connect through an HTTP proxy.

```cpp
httplib::Client cli("https://example.com");
cli.set_proxy("proxy.example.com", 8080);
cli.set_proxy_basic_auth("user", "password");
```

## Timeouts

You can set connection, read, and write timeouts individually.

```cpp
httplib::Client cli("https://example.com");
cli.set_connection_timeout(5, 0);  // 5 seconds
cli.set_read_timeout(10, 0);       // 10 seconds
cli.set_write_timeout(10, 0);      // 10 seconds
```

## Keep-Alive

If you're making multiple requests to the same server, enable Keep-Alive. It reuses the TCP connection, which is much more efficient.

```cpp
httplib::Client cli("https://example.com");
cli.set_keep_alive(true);
```

## Server Middleware

You can hook into request processing before and after handlers run.

```cpp
svr.set_pre_routing_handler([](const auto &req, auto &res) {
    // Runs before every request
    return httplib::Server::HandlerResponse::Unhandled;  // Continue to normal routing
});

svr.set_post_routing_handler([](const auto &req, auto &res) {
    // Runs after the response is sent
    res.set_header("X-Server", "cpp-httplib");
});
```

Use `req.user_data` to pass data from middleware to handlers. This is useful for sharing things like decoded auth tokens.

```cpp
svr.set_pre_routing_handler([](const auto &req, auto &res) {
    req.user_data["auth_user"] = std::string("alice");
    return httplib::Server::HandlerResponse::Unhandled;
});

svr.Get("/me", [](const auto &req, auto &res) {
    auto user = std::any_cast<std::string>(req.user_data.at("auth_user"));
    res.set_content("Hello, " + user, "text/plain");
});
```

You can also customize error and exception handlers.

```cpp
svr.set_error_handler([](const auto &req, auto &res) {
    res.set_content("Custom Error Page", "text/html");
});

svr.set_exception_handler([](const auto &req, auto &res, std::exception_ptr ep) {
    res.status = 500;
    res.set_content("Internal Server Error", "text/plain");
});
```

## Logging

You can set a logger on both the server and the client.

```cpp
svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " " << res.status << std::endl;
});
```

## Unix Domain Socket

In addition to TCP, we support Unix Domain Sockets. You can use them for inter-process communication on the same machine.

```cpp
// Server
httplib::Server svr;
svr.set_address_family(AF_UNIX);
svr.listen("/tmp/httplib.sock", 0);
```

```cpp
// Client
httplib::Client cli("http://localhost");
cli.set_address_family(AF_UNIX);
cli.set_hostname_addr_map({{"localhost", "/tmp/httplib.sock"}});

auto res = cli.Get("/");
```

## Learn More

Want to dig deeper? Check out these resources.

- Cookbook — A collection of recipes for common use cases
- [README](https://github.com/yhirose/cpp-httplib/blob/master/README.md) — Full API reference
- [README-sse](https://github.com/yhirose/cpp-httplib/blob/master/README-sse.md) — How to use Server-Sent Events
- [README-stream](https://github.com/yhirose/cpp-httplib/blob/master/README-stream.md) — How to use the Streaming API
- [README-websocket](https://github.com/yhirose/cpp-httplib/blob/master/README-websocket.md) — How to use the WebSocket server
