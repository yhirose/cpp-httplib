---
title: "S17. 绑定到任意可用端口"
order: 36
status: "draft"
---

搭建测试服务器时经常会遇到端口冲突。使用 `bind_to_any_port()`，你可以让操作系统挑选一个空闲端口，然后读取它分配给你的是哪一个。

## 基本用法

```cpp
httplib::Server svr;

svr.Get("/", [](const auto &req, auto &res) {
  res.set_content("hello", "text/plain");
});

int port = svr.bind_to_any_port("0.0.0.0");
std::cout << "listening on port " << port << std::endl;

svr.listen_after_bind();
```

`bind_to_any_port()` 等价于把端口传为 `0`——操作系统会分配一个空闲端口。返回值是实际使用的端口。

之后，调用 `listen_after_bind()` 开始接受连接。这里无法把绑定和监听的调用合并为一个，所以需要分两步完成。

## 在测试中很有用

这种模式非常适合启动服务器并访问它的测试。

```cpp
httplib::Server svr;
svr.Get("/ping", [](const auto &, auto &res) { res.set_content("pong", "text/plain"); });

int port = svr.bind_to_any_port("127.0.0.1");
std::thread t([&] { svr.listen_after_bind(); });

// run the test while the server is up on another thread
httplib::Client cli("127.0.0.1", port);
auto res = cli.Get("/ping");
assert(res && res->body == "pong");

svr.stop();
t.join();
```

由于端口是在运行时分配的，并行的测试运行不会相互冲突。

> **注意：** `bind_to_any_port()` 在失败时（权限错误、没有可用端口等）返回 `-1`。请务必检查返回值。

> 要停止服务器，参见 [S19. 优雅关闭](../s19-graceful-shutdown)。
