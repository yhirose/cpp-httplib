---
title: "S22. 通过 Unix domain socket 通信"
order: 41
status: "draft"
---

当你只想与同一主机上的其他进程通信时，Unix domain socket 是一个很合适的选择。它避免了 TCP 开销，并使用文件系统权限进行访问控制。本地 IPC 和位于反向代理之后的服务都是典型的用例。

## 服务器端

```cpp
httplib::Server svr;
svr.set_address_family(AF_UNIX);

svr.Get("/", [](const auto &, auto &res) {
  res.set_content("hello from unix socket", "text/plain");
});

svr.listen("/tmp/httplib.sock", 80);
```

先调用 `set_address_family(AF_UNIX)`，然后把套接字文件路径作为第一个参数传给 `listen()`。端口号不会被使用，但函数签名要求提供——传任意值即可。

## 客户端

```cpp
httplib::Client cli("/tmp/httplib.sock");
cli.set_address_family(AF_UNIX);

auto res = cli.Get("/");
if (res) {
  std::cout << res->body << std::endl;
}
```

把套接字文件路径传给 `Client` 构造函数，并调用 `set_address_family(AF_UNIX)`。其余一切与普通 HTTP 请求相同。

## 何时使用它

- **位于反向代理之后**：nginx 到后端通过 Unix domain socket 通信比 TCP 更快，并且省去了端口管理
- **仅本地 API**：不应从外部访问的工具之间的 IPC
- **容器内 IPC**：同一 pod 或容器内的进程间通信
- **开发环境**：不再需要担心端口冲突

## 清理套接字文件

Unix domain socket 会在文件系统中创建一个真实文件。它在关闭时不会被删除，所以如有需要，请在启动前先删除它。

```cpp
std::remove("/tmp/httplib.sock");
svr.listen("/tmp/httplib.sock", 80);
```

## 权限

你可以通过套接字文件的权限来控制谁可以连接。

```cpp
svr.listen("/tmp/httplib.sock", 80);
// from another process or thread
chmod("/tmp/httplib.sock", 0660); // owner and group only
```

> **警告：** 某些 Windows 版本支持 AF_UNIX，但实现和行为因平台而异。在生产环境中跨平台运行之前，请进行充分测试。
