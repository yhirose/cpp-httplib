---
title: "S18. 用 listen_after_bind 控制启动顺序"
order: 37
status: "draft"
---

通常 `svr.listen("0.0.0.0", 8080)` 会一次性完成绑定和监听。当你需要在这两步之间做某些事情时，请把它们拆成两次调用。

## 分离绑定和监听

```cpp
httplib::Server svr;

svr.Get("/", [](const auto &, auto &res) { res.set_content("ok", "text/plain"); });

if (!svr.bind_to_port("0.0.0.0", 8080)) {
  std::cerr << "bind failed" << std::endl;
  return 1;
}

// bind is done here. accept hasn't started yet.
drop_privileges();
signal_ready_to_parent_process();

svr.listen_after_bind(); // start the accept loop
```

`bind_to_port()` 预留端口；`listen_after_bind()` 才真正开始接受连接。将它们分离，你就拥有了这两步之间的一个窗口期。

## 常见用例

**降权**：绑定 1024 以下的端口需要 root 权限。以 root 身份绑定，然后降权到普通用户，之后所有的请求处理都以降低后的权限运行。

```cpp
svr.bind_to_port("0.0.0.0", 80);
drop_privileges();
svr.listen_after_bind();
```

**启动通知**：在开始接受连接之前，告诉父进程或 systemd"我已就绪"。

**测试同步**：在测试中，你可以可靠地捕捉到"服务器完成绑定的那一刻"，并在此之后启动客户端。

## 检查返回值

`bind_to_port()` 在失败时返回 `false`，例如你没有权限绑定该端口时。请务必检查它。

```cpp
if (!svr.bind_to_port("0.0.0.0", 8080)) {
  std::cerr << "bind failed" << std::endl;
  return 1;
}
```

`listen_after_bind()` 会阻塞直到服务器停止，并在正常关闭时返回 `true`。

## 检测端口已被占用

在默认设置下，你实际上可以绑定到另一个服务器已经在使用的端口。这是因为 cpp-httplib 会在服务器套接字上设置 `SO_REUSEPORT`（Linux、macOS）或 `SO_REUSEADDR`（Windows）。重启后的服务器可以立即再次绑定。另一面则是，同一端口上的第二个服务器会毫无错误地启动，连接会在两者之间被拆分。

要让 `bind_to_port()` 在端口被占用时失败，可以用 `set_socket_options()` 替换套接字选项。

```cpp
svr.set_socket_options([](socket_t sock) {
#ifdef _WIN32
  httplib::set_socket_opt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
#else
  httplib::set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
#endif
});

if (!svr.bind_to_port("0.0.0.0", 8080)) {
  std::cerr << "port already in use" << std::endl;
  return 1;
}
```

`set_socket_options()` 会完全替换默认设置。在 Linux 和 macOS 上设置 `SO_REUSEADDR` 会保留"重启后的服务器可以立即再次绑定"的行为。

> **注意：** 仅在 Windows 上设置 `SO_REUSEADDR` 是不够的。两个都设置了它的套接字可以绑定到同一端口，所以请改用 `SO_EXCLUSIVEADDRUSE`。

> **注意：** 要自动挑选空闲端口，参见 [S17. 绑定到任意可用端口](../s17-bind-any-port)。底层实现其实只是 `bind_to_any_port()` + `listen_after_bind()`。
