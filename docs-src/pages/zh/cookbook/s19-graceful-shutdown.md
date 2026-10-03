---
title: "S19. 优雅关闭"
order: 38
status: "draft"
---

要停止服务器，请调用 `Server::stop()`。即使在请求正在处理时调用它也是安全的，因此你可以把它接到 SIGINT 或 SIGTERM 上实现优雅关闭。

## 基本用法

```cpp
httplib::Server svr;

svr.Get("/", [](const auto &, auto &res) { res.set_content("ok", "text/plain"); });

std::thread t([&] { svr.listen("0.0.0.0", 8080); });

// wait for input on the main thread, or whatever
std::cin.get();

svr.stop();
t.join();
```

`listen()` 会阻塞，所以典型的模式是：在后台 thread 上运行服务器，从主 thread 调用 `stop()`。调用 `stop()` 后，`listen()` 会返回，你就可以 `join()` 了。

## 收到信号时关闭

下面介绍如何在收到 SIGINT（Ctrl+C）或 SIGTERM 时停止服务器。

```cpp
#include <csignal>

httplib::Server svr;

// global so the signal handler can reach it
httplib::Server *g_svr = nullptr;

int main() {
  svr.Get("/", [](const auto &, auto &res) { res.set_content("ok", "text/plain"); });

  g_svr = &svr;
  std::signal(SIGINT,  [](int) { if (g_svr) g_svr->stop(); });
  std::signal(SIGTERM, [](int) { if (g_svr) g_svr->stop(); });

  svr.listen("0.0.0.0", 8080);
  std::cout << "server stopped" << std::endl;
}
```

`stop()` 是 thread 安全且信号安全的——你可以从信号处理器中调用它。即使 `listen()` 正在主 thread 上运行，信号也能干净地把它拉出来。

## 正在处理的请求会怎样

当你调用 `stop()` 时，新连接会被拒绝，但已经在处理的请求**允许完成**。当所有工作线程都排空后，`listen()` 返回。这正是它之所以"优雅"的原因。

> **警告：** 从调用 `stop()` 到 `listen()` 返回之间存在一段等待——这段时长就是处理中的请求完成所需的时间。要强制实施超时，你需要在应用代码中自己添加关闭计时器。
