---
title: "S19. Shut Down Gracefully"
order: 38
status: "draft"
---

To stop the server, call `Server::stop()`. It's safe to call even while requests are in flight, so you can wire it to SIGINT or SIGTERM for a graceful shutdown.

## Basic usage

```cpp
httplib::Server svr;

svr.Get("/", [](const auto &, auto &res) { res.set_content("ok", "text/plain"); });

std::thread t([&] { svr.listen("0.0.0.0", 8080); });

// wait for input on the main thread, or whatever
std::cin.get();

svr.stop();
t.join();
```

`listen()` blocks, so the typical pattern is: run the server on a background thread and call `stop()` from the main thread. After `stop()`, `listen()` returns and you can `join()`.

## Shut down on a signal

Here's how to stop the server on SIGINT (Ctrl+C) or SIGTERM.

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

`stop()` is thread-safe and signal-safe — you can call it from a signal handler. Even when `listen()` is running on the main thread, the signal pulls it out cleanly.

## What happens to in-flight requests

When you call `stop()`, new connections are refused, but requests already being processed are **allowed to finish**. Once all workers drain, `listen()` returns. That's what makes it graceful.

> **Warning:** There's a wait between calling `stop()` and `listen()` returning — it's the time in-flight requests take to finish. To enforce a timeout, you'll need to add your own shutdown timer in application code.
