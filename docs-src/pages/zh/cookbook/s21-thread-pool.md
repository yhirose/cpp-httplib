---
title: "S21. 配置线程池"
order: 40
status: "draft"
---

cpp-httplib 使用线程池来服务请求。默认情况下，基础 thread 数量是 `std::thread::hardware_concurrency() - 1` 与 `8` 中的较大者，并且可以动态扩展至该值的 4 倍。要显式设置 thread 数量，请通过 `new_task_queue` 提供你自己的工厂。

## 设置 thread 数量

```cpp
httplib::Server svr;

svr.new_task_queue = [] {
  return new httplib::ThreadPool(/*base_threads=*/8, /*max_threads=*/64);
};

svr.listen("0.0.0.0", 8080);
```

该工厂是一个返回 `TaskQueue*` 的 lambda。把 `base_threads` 和 `max_threads` 传给 `ThreadPool`，线程池会根据负载在两者之间扩展。空闲 thread 会在超时后退出（默认 3 秒）。

## 同时限制队列

待处理队列如果无限制增长会吞噬内存。你也可以对它加以限制。

```cpp
svr.new_task_queue = [] {
  return new httplib::ThreadPool(
    /*base_threads=*/12,
    /*max_threads=*/0,   // disable dynamic scaling
    /*max_queued_requests=*/18);
};
```

`max_threads=0` 会禁用动态扩展——你将得到一个固定的 `base_threads`。无法放入 `max_queued_requests` 的请求会被拒绝。

## 使用你自己的线程池

你可以通过继承 `TaskQueue` 并让工厂返回它，来接入一个完全自定义的线程池。

```cpp
class MyTaskQueue : public httplib::TaskQueue {
public:
  MyTaskQueue(size_t n) { pool_.start_with_thread_count(n); }
  bool enqueue(std::function<void()> fn) override { return pool_.post(std::move(fn)); }
  void shutdown() override { pool_.shutdown(); }

private:
  MyThreadPool pool_;
};

svr.new_task_queue = [] { return new MyTaskQueue(12); };
```

当你项目中已经有一个线程池，并希望统一管理 thread 时，这会很方便。

## 编译期调优

如果你想要编译期配置，可以用宏来设置默认值。

```cpp
#define CPPHTTPLIB_THREAD_POOL_COUNT 16       // base thread count
#define CPPHTTPLIB_THREAD_POOL_MAX_COUNT 128   // max thread count
#define CPPHTTPLIB_THREAD_POOL_IDLE_TIMEOUT 5  // seconds before idle threads exit
#include <httplib.h>
```

> **注意：** 一个 WebSocket 连接会在其整个生命周期内占用一个工作 thread。对于大量同时存在的 WebSocket 连接，请启用动态扩展（例如 `ThreadPool(8, 64)`）。
