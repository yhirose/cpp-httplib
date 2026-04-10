---
title: "S21. Configure the Thread Pool"
order: 40
status: "draft"
---

cpp-httplib serves requests from a thread pool. By default, the base thread count is the greater of `std::thread::hardware_concurrency() - 1` and `8`, and it can scale up dynamically to 4× that. To set thread counts explicitly, provide your own factory via `new_task_queue`.

## Set thread counts

```cpp
httplib::Server svr;

svr.new_task_queue = [] {
  return new httplib::ThreadPool(/*base_threads=*/8, /*max_threads=*/64);
};

svr.listen("0.0.0.0", 8080);
```

The factory is a lambda returning a `TaskQueue*`. Pass `base_threads` and `max_threads` to `ThreadPool` and the pool scales between them based on load. Idle threads exit after a timeout (3 seconds by default).

## Also cap the queue

The pending queue can eat memory if it grows unchecked. You can cap it too.

```cpp
svr.new_task_queue = [] {
  return new httplib::ThreadPool(
    /*base_threads=*/12,
    /*max_threads=*/0,   // disable dynamic scaling
    /*max_queued_requests=*/18);
};
```

`max_threads=0` disables dynamic scaling — you get a fixed `base_threads`. Requests that don't fit in `max_queued_requests` are rejected.

## Use your own thread pool

You can plug in a fully custom thread pool by subclassing `TaskQueue` and returning it from the factory.

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

Handy when you already have a thread pool in your project and want to keep thread management unified.

## Compile-time tuning

You can set the defaults with macros if you want compile-time configuration.

```cpp
#define CPPHTTPLIB_THREAD_POOL_COUNT 16       // base thread count
#define CPPHTTPLIB_THREAD_POOL_MAX_COUNT 128   // max thread count
#define CPPHTTPLIB_THREAD_POOL_IDLE_TIMEOUT 5  // seconds before idle threads exit
#include <httplib.h>
```

> **Note:** A WebSocket connection holds a worker thread for its entire lifetime. For lots of simultaneous WebSocket connections, enable dynamic scaling (e.g. `ThreadPool(8, 64)`).
