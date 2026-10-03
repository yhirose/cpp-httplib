---
title: "S16. 检测客户端已断开连接"
order: 35
status: "draft"
---

在长时间运行的响应过程中，客户端可能会关闭连接。继续做没有人等待的工作毫无意义。在 cpp-httplib 中，请检查 `req.is_connection_closed()`。

## 基本用法

```cpp
svr.Get("/long-task", [](const httplib::Request &req, httplib::Response &res) {
  for (int i = 0; i < 1000; ++i) {
    if (req.is_connection_closed()) {
      std::cout << "client disconnected" << std::endl;
      return;
    }

    do_heavy_work(i);
  }

  res.set_content("done", "text/plain");
});
```

`is_connection_closed` 是一个 `std::function<bool()>`，所以要用 `()` 调用它。当客户端已经消失时，它返回 `true`。

## 配合流式响应

同样的检查在 `set_chunked_content_provider()` 内部也适用。按引用捕获请求。

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/event-stream",
    [&req](size_t offset, httplib::DataSink &sink) {
      if (req.is_connection_closed()) {
        sink.done();
        return true;
      }

      auto event = generate_next_event();
      sink.write(event.data(), event.size());
      return true;
    });
});
```

当你检测到断开连接时，调用 `sink.done()` 以阻止提供器被再次调用。

## 应该多久检查一次？

这个调用本身开销很低，但在紧密的内层循环中调用它并不会带来多少价值。请在**中断安全的边界处**检查——例如生成一个 chunk 之后、数据库查询之后等。

> **警告：** `is_connection_closed()` 并不保证能立即反映真实情况。由于 TCP 的工作方式，有时只有在你尝试发送时才会察觉到断开连接。不要期待像素级完美的实时检测——把它理解为"我们最终会察觉到"即可。
