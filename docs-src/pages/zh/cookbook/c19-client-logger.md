---
title: "C19. 在客户端上设置日志器"
order: 19
status: "draft"
---

要记录客户端发送的请求和接收到的响应，请使用 `set_logger()`。如果你只关心错误，还有一个单独的 `set_error_logger()`。

## 记录请求和响应

```cpp
httplib::Client cli("https://api.example.com");

cli.set_logger([](const httplib::Request &req, const httplib::Response &res) {
  std::cout << req.method << " " << req.path
            << " -> " << res.status << std::endl;
});

auto res = cli.Get("/users");
```

传给 `set_logger()` 的回调会在每个完成的请求上触发一次。你会在参数中同时拿到请求和响应 —— 因此你可以记录方法、路径、状态码、请求头、请求体，或者你需要的任何其他内容。

## 只捕获错误

当发生网络层错误时（例如 `Error::Connection`），`set_logger()` **不会**被调用 —— 因为没有响应可供记录。对于这些情况，请使用 `set_error_logger()`。

```cpp
cli.set_error_logger([](const httplib::Error &err, const httplib::Request *req) {
  std::cerr << "error: " << httplib::to_string(err);
  if (req) {
    std::cerr << " (" << req->method << " " << req->path << ")";
  }
  std::cerr << std::endl;
});
```

第二个参数 `req` 可能为 null —— 当失败发生在请求构建完成之前时就会这样。解引用之前一定要先做 null 检查。

## 两者一起使用

一个不错的方式是通过其中一个记录成功，通过另一个记录失败。

```cpp
cli.set_logger([](const auto &req, const auto &res) {
  std::cout << "[ok] " << req.method << " " << req.path
            << " " << res.status << std::endl;
});

cli.set_error_logger([](const auto &err, const auto *req) {
  std::cerr << "[ng] " << httplib::to_string(err);
  if (req) std::cerr << " " << req->method << " " << req->path;
  std::cerr << std::endl;
});
```

> **注意：** 日志回调会在与请求相同的线程上同步执行。在回调中做繁重的工作会拖慢请求 —— 如果你需要做任何开销较大的事情，请把它推到后台队列中。
