---
title: "S15. 在服务器上记录请求日志"
order: 34
status: "draft"
---

要记录服务器收到的请求和返回的响应，请使用 `Server::set_logger()`。该回调会在每个请求完成时触发一次，是访问日志和指标采集的基础。

## 基本用法

```cpp
svr.set_logger([](const httplib::Request &req, const httplib::Response &res) {
  std::cout << req.remote_addr << " "
            << req.method << " " << req.path
            << " -> " << res.status << std::endl;
});
```

日志回调会同时收到 `Request` 和 `Response`。你可以获取方法、路径、状态码、客户端 IP、请求头、请求体——任何你需要的信息。

## 访问日志风格的格式

下面是一个类似 Apache/Nginx 的访问日志格式。

```cpp
svr.set_logger([](const auto &req, const auto &res) {
  auto now = std::time(nullptr);
  char timebuf[32];
  std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S",
                std::localtime(&now));

  std::cout << timebuf << " "
            << req.remote_addr << " "
            << "\"" << req.method << " " << req.path << "\" "
            << res.status << " "
            << res.body.size() << "B"
            << std::endl;
});
```

## 测量请求耗时

要在日志中包含请求耗时，可以在预路由处理器中把起始时间戳存入 `res.user_data`，然后在日志记录器中相减。

```cpp
svr.set_pre_routing_handler([](const auto &req, auto &res) {
  res.user_data.set("start", std::chrono::steady_clock::now());
  return httplib::Server::HandlerResponse::Unhandled;
});

svr.set_logger([](const auto &req, const auto &res) {
  auto *start = res.user_data.get<std::chrono::steady_clock::time_point>("start");
  auto elapsed = start
    ? std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - *start).count()
    : 0;
  std::cout << req.method << " " << req.path
            << " " << res.status << " " << elapsed << "ms" << std::endl;
});
```

关于 `user_data` 的更多内容，参见 [S12. 用 `res.user_data` 在处理器之间传递数据](../s12-user-data)。

> **注意：** 日志记录器与请求处理运行在同一个 thread 上，且是同步执行的。在其中做繁重的工作会损害吞吐量——如果需要任何昂贵的操作，请把它推入队列并异步处理。
