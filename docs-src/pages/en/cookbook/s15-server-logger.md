---
title: "S15. Log Requests on the Server"
order: 34
status: "draft"
---

To log the requests the server receives and the responses it returns, use `Server::set_logger()`. The callback fires once per completed request, making it the foundation for access logs and metrics collection.

## Basic usage

```cpp
svr.set_logger([](const httplib::Request &req, const httplib::Response &res) {
  std::cout << req.remote_addr << " "
            << req.method << " " << req.path
            << " -> " << res.status << std::endl;
});
```

The log callback receives both the `Request` and the `Response`. You can grab the method, path, status, client IP, headers, body — whatever you need.

## Access-log style format

Here's an Apache/Nginx-ish access log format.

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

## Measure request time

To include request duration in the log, stash a start timestamp in `res.user_data` from a pre-routing handler, then subtract in the logger.

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

For more on `user_data`, see S12. Pass Data Between Handlers with `res.user_data`.

> **Note:** The logger runs synchronously on the same thread as request processing. Heavy work inside it hurts throughput — push it to a queue and process asynchronously if you need anything expensive.
