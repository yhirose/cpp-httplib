---
title: "S10. 使用 post-routing 处理器添加响应头"
order: 29
status: "draft"
---

有时你希望在处理器运行之后为响应添加共享的响应头——CORS 响应头、安全响应头、请求 ID，等等。这正是 `set_post_routing_handler()` 的用途。

## 基本用法

```cpp
svr.set_post_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    res.set_header("X-Request-ID", generate_request_id());
  });
```

post-routing 处理器在**路由处理器之后、响应发送之前**运行。在这里你可以调用 `res.set_header()` 或 `res.headers.erase()`，在一个地方为每个响应添加或移除响应头。

## 添加 CORS 响应头

CORS 是一个经典的使用场景。

```cpp
svr.set_post_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  });
```

对于预检 `OPTIONS` 请求，请注册一个单独的处理器——或者在 pre-routing 处理器中处理它们。

```cpp
svr.Options("/.*", [](const auto &req, auto &res) {
  res.status = 204;
});
```

## 集中管理你的安全响应头

在一个地方管理浏览器的安全响应头。

```cpp
svr.set_post_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
  });
```

无论响应是由哪个处理器产生的，都会附加相同的响应头。

> **注意：** 对于不匹配任何路由的响应，以及来自错误处理器的响应，post-routing 处理器也会运行。当你需要保证每个响应都带有某些响应头时，这正是你想要的。
