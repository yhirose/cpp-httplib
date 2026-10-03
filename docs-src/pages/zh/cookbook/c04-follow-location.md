---
title: "C04. 跟随重定向"
order: 4
status: "draft"
---

默认情况下，cpp-httplib 不会跟随 HTTP 重定向（3xx）。如果服务器返回 `302 Found`，你只会得到一个状态码为 302 的响应——仅此而已。

要自动跟随重定向，请调用 `set_follow_location(true)`。

## 跟随重定向

```cpp
httplib::Client cli("http://example.com");
cli.set_follow_location(true);

auto res = cli.Get("/old-path");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

启用 `set_follow_location(true)` 后，客户端会读取 `Location` 响应头，并自动向新的 URL 重新发起请求。最终响应会存入 `res`。

## 从 HTTP 到 HTTPS 的重定向

```cpp
httplib::Client cli("http://example.com");
cli.set_follow_location(true);

auto res = cli.Get("/");
```

许多网站会把 HTTP 流量重定向到 HTTPS。启用 `set_follow_location(true)` 后，这种情况会被透明处理——即使协议或主机发生变化，客户端也会跟随重定向。

> **警告：** 要跟随重定向到 HTTPS，需要使用 OpenSSL（或其他 TLS 后端）编译 cpp-httplib。如果没有 TLS 支持，重定向到 HTTPS 将会失败。

> **注意：** 跟随重定向会增加请求的总耗时。超时配置请参见 [C12. 设置超时](../c12-timeouts)。
