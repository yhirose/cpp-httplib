---
title: "C13. 设置整体超时"
order: 13
status: "draft"
---

[C12. 设置超时](../c12-timeouts)中的三种超时都作用于单次 `send` 或 `recv` 调用。如果要限制一个请求可以花费的总时间，请使用 `set_max_timeout()`。

## 基本用法

```cpp
httplib::Client cli("http://localhost:8080");

cli.set_max_timeout(5000); // 5 秒（单位为毫秒）

auto res = cli.Get("/slow-endpoint");
```

该值以毫秒为单位。连接、发送和接收合计 —— 如果超过限制，整个请求都会被中止。

## 使用 `std::chrono`

还有一个接受 `std::chrono` 时长（duration）的重载。

```cpp
using namespace std::chrono_literals;
cli.set_max_timeout(5s);
```

## 何时使用哪一个

当一段时间内没有数据到达时，`set_read_timeout` 会触发。如果数据一点一点地持续到来，它就永远不会触发。对于一个每秒只发送一个字节的端点，无论你把 `set_read_timeout` 设得多短都没有用。

`set_max_timeout` 限制的是经过的时间，因此能干净利落地处理这些情况。它非常适合调用外部 API，或者任何你不希望用户无限等待的场景。

```cpp
cli.set_connection_timeout(3s);
cli.set_read_timeout(10s);
cli.set_max_timeout(30s); // 如果整个请求耗时超过 30s 就中止
```

> **注意：** `set_max_timeout()` 会与常规超时协同工作。短暂的停顿由 `set_read_timeout` 捕获；长时间运行的请求由 `set_max_timeout` 限制。两者一起使用可以形成一道安全网。
