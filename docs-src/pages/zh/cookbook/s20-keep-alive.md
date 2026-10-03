---
title: "S20. 调整 Keep-Alive"
order: 39
status: "draft"
---

`httplib::Server` 会自动启用 HTTP/1.1 Keep-Alive。从客户端的角度来看，连接会被复用——因此它们不必在每个请求上付出 TCP 握手的开销。当你需要调整该行为时，有两个 setter。

## 可以配置的内容

| API | 默认值 | 含义 |
| --- | --- | --- |
| `set_keep_alive_max_count` | 100 | 单个连接上服务的最大请求数 |
| `set_keep_alive_timeout` | 5s | 空闲连接在关闭前保持的时长 |

## 基本用法

```cpp
httplib::Server svr;

svr.set_keep_alive_max_count(20);
svr.set_keep_alive_timeout(10); // 10 seconds

svr.listen("0.0.0.0", 8080);
```

`set_keep_alive_timeout()` 还有一个 `std::chrono` 重载。

```cpp
using namespace std::chrono_literals;
svr.set_keep_alive_timeout(10s);
```

## 调优思路

**空闲连接太多，占用资源**  
缩短超时时间，让空闲连接断开并释放其工作 thread。

```cpp
svr.set_keep_alive_timeout(2s);
```

**API 被高频访问，想要最大化复用**  
提高每个连接的请求上限可以改善基准测试数据。

```cpp
svr.set_keep_alive_max_count(1000);
```

**从不复用连接**  
设置 `set_keep_alive_max_count(1)`，每个请求都会获得自己的连接。这主要用于调试或兼容性测试。

## 与线程池的关系

一个 Keep-Alive 连接会在其整个生命周期内占用一个工作 thread。如果 `连接数 × 并发请求数` 超过了线程池大小，新请求就会等待。关于 thread 数量，参见 [S21. 配置线程池](../s21-thread-pool)。

> **注意：** 关于客户端侧，参见 [C14. 理解连接复用与 Keep-Alive 行为](../c14-keep-alive)。即使服务器在超时后关闭了连接，客户端也会自动重连。
