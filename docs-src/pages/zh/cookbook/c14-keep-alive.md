---
title: "C14. 理解连接复用与 Keep-Alive 行为"
order: 14
status: "draft"
---

当你通过同一个 `httplib::Client` 实例发送多个请求时，TCP 连接会被自动复用。HTTP/1.1 Keep-Alive 会替你完成这项工作 —— 你无需在每次调用时都付出 TCP 和 TLS 握手的开销。

## 连接会被自动复用

```cpp
httplib::Client cli("https://api.example.com");

auto res1 = cli.Get("/users/1");
auto res2 = cli.Get("/users/2"); // 复用同一个连接
auto res3 = cli.Get("/users/3"); // 复用同一个连接
```

不需要特殊配置。只要一直持有 `cli` 即可 —— 在内部，套接字会跨调用保持打开。这一效果在 HTTPS 上尤其明显，因为那里的 TLS 握手开销很大。

## 显式禁用 Keep-Alive

如果想强制每次都使用全新连接，请调用 `set_keep_alive(false)`。这主要用于测试。

```cpp
cli.set_keep_alive(false);
```

正常使用时请保持开启（默认值）。

## 不要为每个请求都创建一个 `Client`

如果你在循环内部创建 `Client`，并让它在每次迭代后离开作用域，就会失去复用的好处。请把实例创建在循环外部。

```cpp
// 不好：每次迭代都新建一个连接
for (auto id : ids) {
  httplib::Client cli("https://api.example.com");
  cli.Get("/users/" + id);
}

// 好：连接被复用
httplib::Client cli("https://api.example.com");
for (auto id : ids) {
  cli.Get("/users/" + id);
}
```

## 并发请求

如果你想从多个线程并行发送请求，请为每个线程分配各自的 `Client` 实例。单个 `Client` 使用单个 TCP 连接，因此对同一实例发起并发请求最终仍会被串行化。

> **注意：** 如果服务器在其 Keep-Alive 超时后关闭了连接，cpp-httplib 会透明地重新连接并重试。你无需在应用代码中处理这种情况。
