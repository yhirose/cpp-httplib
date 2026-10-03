---
title: "C17. 处理错误码"
order: 17
status: "draft"
---

`cli.Get()`、`cli.Post()` 以及类似的函数会返回一个 `Result`。当请求失败时 —— 无法连接到服务器、超时等 —— 结果就是“假值”（falsy）。要获取具体原因，请使用 `Result::error()`。

## 基本检查

```cpp
httplib::Client cli("http://localhost:8080");
auto res = cli.Get("/api/data");

if (res) {
  // 请求已发送并收到了响应
  std::cout << "status: " << res->status << std::endl;
} else {
  // 网络层失败
  std::cerr << "error: " << httplib::to_string(res.error()) << std::endl;
}
```

使用 `if (res)` 检查是否成功。失败时，`res.error()` 会返回一个 `httplib::Error` 枚举值。把它传给 `to_string()` 就能得到人类可读的描述。

## 常见错误

| 值 | 含义 |
| --- | --- |
| `Error::Connection` | 无法连接到服务器 |
| `Error::ConnectionTimeout` | 连接超时（`set_connection_timeout`） |
| `Error::Read` / `Error::Write` | 发送或接收过程中出错 |
| `Error::Timeout` | 通过 `set_max_timeout` 设置的整体超时 |
| `Error::ExceedRedirectCount` | 重定向次数过多 |
| `Error::SSLConnection` | TLS 握手失败 |
| `Error::SSLServerVerification` | 服务器证书验证失败 |
| `Error::Canceled` | 某个进度回调返回了 `false` |

## 网络错误与 HTTP 错误

即使 `res` 为真值，HTTP 状态码仍可能是 4xx 或 5xx。这是两件不同的事。

```cpp
auto res = cli.Get("/api/data");
if (!res) {
  // 网络错误（完全没有收到响应）
  std::cerr << "network error: " << httplib::to_string(res.error()) << std::endl;
  return 1;
}

if (res->status >= 400) {
  // HTTP 错误（收到了响应，但状态码不正常）
  std::cerr << "http error: " << res->status << std::endl;
  return 1;
}

// 成功
std::cout << res->body << std::endl;
```

请在脑海中把两者区分开：网络层错误通过 `res.error()` 获取，HTTP 层错误通过 `res->status` 获取。

> 要进一步深入了解与 SSL 相关的错误，请参阅 [C18. 处理 SSL 错误](../c18-ssl-errors)。
