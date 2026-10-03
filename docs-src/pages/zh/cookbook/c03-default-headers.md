---
title: "C03. 设置默认请求头"
order: 3
status: "draft"
---

如果希望每个请求都带上相同的请求头，请使用 `set_default_headers()`。设置一次后，它们会自动附加到该客户端发出的每个请求上。

## 基本用法

```cpp
httplib::Client cli("https://api.example.com");

cli.set_default_headers({
  {"Accept", "application/json"},
  {"User-Agent", "my-app/1.0"},
});

auto res = cli.Get("/users");
```

把每次 API 调用都需要的请求头——比如 `Accept` 或 `User-Agent`——集中注册在一处。无需在每个请求中重复设置。

## 在每个请求中发送 Bearer 令牌

```cpp
httplib::Client cli("https://api.example.com");

cli.set_default_headers({
  {"Authorization", "Bearer " + token},
  {"Accept", "application/json"},
});

auto res1 = cli.Get("/me");
auto res2 = cli.Get("/projects");
```

认证令牌只需设置一次，之后每个请求都会携带它。在编写需要访问多个端点的 API 客户端时非常方便。

> **注意：** `set_default_headers()` 会**替换**已有的默认请求头。即使你只想新增一个，也需要把完整的集合再传一遍。

## 与单次请求的请求头组合使用

即使设置了默认值，你仍然可以在单个请求上传入额外的请求头。

```cpp
httplib::Headers headers = {
  {"X-Request-ID", "abc-123"},
};
auto res = cli.Get("/users", headers);
```

单次请求的请求头会**追加**在默认请求头之上。两者都会发送给服务器。

> 关于 Bearer 令牌认证的详细信息，请参见 [C06. 使用 Bearer 令牌调用 API](../c06-bearer-token)。
