---
title: "C06. 使用 Bearer 令牌调用 API"
order: 6
status: "draft"
---

对于 Bearer 令牌认证——常见于 OAuth 2.0 和现代 Web API——请使用 `set_bearer_token_auth()`。传入令牌后，cpp-httplib 会为你构建 `Authorization: Bearer <token>` 请求头。

## 基本用法

```cpp
httplib::Client cli("https://api.example.com");
cli.set_bearer_token_auth("eyJhbGciOiJIUzI1NiIs...");

auto res = cli.Get("/me");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

设置一次后，之后每个请求都会携带该令牌。对于 GitHub、Slack 或你自己的 OAuth 服务等基于令牌的 API，这是首选模式。

## 单次请求用法

如果只想在某个请求上使用令牌——或者每个请求需要不同的令牌——可以通过请求头传入。

```cpp
httplib::Headers headers = {
  httplib::make_bearer_token_authentication_header(token),
};
auto res = cli.Get("/me", headers);
```

`make_bearer_token_authentication_header()` 会为你构建 `Authorization` 请求头。

## 刷新令牌

当令牌过期时，只需用新令牌再次调用 `set_bearer_token_auth()`。

```cpp
if (res && res->status == 401) {
  auto new_token = refresh_token();
  cli.set_bearer_token_auth(new_token);
  res = cli.Get("/me");
}
```

> **警告：** Bearer 令牌本身就是一种凭据。请始终通过 HTTPS 发送，切勿将其硬编码到源代码或配置文件中。

> 要一次设置多个请求头，请参见 [C03. 设置默认请求头](../c03-default-headers)。
