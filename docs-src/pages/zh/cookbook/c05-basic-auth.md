---
title: "C05. 使用 Basic 认证"
order: 5
status: "draft"
---

对于需要 Basic 认证的端点，请把用户名和密码传给 `set_basic_auth()`。cpp-httplib 会为你构建 `Authorization: Basic ...` 请求头。

## 基本用法

```cpp
httplib::Client cli("https://api.example.com");
cli.set_basic_auth("alice", "s3cret");

auto res = cli.Get("/private");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

设置一次后，该客户端的每个请求都会携带凭据。无需每次都构建请求头。

## 单次请求用法

如果只想在某个特定请求上使用凭据，可以直接传入请求头。

```cpp
httplib::Headers headers = {
  httplib::make_basic_authentication_header("alice", "s3cret"),
};
auto res = cli.Get("/private", headers);
```

`make_basic_authentication_header()` 会为你构建 Base64 编码的请求头。

> **警告：** Basic 认证只是用 Base64 **编码**凭据——并不会加密。请始终在 HTTPS 上使用它。在明文 HTTP 上，你的密码会以明文形式在网络中传输。

## Digest 认证

如需更安全的 Digest 认证方案，请使用 `set_digest_auth()`。只有在使用 OpenSSL（或其他 TLS 后端）编译 cpp-httplib 时才可用。

```cpp
cli.set_digest_auth("alice", "s3cret");
```

> 要使用 Bearer 令牌调用 API，请参见 [C06. 使用 Bearer 令牌调用 API](../c06-bearer-token)。
