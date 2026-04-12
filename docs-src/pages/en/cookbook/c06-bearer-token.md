---
title: "C06. Call an API with a Bearer Token"
order: 6
status: "draft"
---

For Bearer token authentication — common in OAuth 2.0 and modern Web APIs — use `set_bearer_token_auth()`. Pass the token and cpp-httplib builds the `Authorization: Bearer <token>` header for you.

## Basic usage

```cpp
httplib::Client cli("https://api.example.com");
cli.set_bearer_token_auth("eyJhbGciOiJIUzI1NiIs...");

auto res = cli.Get("/me");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

Set it once and every subsequent request carries the token. This is the go-to pattern for token-based APIs like GitHub, Slack, or your own OAuth service.

## Per-request usage

When you want the token on only one request — or need a different token per request — pass it via headers.

```cpp
httplib::Headers headers = {
  httplib::make_bearer_token_authentication_header(token),
};
auto res = cli.Get("/me", headers);
```

`make_bearer_token_authentication_header()` builds the `Authorization` header for you.

## Refresh the token

When a token expires, just call `set_bearer_token_auth()` again with the new one.

```cpp
if (res && res->status == 401) {
  auto new_token = refresh_token();
  cli.set_bearer_token_auth(new_token);
  res = cli.Get("/me");
}
```

> **Warning:** A Bearer token is itself a credential. Always send it over HTTPS, and never hard-code it into source or config files.

> To set multiple headers at once, see [C03. Set default headers](c03-default-headers).
