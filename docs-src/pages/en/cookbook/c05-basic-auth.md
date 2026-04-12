---
title: "C05. Use Basic Authentication"
order: 5
status: "draft"
---

For endpoints that require Basic authentication, pass the username and password to `set_basic_auth()`. cpp-httplib builds the `Authorization: Basic ...` header for you.

## Basic usage

```cpp
httplib::Client cli("https://api.example.com");
cli.set_basic_auth("alice", "s3cret");

auto res = cli.Get("/private");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

Set it once, and every request from that client carries the credentials. No need to build the header each time.

## Per-request usage

If you want credentials on only one specific request, pass headers directly.

```cpp
httplib::Headers headers = {
  httplib::make_basic_authentication_header("alice", "s3cret"),
};
auto res = cli.Get("/private", headers);
```

`make_basic_authentication_header()` builds the Base64-encoded header for you.

> **Warning:** Basic authentication **encodes** credentials in Base64 — it does not encrypt them. Always use it over HTTPS. Over plain HTTP, your password travels the network in the clear.

## Digest authentication

For the more secure Digest authentication scheme, use `set_digest_auth()`. This is only available when cpp-httplib is built with OpenSSL (or another TLS backend).

```cpp
cli.set_digest_auth("alice", "s3cret");
```

> To call an API with a Bearer token, see [C06. Call an API with a Bearer token](c06-bearer-token).
