---
title: "C16. Send Requests Through a Proxy"
order: 16
status: "draft"
---

To route traffic through a corporate network or a specific path, send requests via an HTTP proxy. Just pass the proxy host and port to `set_proxy()`.

## Basic usage

```cpp
httplib::Client cli("https://api.example.com");
cli.set_proxy("proxy.internal", 8080);

auto res = cli.Get("/users");
```

The request goes through the proxy. For HTTPS, the client uses the CONNECT method to tunnel through — no extra setup required.

## Proxy authentication

If the proxy itself requires authentication, use `set_proxy_basic_auth()` or `set_proxy_bearer_token_auth()`.

```cpp
cli.set_proxy("proxy.internal", 8080);
cli.set_proxy_basic_auth("user", "password");
```

```cpp
cli.set_proxy_bearer_token_auth("token");
```

If cpp-httplib is built with OpenSSL (or another TLS backend), you can also use Digest authentication for the proxy.

```cpp
cli.set_proxy_digest_auth("user", "password");
```

## Combine with end-server authentication

Proxy authentication is separate from authenticating to the end server ([C05. Use Basic authentication](c05-basic-auth), [C06. Call an API with a Bearer token](c06-bearer-token)). When both are needed, set both.

```cpp
cli.set_proxy("proxy.internal", 8080);
cli.set_proxy_basic_auth("proxy-user", "proxy-pass");

cli.set_bearer_token_auth("api-token"); // for the end server
```

`Proxy-Authorization` is sent to the proxy, `Authorization` to the end server.

> **Note:** cpp-httplib does not read `HTTP_PROXY` or `HTTPS_PROXY` environment variables automatically. If you want to honor them, read them in your application and pass the values to `set_proxy()`.
