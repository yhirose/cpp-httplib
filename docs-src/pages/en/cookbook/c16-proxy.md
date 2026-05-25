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

## Bypass the proxy for specific hosts

You often want internal endpoints to skip the proxy. Configure a bypass list with `set_no_proxy()`.

```cpp
cli.set_proxy("proxy.internal", 8080);
cli.set_no_proxy({"internal.corp", "10.0.0.0/8", "*.dev.local"});
```

Each entry is one of:

- `*` — bypass the proxy for all hosts
- a hostname suffix (e.g. `example.com`) — matches `example.com` itself and any subdomain (`foo.example.com`). A leading dot is permitted but informational; both forms are equivalent.
- a single IP literal (e.g. `192.168.1.1`, `::1`)
- a CIDR block (e.g. `10.0.0.0/8`, `fe80::/10`)

Hostname matching is case-insensitive and uses a dot-boundary rule, so an entry of `example.com` does **not** match `evilexample.com`. IP comparisons are normalized through `inet_pton`, so `127.0.0.1` cannot be bypassed via alternate string forms (e.g. `127.000.000.001`). When an entry matches, the `Proxy-Authorization` header is suppressed as well.

Malformed entries are silently dropped. Port-specific entries such as `example.com:8080` are not supported (cpp-httplib's other host-keyed APIs are also keyed on hostname only).

## Read proxy settings from the environment

cpp-httplib doesn't touch `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` on its own — the config API is always explicit, the same way `set_ca_cert_path()` is. If you'd like that behavior, read the variables in your application and feed them to `set_proxy()` and `set_no_proxy()`.

```cpp
if (const char *v = std::getenv("no_proxy")) {
  std::vector<std::string> patterns;
  std::stringstream ss(v);
  for (std::string item; std::getline(ss, item, ',');) {
    if (!item.empty()) { patterns.push_back(item); }
  }
  cli.set_no_proxy(patterns);
}
```

If you also read `HTTP_PROXY` yourself, honor the lowercase `http_proxy` only. The uppercase form is poisoned in CGI/FastCGI environments by the `Proxy:` request header ([CVE-2016-5385 / "httpoxy"](https://httpoxy.org/)). `HTTPS_PROXY` and `NO_PROXY` are safe in either case because their names don't begin with `HTTP_`.
