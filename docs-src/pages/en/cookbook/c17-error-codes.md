---
title: "C17. Handle Error Codes"
order: 17
status: "draft"
---

`cli.Get()`, `cli.Post()`, and friends return a `Result`. When the request fails — can't reach the server, times out, etc. — the result is "falsy", with one exception noted in the table below. To get the specific reason, use `Result::error()`.

## Basic check

```cpp
httplib::Client cli("http://localhost:8080");
auto res = cli.Get("/api/data");

if (res) {
  // the request was sent and a response came back
  std::cout << "status: " << res->status << std::endl;
} else {
  // the network layer failed
  std::cerr << "error: " << httplib::to_string(res.error()) << std::endl;
}
```

Use `if (res)` to check success. On failure, `res.error()` returns a `httplib::Error` enum value. Pass it to `to_string()` to get a human-readable description.

## Common errors

| Value | Meaning |
| --- | --- |
| `Error::Connection` | Couldn't connect to the server, or the `Client` was built from a URL it can't use (userinfo or a backslash in the authority, a bad port). In the latter case `cli.is_valid()` is `false` |
| `Error::ConnectionTimeout` | Connection timeout (`set_connection_timeout`) |
| `Error::Read` / `Error::Write` | Error during send or receive. A timeout from `set_read_timeout` or `set_max_timeout` is also reported as `Error::Read` |
| `Error::ExceedMaxPayloadSize` | The response body is larger than `set_payload_max_length()` allows, also once decompressed |
| `Error::Timeout` | A body read timed out in `stream::Get()` or `SSEClient` |
| `Error::ExceedRedirectCount` | Too many redirects |
| `Error::SSLConnection` | TLS handshake failed |
| `Error::SSLServerVerification` | Server certificate verification failed |
| `Error::ProxyConnection` | The proxy refused the CONNECT tunnel. A 407 is the exception: `res` is truthy with `res->status == 407`, and `res.error()` is still `Error::ProxyConnection` |
| `Error::Canceled` | A progress callback, a `ContentReceiver`, a `ResponseHandler`, or an upload content provider returned `false` |

## Network errors vs. HTTP errors

Even when `res` is truthy, the HTTP status code can still be 4xx or 5xx. These are two different things.

```cpp
auto res = cli.Get("/api/data");
if (!res) {
  // network error (no response received at all)
  std::cerr << "network error: " << httplib::to_string(res.error()) << std::endl;
  return 1;
}

if (res->status >= 400) {
  // HTTP error (response received, but the status is bad)
  std::cerr << "http error: " << res->status << std::endl;
  return 1;
}

// success
std::cout << res->body << std::endl;
```

Keep them separated in your head: network-layer errors go through `res.error()`, HTTP-level errors through `res->status`.

> To dig deeper into SSL-related errors, see [C18. Handle SSL errors](../c18-ssl-errors).
