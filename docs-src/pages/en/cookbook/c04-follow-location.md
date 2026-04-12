---
title: "C04. Follow Redirects"
order: 4
status: "draft"
---

By default, cpp-httplib does not follow HTTP redirects (3xx). If the server returns `302 Found`, you'll get it as a response with status code 302 — nothing more.

To follow redirects automatically, call `set_follow_location(true)`.

## Follow redirects

```cpp
httplib::Client cli("http://example.com");
cli.set_follow_location(true);

auto res = cli.Get("/old-path");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

With `set_follow_location(true)`, the client reads the `Location` header and reissues the request to the new URL automatically. The final response ends up in `res`.

## Redirects from HTTP to HTTPS

```cpp
httplib::Client cli("http://example.com");
cli.set_follow_location(true);

auto res = cli.Get("/");
```

Many sites redirect HTTP traffic to HTTPS. With `set_follow_location(true)` on, this case is handled transparently — the client follows redirects even when the scheme or host changes.

> **Warning:** To follow redirects to HTTPS, you need to build cpp-httplib with OpenSSL (or another TLS backend). Without TLS support, redirects to HTTPS will fail.

> **Note:** Following redirects adds to the total request time. See [C12. Set timeouts](c12-timeouts) for timeout configuration.
