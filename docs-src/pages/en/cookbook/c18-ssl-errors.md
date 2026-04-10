---
title: "C18. Handle SSL Errors"
order: 18
status: "draft"
---

When an HTTPS request fails, `res.error()` returns values like `Error::SSLConnection` or `Error::SSLServerVerification`. Sometimes that's not enough to pinpoint the cause. That's where `Result::ssl_error()` and `Result::ssl_backend_error()` help.

## Get the SSL error details

```cpp
httplib::Client cli("https://api.example.com");
auto res = cli.Get("/");

if (!res) {
  auto err = res.error();
  std::cerr << "error: " << httplib::to_string(err) << std::endl;

  if (err == httplib::Error::SSLConnection ||
      err == httplib::Error::SSLServerVerification) {
    std::cerr << "ssl_error: " << res.ssl_error() << std::endl;
    std::cerr << "ssl_backend_error: " << res.ssl_backend_error() << std::endl;
  }
}
```

`ssl_error()` returns the error code from the SSL library (e.g., OpenSSL's `SSL_get_error()`). `ssl_backend_error()` gives you the backend's more detailed error value — for OpenSSL, that's `ERR_get_error()`.

## Format OpenSSL errors as strings

When you have a value from `ssl_backend_error()`, pass it to OpenSSL's `ERR_error_string()` to get a readable message.

```cpp
#include <openssl/err.h>

if (res.ssl_backend_error() != 0) {
  char buf[256];
  ERR_error_string_n(res.ssl_backend_error(), buf, sizeof(buf));
  std::cerr << "openssl: " << buf << std::endl;
}
```

## Common causes

| Symptom | Usual suspect |
| --- | --- |
| `SSLServerVerification` | CA certificate path isn't configured, or the cert is self-signed |
| `SSLServerHostnameVerification` | The cert's CN/SAN doesn't match the host |
| `SSLConnection` | TLS version mismatch, no shared cipher suite |

> **Note:** `ssl_backend_error()` was previously called `ssl_openssl_error()`. The old name is deprecated — use `ssl_backend_error()` now.

> To change certificate verification settings, see T02. Control SSL Certificate Verification.
