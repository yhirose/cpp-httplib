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

`ssl_error()` is a backend-independent TLS error category: an `httplib::tls::ErrorCode` cast to `int`. `ssl_backend_error()` gives you the backend's own error value. With OpenSSL that is `ERR_get_error()` when the handshake failed, and the verify result (`X509_V_ERR_*`) when certificate verification failed.

## Format OpenSSL errors as strings

When you have a value from `ssl_backend_error()`, pass it to the OpenSSL function that matches the kind of failure to get a readable message.

```cpp
#include <openssl/err.h>
#include <openssl/x509.h>

if (res.error() == httplib::Error::SSLConnection) {
  char buf[256];
  ERR_error_string_n(res.ssl_backend_error(), buf, sizeof(buf));
  std::cerr << "openssl: " << buf << std::endl;
} else if (res.error() == httplib::Error::SSLServerVerification ||
           res.error() == httplib::Error::SSLServerHostnameVerification) {
  auto code = static_cast<long>(res.ssl_backend_error());
  std::cerr << "openssl: " << X509_verify_cert_error_string(code) << std::endl;
}
```

## Common causes

| Symptom | Usual suspect |
| --- | --- |
| `SSLServerVerification` | CA certificate path isn't configured, or the cert is self-signed |
| `SSLServerHostnameVerification` | The cert's CN/SAN doesn't match the host |
| `SSLConnection` | TLS version mismatch, no shared cipher suite |

> To change certificate verification settings, see [T02. Control SSL certificate verification](../t02-cert-verification).
