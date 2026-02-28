---
title: "HTTPS Client"
order: 6
---

In the previous chapter, you set up OpenSSL. Now let's put it to use with an HTTPS client. You can use the same `httplib::Client` from Chapter 2. Just pass a URL with the `https://` scheme to the constructor.

## GET Request

Let's try accessing a real HTTPS site.

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://nghttp2.org");

    auto res = cli.Get("/");
    if (res) {
        std::cout << res->status << std::endl;           // 200
        std::cout << res->body.substr(0, 100) << std::endl;  // First 100 chars of the HTML
    } else {
        std::cout << "Error: " << httplib::to_string(res.error()) << std::endl;
    }
}
```

In Chapter 2, you wrote `httplib::Client cli("http://localhost:8080")`. All you need to change is the scheme to `https://`. Every API you learned in Chapter 2 -- `Get()`, `Post()`, and so on -- works exactly the same way.

```sh
curl https://nghttp2.org/
```

## Specifying a Port

The default port for HTTPS is 443. If you need a different port, include it in the URL.

```cpp
httplib::Client cli("https://localhost:8443");
```

## CA Certificate Verification

When connecting over HTTPS, `httplib::Client` verifies the server certificate by default. It only connects to servers whose certificate was issued by a trusted CA (Certificate Authority).

CA certificates are loaded automatically from the Keychain on macOS, the system CA certificate store on Linux, and the Windows certificate store on Windows. In most cases, no extra configuration is needed.

### Specifying a CA Certificate File

On some environments, the system CA certificates may not be found. In that case, use `set_ca_cert_path()` to specify the path directly.

```cpp
httplib::Client cli("https://nghttp2.org");
cli.set_ca_cert_path("/etc/ssl/certs/ca-certificates.crt");

auto res = cli.Get("/");
```

```sh
curl --cacert /etc/ssl/certs/ca-certificates.crt https://nghttp2.org/
```

### Disabling Certificate Verification

During development, you might want to connect to a server with a self-signed certificate. You can disable verification for that.

```cpp
httplib::Client cli("https://localhost:8443");
cli.enable_server_certificate_verification(false);

auto res = cli.Get("/");
```

```sh
curl -k https://localhost:8443/
```

Never disable this in production. It opens you up to man-in-the-middle attacks.

## Following Redirects

When accessing HTTPS sites, you'll often encounter redirects. For example, `http://` to `https://`, or a bare domain to `www`.

By default, redirects are not followed. You can check the redirect target in the `Location` header.

```cpp
httplib::Client cli("https://nghttp2.org");

auto res = cli.Get("/httpbin/redirect/3");
if (res) {
    std::cout << res->status << std::endl;  // 302
    std::cout << res->get_header_value("Location") << std::endl;
}
```

```sh
curl https://nghttp2.org/httpbin/redirect/3
```

Call `set_follow_location(true)` to automatically follow redirects and get the final response.

```cpp
httplib::Client cli("https://nghttp2.org");
cli.set_follow_location(true);

auto res = cli.Get("/httpbin/redirect/3");
if (res) {
    std::cout << res->status << std::endl;  // 200 (the final response)
}
```

```sh
curl -L https://nghttp2.org/httpbin/redirect/3
```

## Next Steps

Now you know how to use the HTTPS client. Next, let's set up your own HTTPS server. We'll start with creating a self-signed certificate.

**Next:** [HTTPS Server](../07-https-server)
