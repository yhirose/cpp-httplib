---
title: "T02. Control SSL Certificate Verification"
order: 43
status: "draft"
---

By default, an HTTPS client verifies the server certificate — it uses the OS root certificate store to check the chain and the hostname. Here are the APIs for changing that behavior.

## Specify a custom CA certificate

When connecting to a server whose certificate is signed by an internal CA, use `set_ca_cert_path()`.

```cpp
httplib::Client cli("https://internal.example.com");
cli.set_ca_cert_path("/etc/ssl/certs/internal-ca.pem");

auto res = cli.Get("/");
```

The first argument is the CA certificate file; the second is an optional CA directory. With the OpenSSL backend, you can also pass an `X509_STORE*` directly via `set_ca_cert_store()`.

## Disable certificate verification (not recommended)

For development servers or self-signed certificates, you can skip verification entirely.

```cpp
httplib::Client cli("https://self-signed.example.com");
cli.enable_server_certificate_verification(false);

auto res = cli.Get("/");
```

That's all it takes to disable chain verification.

> **Warning:** Disabling certificate verification removes protection against man-in-the-middle attacks. **Never do this in production.** If you find yourself needing it outside of dev/test, pause and make sure you're not doing something wrong.

## Disable hostname verification only

There's an in-between option: verify the certificate chain, but skip the hostname check. Useful when you need to reach a server whose cert CN/SAN doesn't match the request's hostname.

```cpp
cli.enable_server_hostname_verification(false);
```

The certificate itself is still validated, so this is safer than fully disabling verification — but still not recommended in production.

## Use the OS cert store as-is

On most Linux distributions, root certificates live in a single file like `/etc/ssl/certs/ca-certificates.crt`. cpp-httplib reads the OS default store at startup, so for most servers you don't need to configure anything.

> The same APIs work on the mbedTLS and wolfSSL backends. For choosing between backends, see T01. Choosing Between OpenSSL, mbedTLS, and wolfSSL.

> For details on diagnosing failures, see C18. Handle SSL Errors.
