---
title: "T03. Start an SSL/TLS Server"
order: 44
status: "draft"
---

To stand up an HTTPS server, use `httplib::SSLServer` instead of `httplib::Server`. Pass a certificate and private key to the constructor, and you get back something that works exactly like `Server`.

## Basic usage

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

int main() {
  httplib::SSLServer svr("cert.pem", "key.pem");

  svr.Get("/", [](const auto &req, auto &res) {
    res.set_content("hello over TLS", "text/plain");
  });

  svr.listen("0.0.0.0", 443);
}
```

Pass the server certificate (PEM format) and private key file paths to the constructor. That's all you need for a TLS-enabled server. Registering handlers and calling `listen()` work the same as with `Server`.

## Password-protected private keys

The fifth argument is the private key password.

```cpp
httplib::SSLServer svr("cert.pem", "key.pem",
                       nullptr, nullptr, "password");
```

The third and fourth arguments are for client certificate verification (mTLS, see T04). For now, pass `nullptr`.

## Load PEM data from memory

When you want to load certs from memory instead of files, use the `PemMemory` struct.

```cpp
httplib::SSLServer::PemMemory pem{};
pem.cert_pem = cert_data.data();
pem.cert_pem_len = cert_data.size();
pem.key_pem = key_data.data();
pem.key_pem_len = key_data.size();

httplib::SSLServer svr(pem);
```

Handy when you pull certificates from environment variables or a secrets manager.

## Rotate certificates

Before a certificate expires, you may want to swap it out without restarting the server. That's what `update_certs_pem()` is for.

```cpp
svr.update_certs_pem(new_cert_pem, new_key_pem);
```

Existing connections keep using the old cert; new connections use the new one.

## Generating a test certificate

For a throwaway self-signed cert, use the `openssl` CLI.

```sh
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout key.pem -out cert.pem -subj "/CN=localhost"
```

In production, use certificates from Let's Encrypt or your internal CA.

> **Warning:** Binding an HTTPS server to port 443 requires root. For a safe way to do that, see the privilege-drop pattern in S18. Control Startup Order with `listen_after_bind`.

> For mutual TLS (client certificates), see T04. Configure mTLS.
