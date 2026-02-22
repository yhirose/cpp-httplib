---
title: "HTTPS Server"
draft: true
order: 7
---

In the previous chapter, you used an HTTPS client. Now let's set up your own HTTPS server. Just swap `httplib::Server` from Chapter 3 with `httplib::SSLServer`.

A TLS server needs a server certificate and a private key, though. Let's get those ready first.

## Creating a Self-Signed Certificate

For development and testing, a self-signed certificate works just fine. You can generate one quickly with an OpenSSL command.

```sh
openssl req -x509 -noenc -keyout key.pem -out cert.pem -subj /CN=localhost
```

This creates two files:

- **`cert.pem`** — Server certificate
- **`key.pem`** — Private key

## A Minimal HTTPS Server

Once you have your certificate, let's write the server.

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::SSLServer svr("cert.pem", "key.pem");

    svr.Get("/", [](const auto &, auto &res) {
        res.set_content("Hello, HTTPS!", "text/plain");
    });

    std::cout << "Listening on https://localhost:8443" << std::endl;
    svr.listen("0.0.0.0", 8443);
}
```

Just pass the certificate and private key paths to the `httplib::SSLServer` constructor. The routing API is exactly the same as `httplib::Server` from Chapter 3.

Compile and start it up.

## Testing It Out

With the server running, try accessing it with `curl`. Since we're using a self-signed certificate, add the `-k` option to skip certificate verification.

```sh
curl -k https://localhost:8443/
# Hello, HTTPS!
```

If you open `https://localhost:8443` in a browser, you'll see a "This connection is not secure" warning. That's expected with a self-signed certificate. Just proceed past it.

## Connecting from a Client

Let's connect using `httplib::Client` from the previous chapter. There are two ways to connect to a server with a self-signed certificate.

### Option 1: Disable Certificate Verification

This is the quick and easy approach for development.

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://localhost:8443");
    cli.enable_server_certificate_verification(false);

    auto res = cli.Get("/");
    if (res) {
        std::cout << res->body << std::endl;  // Hello, HTTPS!
    }
}
```

### Option 2: Specify the Self-Signed Certificate as a CA Certificate

This is the safer approach. You tell the client to trust `cert.pem` as a CA certificate.

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://localhost:8443");
    cli.set_ca_cert_path("cert.pem");

    auto res = cli.Get("/");
    if (res) {
        std::cout << res->body << std::endl;  // Hello, HTTPS!
    }
}
```

This way, only connections to the server with that specific certificate are allowed, preventing impersonation. Use this approach whenever possible, even in test environments.

## Comparing Server and SSLServer

The `httplib::Server` API you learned in Chapter 3 works exactly the same with `httplib::SSLServer`. The only difference is the constructor.

| | `httplib::Server` | `httplib::SSLServer` |
| -- | ------------------ | -------------------- |
| Constructor | No arguments | Certificate and private key paths |
| Protocol | HTTP | HTTPS |
| Port (convention) | 8080 | 8443 |
| Routing | Same | Same |

To switch an HTTP server to HTTPS, just change the constructor.

## Next Steps

Your HTTPS server is up and running. You now have the basics of both HTTP/HTTPS clients and servers covered.

Next, let's look at the WebSocket support that was recently added to cpp-httplib.

**Next:** [WebSocket](../08-websocket)
