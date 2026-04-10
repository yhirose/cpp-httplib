---
title: "T01. Choosing Between OpenSSL, mbedTLS, and wolfSSL"
order: 42
status: "draft"
---

cpp-httplib doesn't ship its own TLS implementation — it uses one of three backends that you pick at build time via a macro.

| Backend | Macro | Character |
| --- | --- | --- |
| OpenSSL | `CPPHTTPLIB_OPENSSL_SUPPORT` | Most widely used, richest feature set |
| mbedTLS | `CPPHTTPLIB_MBEDTLS_SUPPORT` | Lightweight, aimed at embedded |
| wolfSSL | `CPPHTTPLIB_WOLFSSL_SUPPORT` | Embedded-friendly, commercial support available |

## Build-time selection

Define the macro for your chosen backend before including `httplib.h`:

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
```

You'll also need to link against the backend's libraries (`libssl`, `libcrypto`, `libmbedtls`, `libwolfssl`, etc.).

## Which to pick

**When in doubt, OpenSSL**  
It has the most features and the best documentation. For normal server use or Linux desktop apps, start here — you probably won't need anything else.

**To shrink binary size or target embedded**  
mbedTLS or wolfSSL are a better fit. They're far more compact than OpenSSL and run on memory-constrained devices.

**When you need commercial support**  
wolfSSL offers commercial licensing and support. If you're shipping in a product, it's worth considering.

## Supporting multiple backends

The usual approach is to treat each backend as a build variant and recompile the same source with different macros. cpp-httplib smooths over most of the API differences, but the backends are not 100% identical — always test.

## APIs that work across all backends

Certificate verification control, standing up an SSLServer, reading the peer certificate — these all share the same API across backends:

- T02. Control SSL Certificate Verification
- T03. Start an SSL/TLS Server
- T05. Access the Peer Certificate on the Server Side

> **Note:** On macOS with an OpenSSL-family backend, cpp-httplib automatically loads root certificates from the system keychain (via `CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN`, on by default). To disable this, define `CPPHTTPLIB_DISABLE_MACOSX_AUTOMATIC_ROOT_CERTIFICATES`.
