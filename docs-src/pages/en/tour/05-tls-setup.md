---
title: "TLS Setup"
order: 5
draft: true
---

So far we've been using plain HTTP, but in the real world, HTTPS is the norm. To use HTTPS with cpp-httplib, you need a TLS library.

In this tour, we'll use OpenSSL. It's the most widely used option, and you'll find plenty of resources online.

## Installing OpenSSL

Install it for your OS.

| OS | How to install |
| -- | -------------- |
| macOS | [Homebrew](https://brew.sh/) (`brew install openssl`) |
| Ubuntu / Debian | `sudo apt install libssl-dev` |
| Windows | [vcpkg](https://vcpkg.io/) (`vcpkg install openssl`) |

## Compile Options

To enable TLS, define the `CPPHTTPLIB_OPENSSL_SUPPORT` macro when compiling. You'll need a few extra options compared to the previous chapters.

```sh
# macOS (Homebrew)
clang++ -std=c++17 -DCPPHTTPLIB_OPENSSL_SUPPORT \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -lssl -lcrypto \
    -framework CoreFoundation -framework Security \
    -o server server.cpp

# Linux
clang++ -std=c++17 -pthread -DCPPHTTPLIB_OPENSSL_SUPPORT \
    -lssl -lcrypto \
    -o server server.cpp

# Windows (Developer Command Prompt)
cl /EHsc /std:c++17 /DCPPHTTPLIB_OPENSSL_SUPPORT server.cpp libssl.lib libcrypto.lib
```

Let's look at what each option does.

- **`-DCPPHTTPLIB_OPENSSL_SUPPORT`** — Defines the macro that enables TLS support
- **`-lssl -lcrypto`** — Links the OpenSSL libraries
- **`-I` / `-L`** (macOS only) — Points to the Homebrew OpenSSL paths
- **`-framework CoreFoundation -framework Security`** (macOS only) — Needed to automatically load system certificates from the Keychain

## Verifying the Setup

Let's make sure everything works. Here's a simple program that passes an HTTPS URL to `httplib::Client`.

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://www.google.com");

    auto res = cli.Get("/");
    if (res) {
        std::cout << "Status: " << res->status << std::endl;
    } else {
        std::cout << "Error: " << httplib::to_string(res.error()) << std::endl;
    }
}
```

Compile and run it. If you see `Status: 200`, your setup is complete.

## Other TLS Backends

cpp-httplib also supports Mbed TLS and wolfSSL in addition to OpenSSL. You can switch between them just by changing the macro definition and linked libraries.

| Backend | Macro | Libraries to link |
| :--- | :--- | :--- |
| OpenSSL | `CPPHTTPLIB_OPENSSL_SUPPORT` | `libssl`, `libcrypto` |
| Mbed TLS | `CPPHTTPLIB_MBEDTLS_SUPPORT` | `libmbedtls`, `libmbedx509`, `libmbedcrypto` |
| wolfSSL | `CPPHTTPLIB_WOLFSSL_SUPPORT` | `libwolfssl` |

This tour assumes OpenSSL, but the API is the same regardless of which backend you choose.

## Next Step

You're all set with TLS. Next, let's send a request to an HTTPS site.

**Next:** [HTTPS Client](../06-https-client)
