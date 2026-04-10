---
title: "C15. Enable Compression"
order: 15
status: "draft"
---

cpp-httplib supports compression when sending and decompression when receiving. You just need to build it with zlib or Brotli enabled.

## Build-time setup

To use compression, define these macros before including `httplib.h`:

```cpp
#define CPPHTTPLIB_ZLIB_SUPPORT    // gzip / deflate
#define CPPHTTPLIB_BROTLI_SUPPORT  // brotli
#include <httplib.h>
```

You'll also need to link against `zlib` or `brotli`.

## Compress the request body

```cpp
httplib::Client cli("https://api.example.com");
cli.set_compress(true);

std::string big_payload = build_payload();
auto res = cli.Post("/api/data", big_payload, "application/json");
```

With `set_compress(true)`, the body of POST or PUT requests gets gzipped before sending. The server needs to handle compressed bodies too.

## Decompress the response

```cpp
httplib::Client cli("https://api.example.com");
cli.set_decompress(true); // on by default

auto res = cli.Get("/api/data");
std::cout << res->body << std::endl;
```

With `set_decompress(true)`, the client automatically decompresses responses that arrive with `Content-Encoding: gzip` or similar. `res->body` contains the decompressed data.

It's on by default, so normally you don't need to do anything. Set it to `false` only if you want the raw compressed bytes.

> **Warning:** If you build without `CPPHTTPLIB_ZLIB_SUPPORT`, calling `set_compress()` or `set_decompress()` does nothing. If compression isn't working, check the macro definition first.
