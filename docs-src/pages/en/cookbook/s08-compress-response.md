---
title: "S08. Return a Compressed Response"
order: 27
status: "draft"
---

cpp-httplib automatically compresses response bodies when the client indicates support via `Accept-Encoding`. The handler doesn't need to do anything special. Supported encodings are gzip, Brotli, and Zstd.

## Build-time setup

To enable compression, define the relevant macros before including `httplib.h`:

```cpp
#define CPPHTTPLIB_ZLIB_SUPPORT     // gzip
#define CPPHTTPLIB_BROTLI_SUPPORT   // brotli
#define CPPHTTPLIB_ZSTD_SUPPORT     // zstd
#include <httplib.h>
```

You'll also need to link `zlib`, `brotli`, and `zstd` respectively. Enable only what you need.

## Usage

```cpp
svr.Get("/api/data", [](const httplib::Request &req, httplib::Response &res) {
  std::string body = build_large_response();
  res.set_content(body, "application/json");
});
```

That's it. If the client sent `Accept-Encoding: gzip`, cpp-httplib compresses the response with gzip automatically. `Content-Encoding: gzip` and `Vary: Accept-Encoding` are added for you.

## Encoding priority

When the client accepts multiple encodings, cpp-httplib picks in this order (among those enabled at build time): Brotli → Zstd → gzip. Your code doesn't need to care — you always get the most efficient option available.

## Streaming responses are compressed too

Streaming responses via `set_chunked_content_provider()` get the same automatic compression.

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/plain",
    [](size_t offset, httplib::DataSink &sink) {
      // ...
    });
});
```

> **Note:** Tiny responses barely benefit from compression and just waste CPU time. cpp-httplib skips compression for bodies that are too small to bother with.

> For the client-side counterpart, see C15. Enable Compression.
