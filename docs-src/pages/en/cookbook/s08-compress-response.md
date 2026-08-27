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

## Static files need to be opted in

Files served as they are, through `set_mount_point()` or `Response::set_file_content()`, are not compressed by default. Turn it on with:

```cpp
svr.set_static_file_compression(true);
```

Only files within a size range are compressed, and both ends of it can be moved:

```cpp
svr.set_static_file_compression_min_length(512);
svr.set_static_file_compression_max_length(1024 * 1024);
```

The lower bound defaults to 1400 bytes. A response that already fits in a single 1500-byte MTU is not delivered any faster for being smaller, and a file of a few bytes comes back larger than it went in, because gzip's header and trailer outweigh what deflate saves.

The upper bound defaults to 4MB and exists for a different reason: the file is compressed on every request, and the compressed bytes stay in memory until the response has been written, so the peak cost scales with the number of requests in flight. It bounds what a single request can cost, and says nothing about how well large files compress, so raising it is reasonable when the files are known and the traffic is not.

Either bound takes `0` to turn it off, and each has a compile-time default (`CPPHTTPLIB_STATIC_FILE_COMPRESSION_MIN_LENGTH`, `CPPHTTPLIB_STATIC_FILE_COMPRESSION_MAX_LENGTH`).

A compressed response keeps its `Content-Length`, so `HEAD` reports the same size a `GET` would. Two details to know: Range requests are answered from the uncompressed representation, and the `ETag` carries the coding it belongs to, as in `W/"...-gzip"`.

Content providers registered with `set_content_provider()` are not covered. Running one through a compressor holds each write back until the internal buffer fills, which stalls providers that build their body a piece at a time. To compress a generated body, use `set_chunked_content_provider()`.

> **Note:** The size range covers static files only. A body passed to `set_content()` is compressed whenever the client accepts it and the MIME type is compressible, however small it is, so a response of a few bytes ends up larger than it started. Decide in the handler if you want to avoid that.

> For the client-side counterpart, see [C15. Enable compression](../c15-compression).
