---
title: "cpp-httplib"
order: 0
---

[cpp-httplib](https://github.com/yhirose/cpp-httplib) is an HTTP/HTTPS library for C++. Just copy a single header file, [`httplib.h`](https://github.com/yhirose/cpp-httplib/raw/refs/tags/latest/httplib.h), and you're ready to go.

When you need a quick HTTP server or client in C++, you want something that just works. That's exactly why I built cpp-httplib. You can start writing both servers and clients in just a few lines of code.

The API uses a lambda-based design that feels natural. It runs anywhere you have a C++11 or later compiler. Windows, macOS, Linux — use whatever environment you already have.

HTTPS works too. Just link OpenSSL or mbedTLS, and both server and client gain TLS support. Content-Encoding (gzip, Brotli, etc.), file uploads, and other features you actually need in real-world development are all included. WebSocket is also supported.

Under the hood, it uses blocking I/O with a thread pool. It's not built for handling massive numbers of simultaneous connections. But for API servers, embedded HTTP in tools, mock servers for testing, and many other use cases, it delivers solid performance.

"Solve today's problem, today." That's the kind of simplicity cpp-httplib aims for.

## Documentation

- [A Tour of cpp-httplib](tour/index) — A step-by-step tutorial covering the basics. Start here if you're new
- [Cookbook](cookbook/index) — A collection of recipes organized by topic. Jump to whatever you need
