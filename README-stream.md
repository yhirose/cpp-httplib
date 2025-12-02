# cpp-httplib Streaming API

This document describes the streaming extensions for cpp-httplib, providing an iterator-style API for handling HTTP responses incrementally with **true socket-level streaming**.

> **Important Notes**:
>
> - **No Keep-Alive**: Each `stream::Get()` call uses a dedicated connection that is closed after the response is fully read. For connection reuse, use `Client::Get()`.
> - **Single iteration only**: The `next()` method can only iterate through the body once.
> - **Result is not thread-safe**: While `stream::Get()` can be called from multiple threads simultaneously, the returned `stream::Result` must be used from a single thread only.

## Overview

The streaming API allows you to process HTTP response bodies chunk by chunk using an iterator-style pattern. Data is read directly from the network socket, enabling low-memory processing of large responses. This is particularly useful for:

- **LLM/AI streaming responses** (e.g., ChatGPT, Claude, Ollama)
- **Server-Sent Events (SSE)**
- **Large file downloads** with progress tracking
- **Reverse proxy implementations**

## Quick Start

```cpp
#include "httplib.h"

int main() {
    httplib::Client cli("http://localhost:8080");
    
    // Get streaming response
    auto result = httplib::stream::Get(cli, "/stream");
    
    if (result) {
        // Process response body in chunks
        while (result.next()) {
            std::cout.write(result.data(), result.size());
        }
    }
    
    return 0;
}
```

## API Layers

cpp-httplib provides multiple API layers for different use cases:

```text
┌─────────────────────────────────────────────┐
│  SSEClient (planned)                        │  ← SSE-specific, parsed events
│  - on_message(), on_event()                 │
│  - Auto-reconnect, Last-Event-ID            │
├─────────────────────────────────────────────┤
│  stream::Get() / stream::Result             │  ← Iterator-based streaming
│  - while (result.next()) { ... }            │
├─────────────────────────────────────────────┤
│  open_stream() / StreamHandle               │  ← General-purpose streaming
│  - handle.read(buf, len)                    │
├─────────────────────────────────────────────┤
│  Client::Get()                              │  ← Traditional, full buffering
└─────────────────────────────────────────────┘
```

| Use Case | Recommended API |
|----------|----------------|
| SSE with auto-reconnect | SSEClient (planned) or `ssecli-stream.cc` example |
| LLM streaming (JSON Lines) | `stream::Get()` |
| Large file download | `stream::Get()` or `open_stream()` |
| Reverse proxy | `open_stream()` |
| Small responses with Keep-Alive | `Client::Get()` |

## API Reference

### Low-Level API: `StreamHandle`

The `StreamHandle` struct provides direct control over streaming responses. It takes ownership of the socket connection and reads data directly from the network.

> **Note:** When using `open_stream()`, the connection is dedicated to streaming and **Keep-Alive is not supported**. For Keep-Alive connections, use `client.Get()` instead.

```cpp
// Open a stream (takes ownership of socket)
httplib::Client cli("http://localhost:8080");
auto handle = cli.open_stream("GET", "/path");

// Check validity
if (handle.is_valid()) {
    // Access response headers immediately
    int status = handle.response->status;
    auto content_type = handle.response->get_header_value("Content-Type");
    
    // Read body incrementally
    char buf[4096];
    ssize_t n;
    while ((n = handle.read(buf, sizeof(buf))) > 0) {
        process(buf, n);
    }
}
```

#### StreamHandle Members

| Member | Type | Description |
|--------|------|-------------|
| `response` | `std::unique_ptr<Response>` | HTTP response with headers |
| `error` | `Error` | Error code if request failed |
| `is_valid()` | `bool` | Returns true if response is valid |
| `read(buf, len)` | `ssize_t` | Read up to `len` bytes directly from socket |
| `get_read_error()` | `Error` | Get the last read error |
| `has_read_error()` | `bool` | Check if a read error occurred |

### High-Level API: `stream::Get()` and `stream::Result`

The `httplib.h` header provides a more ergonomic iterator-style API.

```cpp
#include "httplib.h"

httplib::Client cli("http://localhost:8080");
cli.set_follow_location(true);
...

// Simple GET
auto result = httplib::stream::Get(cli, "/path");

// GET with custom headers
httplib::Headers headers = {{"Authorization", "Bearer token"}};
auto result = httplib::stream::Get(cli, "/path", headers);

// Process the response
if (result) {
    while (result.next()) {
        process(result.data(), result.size());
    }
}

// Or read entire body at once
auto result2 = httplib::stream::Get(cli, "/path");
if (result2) {
    std::string body = result2.read_all();
}
```

#### stream::Result Members

| Member | Type | Description |
|--------|------|-------------|
| `operator bool()` | `bool` | Returns true if response is valid |
| `is_valid()` | `bool` | Same as `operator bool()` |
| `status()` | `int` | HTTP status code |
| `headers()` | `const Headers&` | Response headers |
| `get_header_value(key, def)` | `std::string` | Get header value (with optional default) |
| `has_header(key)` | `bool` | Check if header exists |
| `next()` | `bool` | Read next chunk, returns false when done |
| `data()` | `const char*` | Pointer to current chunk data |
| `size()` | `size_t` | Size of current chunk |
| `read_all()` | `std::string` | Read entire remaining body into string |
| `error()` | `Error` | Get the connection/request error |
| `read_error()` | `Error` | Get the last read error |
| `has_read_error()` | `bool` | Check if a read error occurred |

## Usage Examples

### Example 1: SSE (Server-Sent Events) Client

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("http://localhost:1234");
    
    auto result = httplib::stream::Get(cli, "/events");
    if (!result) { return 1; }
    
    while (result.next()) {
        std::cout.write(result.data(), result.size());
        std::cout.flush();
    }
    
    return 0;
}
```

For a complete SSE client with auto-reconnection and event parsing, see `example/ssecli-stream.cc`.

### Example 2: LLM Streaming Response

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("http://localhost:11434");  // Ollama
    
    auto result = httplib::stream::Get(cli, "/api/generate");
    
    if (result && result.status() == 200) {
        while (result.next()) {
            std::cout.write(result.data(), result.size());
            std::cout.flush();
        }
    }
    
    // Check for connection errors
    if (result.read_error() != httplib::Error::Success) {
        std::cerr << "Connection lost\n";
    }
    
    return 0;
}
```

### Example 3: Large File Download with Progress

```cpp
#include "httplib.h"
#include <fstream>
#include <iostream>

int main() {
    httplib::Client cli("http://example.com");
    auto result = httplib::stream::Get(cli, "/large-file.zip");
    
    if (!result || result.status() != 200) {
        std::cerr << "Download failed\n";
        return 1;
    }
    
    std::ofstream file("download.zip", std::ios::binary);
    size_t total = 0;
    
    while (result.next()) {
        file.write(result.data(), result.size());
        total += result.size();
        std::cout << "\rDownloaded: " << (total / 1024) << " KB" << std::flush;
    }
    
    std::cout << "\nComplete!\n";
    return 0;
}
```

### Example 4: Reverse Proxy Streaming

```cpp
#include "httplib.h"

httplib::Server svr;

svr.Get("/proxy/(.*)", [](const httplib::Request& req, httplib::Response& res) {
    httplib::Client upstream("http://backend:8080");
    auto handle = upstream.open_stream("/" + req.matches[1].str());
    
    if (!handle.is_valid()) {
        res.status = 502;
        return;
    }
    
    res.status = handle.response->status;
    res.set_chunked_content_provider(
        handle.response->get_header_value("Content-Type"),
        [handle = std::move(handle)](size_t, httplib::DataSink& sink) mutable {
            char buf[8192];
            auto n = handle.read(buf, sizeof(buf));
            if (n > 0) {
                sink.write(buf, static_cast<size_t>(n));
                return true;
            }
            sink.done();
            return true;
        }
    );
});

svr.listen("0.0.0.0", 3000);
```

## Comparison with Existing APIs

| Feature | `Client::Get()` | `open_stream()` | `stream::Get()` |
|---------|----------------|-----------------|----------------|
| Headers available | After complete | Immediately | Immediately |
| Body reading | All at once | Direct from socket | Iterator-based |
| Memory usage | Full body in RAM | Minimal (controlled) | Minimal (controlled) |
| Keep-Alive support | ✅ Yes | ❌ No | ❌ No |
| Compression | Auto-handled | Auto-handled | Auto-handled |
| Best for | Small responses, Keep-Alive | Low-level streaming | Easy streaming |

## Features

- **True socket-level streaming**: Data is read directly from the network socket
- **Low memory footprint**: Only the current chunk is held in memory
- **Compression support**: Automatic decompression for gzip, brotli, and zstd
- **Chunked transfer**: Full support for chunked transfer encoding
- **SSL/TLS support**: Works with HTTPS connections

## Important Notes

### Keep-Alive Behavior

The streaming API (`stream::Get()` / `open_stream()`) takes ownership of the socket connection for the duration of the stream. This means:

- **Keep-Alive is not supported** for streaming connections
- The socket is closed when `StreamHandle` is destroyed
- For Keep-Alive scenarios, use the standard `client.Get()` API instead

```cpp
// Use for streaming (no Keep-Alive)
auto result = httplib::stream::Get(cli, "/large-stream");
while (result.next()) { /* ... */ }

// Use for Keep-Alive connections
auto res = cli.Get("/api/data");  // Connection can be reused
```

## Related

- [Issue #2269](https://github.com/yhirose/cpp-httplib/issues/2269) - Original feature request
- [example/ssecli-stream.cc](./example/ssecli-stream.cc) - SSE client with auto-reconnection
