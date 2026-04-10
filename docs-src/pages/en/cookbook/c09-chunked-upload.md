---
title: "C09. Send the Body with Chunked Transfer"
order: 9
status: "draft"
---

When you don't know the body size up front — for data generated on the fly or piped from another stream — use `ContentProviderWithoutLength`. The client sends the body with HTTP chunked transfer encoding.

## Basic usage

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Post("/stream",
  [&](size_t offset, httplib::DataSink &sink) {
    std::string chunk = produce_next_chunk();
    if (chunk.empty()) {
      sink.done(); // done sending
      return true;
    }
    return sink.write(chunk.data(), chunk.size());
  },
  "application/octet-stream");
```

The lambda's job is just: produce the next chunk and send it with `sink.write()`. When there's no more data, call `sink.done()` and you're finished.

## When the size is known

If you **do** know the total size ahead of time, use the `ContentProvider` overload (taking `size_t offset, size_t length, DataSink &sink`) and pass the total size as well.

```cpp
size_t total_size = get_total_size();

auto res = cli.Post("/upload", total_size,
  [&](size_t offset, size_t length, httplib::DataSink &sink) {
    auto data = read_range(offset, length);
    return sink.write(data.data(), data.size());
  },
  "application/octet-stream");
```

With a known size, the request carries a Content-Length header — so the server can show progress. Prefer this form when you can.

> **Detail:** `sink.write()` returns a `bool` indicating whether the write succeeded. If it returns `false`, the connection is gone — return `false` from the lambda to stop.

> If you're just sending a file, `make_file_body()` is easier. See C08. POST a File as Raw Binary.
