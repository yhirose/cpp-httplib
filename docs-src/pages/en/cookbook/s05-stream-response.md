---
title: "S05. Stream a Large File in the Response"
order: 24
status: "draft"
---

When the response is a huge file or data generated on the fly, loading the whole thing into memory isn't realistic. Use `Response::set_content_provider()` to produce data in chunks as you send it.

## When the size is known

```cpp
svr.Get("/download", [](const httplib::Request &req, httplib::Response &res) {
  size_t total_size = get_file_size("large.bin");

  res.set_content_provider(
    total_size, "application/octet-stream",
    [](size_t offset, size_t length, httplib::DataSink &sink) {
      auto data = read_range_from_file("large.bin", offset, length);
      sink.write(data.data(), data.size());
      return true;
    });
});
```

The lambda is called repeatedly with `offset` and `length`. Read just that range and write it to `sink`. Only a small chunk sits in memory at any given time.

## Just send a file

If you only want to serve a file, `set_file_content()` is far simpler.

```cpp
svr.Get("/download", [](const httplib::Request &req, httplib::Response &res) {
  res.set_file_content("large.bin", "application/octet-stream");
});
```

It streams internally, so even huge files are safe. Omit the Content-Type and it's guessed from the extension.

## When the size is unknown — chunked transfer

For data generated on the fly, where you don't know the total size up front, use `set_chunked_content_provider()`. It's sent with HTTP chunked transfer encoding.

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/plain",
    [](size_t offset, httplib::DataSink &sink) {
      auto chunk = produce_next_chunk();
      if (chunk.empty()) {
        sink.done(); // done sending
        return true;
      }
      sink.write(chunk.data(), chunk.size());
      return true;
    });
});
```

Call `sink.done()` to signal the end.

> **Note:** The provider lambda is called multiple times. Watch out for the lifetime of captured variables — wrap them in a `std::shared_ptr` if needed.

> To serve the file as a download, see [S06. Return a file download response](s06-download-response).
