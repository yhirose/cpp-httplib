---
title: "C11. Use the Progress Callback"
order: 11
status: "draft"
---

To display download or upload progress, pass a `DownloadProgress` or `UploadProgress` callback. Both take two arguments: `(current, total)`.

## Download progress

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Get("/large-file",
  [](size_t current, size_t total) {
    auto percent = (total > 0) ? (current * 100 / total) : 0;
    std::cout << "\rDownloading: " << percent << "% ("
              << current << "/" << total << ")" << std::flush;
    return true; // return false to abort
  });
std::cout << std::endl;
```

The callback fires each time data arrives. `total` comes from the Content-Length header — if the server doesn't send one, it may be `0`. In that case, you can't compute a percentage, so just display bytes received.

## Upload progress

Uploads work the same way. Pass an `UploadProgress` as the last argument to `Post()` or `Put()`.

```cpp
httplib::Client cli("http://localhost:8080");

std::string body = load_large_body();

auto res = cli.Post("/upload", body, "application/octet-stream",
  [](size_t current, size_t total) {
    auto percent = current * 100 / total;
    std::cout << "\rUploading: " << percent << "%" << std::flush;
    return true;
  });
std::cout << std::endl;
```

## Cancel mid-transfer

Return `false` from the callback to abort the transfer. This is how you wire up a "Cancel" button in a UI — flip a flag, and the next progress tick stops the transfer.

```cpp
std::atomic<bool> cancelled{false};

auto res = cli.Get("/large-file",
  [&](size_t current, size_t total) {
    return !cancelled.load();
  });
```

> **Note:** `ContentReceiver` and the progress callback can be used together. When you want to stream to a file and show progress at the same time, pass both.

> For a concrete example of saving to a file, see [C01. Get the response body / save to a file](c01-get-response-body).
