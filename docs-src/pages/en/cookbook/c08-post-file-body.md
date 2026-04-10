---
title: "C08. POST a File as Raw Binary"
order: 8
status: "draft"
---

Sometimes you want to send a file's contents as the request body directly — no multipart wrapping. This is common for S3-compatible APIs or endpoints that take raw image data. For this, use `make_file_body()`.

## Basic usage

```cpp
httplib::Client cli("https://storage.example.com");

auto [size, provider] = httplib::make_file_body("backup.tar.gz");
if (size == 0) {
  std::cerr << "Failed to open file" << std::endl;
  return 1;
}

auto res = cli.Put("/bucket/backup.tar.gz", size,
                   provider, "application/gzip");
```

`make_file_body()` returns a pair of file size and a `ContentProvider`. Pass them to `Post()` or `Put()` and the file contents flow straight into the request body.

The `ContentProvider` reads the file in chunks, so even huge files never sit fully in memory.

## When the file can't be opened

If the file can't be opened, `make_file_body()` returns `size` as `0` and `provider` as an empty function object. Sending that would produce garbage — always check `size` first.

> **Warning:** `make_file_body()` needs to fix the Content-Length up front, so it reads the file size ahead of time. If the file size might change mid-upload, this API isn't the right fit.

> To send the file as multipart form data instead, see C07. Upload a File as Multipart Form Data.
