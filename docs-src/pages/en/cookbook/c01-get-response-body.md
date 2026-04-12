---
title: "C01. Get the Response Body / Save to a File"
order: 1
status: "draft"
---

## Get it as a string

```cpp
httplib::Client cli("http://localhost:8080");
auto res = cli.Get("/hello");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

`res->body` is a `std::string`, ready to use as-is. The entire response is loaded into memory.

> **Warning:** If you fetch a large file with `res->body`, it all goes into memory. For large downloads, use a `ContentReceiver` as shown below.

## Save to a file

```cpp
httplib::Client cli("http://localhost:8080");

std::ofstream ofs("output.bin", std::ios::binary);
if (!ofs) {
  std::cerr << "Failed to open file" << std::endl;
  return 1;
}

auto res = cli.Get("/large-file",
  [&](const char *data, size_t len) {
    ofs.write(data, len);
    return static_cast<bool>(ofs);
  });
```

With a `ContentReceiver`, data arrives in chunks. You can write each chunk straight to disk without buffering the whole body in memory — perfect for large file downloads.

Return `false` from the callback to abort the download. In the example above, if writing to `ofs` fails, the download stops automatically.

> **Detail:** Want to check response headers like Content-Length before downloading? Combine a `ResponseHandler` with a `ContentReceiver`.
>
> ```cpp
> auto res = cli.Get("/large-file",
>   [](const httplib::Response &res) {
>     auto len = res.get_header_value("Content-Length");
>     std::cout << "Size: " << len << std::endl;
>     return true; // return false to skip the download
>   },
>   [&](const char *data, size_t len) {
>     ofs.write(data, len);
>     return static_cast<bool>(ofs);
>   });
> ```
>
> The `ResponseHandler` is called after headers arrive but before the body. Return `false` to skip the download entirely.

> To show download progress, see [C11. Use the progress callback](c11-progress-callback).
