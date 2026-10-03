---
title: "C01. 获取响应体 / 保存到文件"
order: 1
status: "draft"
---

## 以字符串形式获取

```cpp
httplib::Client cli("http://localhost:8080");
auto res = cli.Get("/hello");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

`res->body` 是一个 `std::string`，可以直接使用。整个响应都会被加载到内存中。

> **警告：** 如果用 `res->body` 获取大文件，它会全部进入内存。对于大文件下载，请使用下面展示的 `ContentReceiver`。

## 保存到文件

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

使用 `ContentReceiver` 时，数据会以数据块的形式到达。你可以把每个数据块直接写入磁盘，而无需在内存中缓冲整个请求体——非常适合大文件下载。

从回调中返回 `false` 可以中止下载。在上面的示例中，如果写入 `ofs` 失败，下载会自动停止。

> **详情：** 想在下载前检查 Content-Length 之类的响应头吗？可以把 `ResponseHandler` 与 `ContentReceiver` 组合起来使用。
>
> ```cpp
> auto res = cli.Get("/large-file",
>   [](const httplib::Response &res) {
>     auto len = res.get_header_value("Content-Length");
>     std::cout << "Size: " << len << std::endl;
>     return true; // 返回 false 可跳过下载
>   },
>   [&](const char *data, size_t len) {
>     ofs.write(data, len);
>     return static_cast<bool>(ofs);
>   });
> ```
>
> `ResponseHandler` 会在响应头到达之后、响应体之前被调用。返回 `false` 可完全跳过下载。

> 要显示下载进度，请参见 [C11. 使用进度回调](../c11-progress-callback)。
