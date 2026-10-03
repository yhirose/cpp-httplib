---
title: "C08. 以原始二进制形式 POST 文件"
order: 8
status: "draft"
---

有时你希望直接把文件内容作为请求体发送——不进行 multipart 包装。这在兼容 S3 的 API 或接收原始图像数据的端点中很常见。为此，请使用 `make_file_body()`。

## 基本用法

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

`make_file_body()` 返回一个由文件大小和 `ContentProvider` 组成的 pair。把它们传给 `Post()` 或 `Put()`，文件内容就会直接流入请求体。

`ContentProvider` 会按数据块读取文件，因此即使是超大文件也绝不会完整地驻留在内存中。

## 当文件无法打开时

如果文件无法打开，`make_file_body()` 会将 `size` 返回为 `0`，并将 `provider` 返回为空函数对象。直接发送它会产生垃圾数据——请始终先检查 `size`。

> **警告：** `make_file_body()` 需要预先确定 Content-Length，因此它会提前读取文件大小。如果文件大小可能在上传过程中发生变化，那么这个 API 并不合适。

> 如果想改为以 multipart 表单数据发送文件，请参见 [C07. 以 multipart 表单数据上传文件](../c07-multipart-upload)。
