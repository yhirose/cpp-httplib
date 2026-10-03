---
title: "S05. 在响应中流式传输大文件"
order: 24
status: "draft"
---

当响应是一个巨大的文件或即时生成的数据时，将整个内容加载到内存中并不现实。请使用 `Response::set_content_provider()` 在发送时按块生成数据。

## 当大小已知时

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

该 lambda 会以 `offset` 和 `length` 为参数被反复调用。只读取该范围的内容并将其写入 `sink`。任意时刻内存中只驻留一小块数据。

## 仅发送一个文件

如果你只是想提供某个文件，`set_file_content()` 要简单得多。

```cpp
svr.Get("/download", [](const httplib::Request &req, httplib::Response &res) {
  res.set_file_content("large.bin", "application/octet-stream");
});
```

它在内部进行流式传输，因此即使是巨大的文件也很安全。省略 Content-Type，它会根据扩展名推测。

## 当大小未知时——分块传输

对于即时生成、无法预先知道总大小的数据，请使用 `set_chunked_content_provider()`。它会以 HTTP 分块传输编码发送。

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/plain",
    [](size_t offset, httplib::DataSink &sink) {
      auto chunk = produce_next_chunk();
      if (chunk.empty()) {
        sink.done(); // 发送完成
        return true;
      }
      sink.write(chunk.data(), chunk.size());
      return true;
    });
});
```

调用 `sink.done()` 来表示结束。

> **注意：** provider lambda 会被多次调用。注意捕获变量的生命周期——如有需要，请用 `std::shared_ptr` 包装它们。

> 要将文件作为下载提供，请参阅 [S06. 返回文件下载响应](../s06-download-response)。
