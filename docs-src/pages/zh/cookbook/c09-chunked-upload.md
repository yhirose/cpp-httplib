---
title: "C09. 使用 chunked 传输发送请求体"
order: 9
status: "draft"
---

当你无法预先知道请求体大小时——例如数据是即时生成的，或来自其他流的管道——请使用 `ContentProviderWithoutLength`。客户端会使用 HTTP chunked 传输编码发送请求体。

## 基本用法

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Post("/stream",
  [&](size_t offset, httplib::DataSink &sink) {
    std::string chunk = produce_next_chunk();
    if (chunk.empty()) {
      sink.done(); // 发送完成
      return true;
    }
    return sink.write(chunk.data(), chunk.size());
  },
  "application/octet-stream");
```

这个 lambda 的职责很简单：生成下一个数据块并用 `sink.write()` 发送。当没有更多数据时，调用 `sink.done()` 就完成了。

## 当大小已知时

如果你**确实**预先知道总大小，请使用 `ContentProvider` 重载（参数为 `size_t offset, size_t length, DataSink &sink`），并同时传入总大小。

```cpp
size_t total_size = get_total_size();

auto res = cli.Post("/upload", total_size,
  [&](size_t offset, size_t length, httplib::DataSink &sink) {
    auto data = read_range(offset, length);
    return sink.write(data.data(), data.size());
  },
  "application/octet-stream");
```

在大小已知的情况下，请求会带上 Content-Length 请求头——因此服务器可以显示进度。在可行时优先使用这种形式。

> **详情：** `sink.write()` 返回一个 `bool`，表示写入是否成功。如果返回 `false`，说明连接已断开——从 lambda 中返回 `false` 即可停止。

> 如果你只是要发送一个文件，`make_file_body()` 更简单。请参见 [C08. 以原始二进制形式 POST 文件](../c08-post-file-body)。
