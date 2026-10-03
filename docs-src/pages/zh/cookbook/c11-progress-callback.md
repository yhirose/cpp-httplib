---
title: "C11. 使用进度回调"
order: 11
status: "draft"
---

要显示下载或上传进度，请传入 `DownloadProgress` 或 `UploadProgress` 回调。两者都接受两个参数：`(current, total)`。

## 下载进度

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Get("/large-file",
  [](size_t current, size_t total) {
    auto percent = (total > 0) ? (current * 100 / total) : 0;
    std::cout << "\rDownloading: " << percent << "% ("
              << current << "/" << total << ")" << std::flush;
    return true; // 返回 false 可中止
  });
std::cout << std::endl;
```

每次数据到达时都会触发该回调。`total` 来自 Content-Length 响应头——如果服务器没有发送该头，它可能是 `0`。在这种情况下，你无法计算百分比，因此只显示已接收的字节数即可。

## 上传进度

上传的工作方式相同。把 `UploadProgress` 作为最后一个参数传给 `Post()` 或 `Put()`。

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

## 在传输中途取消

从回调中返回 `false` 可以中止传输。UI 中的"取消"按钮就是这样接线的——翻转一个标志，下一次进度回调就会停止传输。

```cpp
std::atomic<bool> cancelled{false};

auto res = cli.Get("/large-file",
  [&](size_t current, size_t total) {
    return !cancelled.load();
  });
```

> **注意：** `ContentReceiver` 和进度回调可以一起使用。当你既想流式写入文件又想显示进度时，把两者都传入即可。

> 关于保存到文件的具体示例，请参见 [C01. 获取响应体 / 保存到文件](../c01-get-response-body)。
