---
title: "C07. 以 multipart 表单数据上传文件"
order: 7
status: "draft"
---

如果想以与 HTML `<input type="file">` 相同的方式发送文件，请使用 multipart 表单数据（`multipart/form-data`）。cpp-httplib 提供两个 API——`UploadFormDataItems` 和 `FormDataProviderItems`——你可以根据**文件大小**在两者之间做选择。

## 发送小文件

先把文件读入内存，然后发送。对于小文件，这是最简单的做法。

```cpp
httplib::Client cli("http://localhost:8080");

std::ifstream ifs("avatar.png", std::ios::binary);
std::string content((std::istreambuf_iterator<char>(ifs)),
                     std::istreambuf_iterator<char>());

httplib::UploadFormDataItems items = {
  {"name", "Alice", "", ""},
  {"avatar", content, "avatar.png", "image/png"},
};

auto res = cli.Post("/upload", items);
```

每个 `UploadFormData` 条目都是 `{name, content, filename, content_type}`。对于纯文本字段，请把 `filename` 和 `content_type` 留空。

## 流式发送大文件

为了避免把整个文件加载到内存中，请使用 `make_file_provider()`。它会在发送时按数据块读取文件——因此即使是超大文件也不会撑爆内存占用。

```cpp
httplib::Client cli("http://localhost:8080");

httplib::UploadFormDataItems items = {
  {"name", "Alice", "", ""},
};

httplib::FormDataProviderItems provider_items = {
  httplib::make_file_provider("video", "large-video.mp4", "", "video/mp4"),
};

auto res = cli.Post("/upload", httplib::Headers{}, items, provider_items);
```

`make_file_provider()` 的参数是 `(表单名, 文件路径, 文件名, 内容类型)`。把文件名留空即可直接使用文件路径。

> **注意：** 你可以在同一个请求中混合使用 `UploadFormDataItems` 和 `FormDataProviderItems`。一种清晰的分工是：文本字段放在 `UploadFormDataItems`，文件放在 `FormDataProviderItems`。

> 要显示上传进度，请参见 [C11. 使用进度回调](../c11-progress-callback)。
