---
title: "S07. 以流的方式接收 multipart 数据"
order: 26
status: "draft"
---

简单的上传处理器会把整个请求放入 `req.body`，对于大文件会导致内存暴涨。请使用 `HandlerWithContentReader` 逐块接收请求体。

## 基本用法

```cpp
svr.Post("/upload",
  [](const httplib::Request &req, httplib::Response &res,
     const httplib::ContentReader &content_reader) {
    if (req.is_multipart_form_data()) {
      content_reader(
        // 每个 part 的头部
        [&](const httplib::FormData &file) {
          std::cout << "name: " << file.name
                    << ", filename: " << file.filename << std::endl;
          return true;
        },
        // 每个 part 的主体（会被多次调用）
        [&](const char *data, size_t len) {
          // 例如，在这里写入磁盘
          return true;
        });
    } else {
      // 普通的请求体
      content_reader([&](const char *data, size_t len) {
        return true;
      });
    }

    res.set_content("ok", "text/plain");
  });
```

`content_reader` 有两种调用形式。对于 multipart 数据，传入两个回调（一个用于头部，一个用于主体）。对于普通请求体，只需传入一个。

## 直接写入磁盘

下面介绍如何将上传的文件流式写入磁盘。

```cpp
svr.Post("/upload",
  [](const httplib::Request &req, httplib::Response &res,
     const httplib::ContentReader &content_reader) {
    std::ofstream ofs;

    content_reader(
      [&](const httplib::FormData &file) {
        if (!file.filename.empty()) {
          ofs.open("uploads/" + file.filename, std::ios::binary);
        }
        return static_cast<bool>(ofs);
      },
      [&](const char *data, size_t len) {
        ofs.write(data, len);
        return static_cast<bool>(ofs);
      });

    res.set_content("uploaded", "text/plain");
  });
```

任意时刻内存中只驻留一小块数据，因此 GB 级别的文件也不在话下。

## 自行统计 part 数量

part 的数量有一个上限 `CPPHTTPLIB_MULTIPART_FORM_DATA_FILE_MAX_COUNT`（默认为 1024），但它只适用于缓冲路径，即每个 part 都会累积到 `req.form` 中的情况。`ContentReader` 在库这一侧不保留任何内容，因此该上限在这里不适用。

如果你想要一个上限，请自行统计 part 数量，并在头部回调中返回 `false`。解析器会就此停止。

```cpp
svr.Post("/upload",
  [](const httplib::Request &req, httplib::Response &res,
     const httplib::ContentReader &content_reader) {
    size_t count = 0;

    auto ok = content_reader(
      [&](const httplib::FormData &file) {
        if (++count > 100) { return false; } // 在此停止
        return true;
      },
      [&](const char *data, size_t len) {
        return true;
      });

    if (!ok) {
      res.status = httplib::StatusCode::BadRequest_400;
      return;
    }

    res.set_content("ok", "text/plain");
  });
```

当 `content_reader` 返回 `false` 时，请自行设置响应状态。请求体的剩余部分不会被读取，连接会被关闭，因此仍在发送数据的客户端会看到连接中断。

> **警告：** 当你使用 `HandlerWithContentReader` 时，`req.body` 会保持为**空**。请在回调内部自行处理请求体。

> 关于 multipart 上传的客户端，请参阅 [C07. 以 multipart 表单数据上传文件](../c07-multipart-upload)。
