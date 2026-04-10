---
title: "S07. Receive Multipart Data as a Stream"
order: 26
status: "draft"
---

A naive upload handler puts the whole request into `req.body`, which blows up memory for large files. Use `HandlerWithContentReader` to receive the body chunk by chunk.

## Basic usage

```cpp
svr.Post("/upload",
  [](const httplib::Request &req, httplib::Response &res,
     const httplib::ContentReader &content_reader) {
    if (req.is_multipart_form_data()) {
      content_reader(
        // headers of each part
        [&](const httplib::FormData &file) {
          std::cout << "name: " << file.name
                    << ", filename: " << file.filename << std::endl;
          return true;
        },
        // body of each part (called multiple times)
        [&](const char *data, size_t len) {
          // write to disk here, for example
          return true;
        });
    } else {
      // plain request body
      content_reader([&](const char *data, size_t len) {
        return true;
      });
    }

    res.set_content("ok", "text/plain");
  });
```

The `content_reader` has two call shapes. For multipart data, pass two callbacks (one for headers, one for body). For plain bodies, pass just one.

## Write directly to disk

Here's how to stream an uploaded file to disk.

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

Only a small chunk sits in memory at any moment, so gigabyte-scale files are no problem.

> **Warning:** When you use `HandlerWithContentReader`, `req.body` stays **empty**. Handle the body yourself inside the callbacks.

> For the client side of multipart uploads, see C07. Upload a File as Multipart Form Data.
