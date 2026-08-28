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

## Count the parts yourself

There is a cap on the number of parts, `CPPHTTPLIB_MULTIPART_FORM_DATA_FILE_MAX_COUNT` (1024 by default), but it only applies to the buffered path, where every part is accumulated into `req.form`. The `ContentReader` keeps nothing on the library side, so the cap does not apply here.

If you want an upper bound, count the parts yourself and return `false` from the header callback. The parser stops right there.

```cpp
svr.Post("/upload",
  [](const httplib::Request &req, httplib::Response &res,
     const httplib::ContentReader &content_reader) {
    size_t count = 0;

    auto ok = content_reader(
      [&](const httplib::FormData &file) {
        if (++count > 100) { return false; } // stop here
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

When `content_reader` returns `false`, set the response status yourself. The rest of the body is left unread and the connection is closed, so a client that is still sending sees the connection drop.

> **Warning:** When you use `HandlerWithContentReader`, `req.body` stays **empty**. Handle the body yourself inside the callbacks.

> For the client side of multipart uploads, see [C07. Upload a file as multipart form data](../c07-multipart-upload).
