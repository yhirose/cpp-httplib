---
title: "C07. Upload a File as Multipart Form Data"
order: 7
status: "draft"
---

When you want to send a file the same way an HTML `<input type="file">` does, use multipart form data (`multipart/form-data`). cpp-httplib offers two APIs — `UploadFormDataItems` and `FormDataProviderItems` — and you pick between them based on **file size**.

## Send a small file

Read the file into memory first, then send it. For small files, this is the simplest path.

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

Each `UploadFormData` entry is `{name, content, filename, content_type}`. For plain text fields, leave `filename` and `content_type` empty.

## Stream a large file

To avoid loading the whole file into memory, use `make_file_provider()`. It reads the file in chunks as it sends — so even huge files won't blow up your memory footprint.

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

The arguments to `make_file_provider()` are `(form name, file path, file name, content type)`. Leave the file name empty to use the file path as-is.

> **Note:** You can mix `UploadFormDataItems` and `FormDataProviderItems` in the same request. A clean split is: text fields in `UploadFormDataItems`, files in `FormDataProviderItems`.

> To show upload progress, see [C11. Use the progress callback](c11-progress-callback).
