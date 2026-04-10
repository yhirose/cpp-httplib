---
title: "S06. Return a File Download Response"
order: 25
status: "draft"
---

To force a browser to show a **download dialog** instead of rendering inline, send a `Content-Disposition` header. There's no special cpp-httplib API for this — it's just a header.

## Basic usage

```cpp
svr.Get("/download/report", [](const httplib::Request &req, httplib::Response &res) {
  res.set_header("Content-Disposition", "attachment; filename=\"report.pdf\"");
  res.set_file_content("reports/2026-04.pdf", "application/pdf");
});
```

`Content-Disposition: attachment` makes the browser pop up a "Save As" dialog. The `filename=` parameter becomes the default save name.

## Non-ASCII file names

For file names with non-ASCII characters or spaces, use the RFC 5987 `filename*` form.

```cpp
svr.Get("/download/report", [](const httplib::Request &req, httplib::Response &res) {
  res.set_header(
    "Content-Disposition",
    "attachment; filename=\"report.pdf\"; "
    "filename*=UTF-8''%E3%83%AC%E3%83%9D%E3%83%BC%E3%83%88.pdf");
  res.set_file_content("reports/2026-04.pdf", "application/pdf");
});
```

The part after `filename*=UTF-8''` is URL-encoded UTF-8. Keep the ASCII `filename=` too, as a fallback for older browsers.

## Download dynamically generated data

You don't need a real file — you can serve a generated string as a download directly.

```cpp
svr.Get("/export.csv", [](const httplib::Request &req, httplib::Response &res) {
  std::string csv = build_csv();
  res.set_header("Content-Disposition", "attachment; filename=\"export.csv\"");
  res.set_content(csv, "text/csv");
});
```

This is the classic pattern for CSV exports.

> **Note:** Some browsers will trigger a download based on Content-Type alone, even without `Content-Disposition`. Conversely, setting `inline` tries to render the content in the browser when possible.
