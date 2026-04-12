---
title: "S04. Serve Static Files"
order: 23
status: "draft"
---

To serve static files like HTML, CSS, and images, use `set_mount_point()`. Just map a URL path to a local directory, and the whole directory becomes accessible.

## Basic usage

```cpp
httplib::Server svr;
svr.set_mount_point("/", "./public");
svr.listen("0.0.0.0", 8080);
```

`./public/index.html` is now reachable at `http://localhost:8080/index.html`, and `./public/css/style.css` at `http://localhost:8080/css/style.css`. The directory layout maps directly to URLs.

## Multiple mount points

You can register more than one mount point.

```cpp
svr.set_mount_point("/", "./public");
svr.set_mount_point("/assets", "./dist/assets");
svr.set_mount_point("/uploads", "./var/uploads");
```

You can even mount multiple directories at the same path — they're searched in registration order, and the first hit wins.

## Combine with API handlers

Static files and API handlers coexist happily. Handlers registered with `Get()` and friends take priority; the mount points are searched only when nothing matches.

```cpp
svr.Get("/api/users", [](const auto &req, auto &res) {
  res.set_content("[]", "application/json");
});

svr.set_mount_point("/", "./public");
```

This gives you an SPA-friendly setup: `/api/*` hits the handlers, everything else is served from `./public/`.

## Add MIME types

cpp-httplib ships with a built-in extension-to-Content-Type map, but you can add your own.

```cpp
svr.set_file_extension_and_mimetype_mapping("wasm", "application/wasm");
```

> **Warning:** The static file server methods are **not thread-safe**. Don't call them after `listen()` — configure everything before starting the server.

> For download-style responses, see [S06. Return a file download response](s06-download-response).
