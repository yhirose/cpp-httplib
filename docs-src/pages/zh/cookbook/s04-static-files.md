---
title: "S04. 提供静态文件"
order: 23
status: "draft"
---

要提供 HTML、CSS 和图片等静态文件，请使用 `set_mount_point()`。只需将 URL 路径映射到本地目录，整个目录就变得可访问了。

## 基本用法

```cpp
httplib::Server svr;
svr.set_mount_point("/", "./public");
svr.listen("0.0.0.0", 8080);
```

现在可以通过 `http://localhost:8080/index.html` 访问 `./public/index.html`，通过 `http://localhost:8080/css/style.css` 访问 `./public/css/style.css`。目录结构与 URL 一一对应。

## 多个挂载点

你可以注册多个挂载点。

```cpp
svr.set_mount_point("/", "./public");
svr.set_mount_point("/assets", "./dist/assets");
svr.set_mount_point("/uploads", "./var/uploads");
```

你甚至可以在同一路径挂载多个目录——它们会按注册顺序被搜索，第一个命中的生效。

## 与 API 处理器结合使用

静态文件和 API 处理器可以很好地共存。使用 `Get()` 及其同类方法注册的处理器优先；只有当没有任何匹配时，才会搜索挂载点。

```cpp
svr.Get("/api/users", [](const auto &req, auto &res) {
  res.set_content("[]", "application/json");
});

svr.set_mount_point("/", "./public");
```

这为你提供了一个对 SPA 友好的配置：`/api/*` 命中处理器，其余内容都从 `./public/` 提供。

## 添加 MIME 类型

cpp-httplib 自带一个扩展名到 Content-Type 的内置映射，但你也可以添加自己的映射。

```cpp
svr.set_file_extension_and_mimetype_mapping("wasm", "application/wasm");
```

> **警告：** 静态文件服务器相关方法**不是线程安全的**。不要在 `listen()` 之后调用它们——请在启动服务器之前完成所有配置。

> 关于下载式响应，请参阅 [S06. 返回文件下载响应](../s06-download-response)。
