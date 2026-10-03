---
title: "S01. 注册 GET / POST / PUT / DELETE 处理器"
order: 20
status: "draft"
---

借助 `httplib::Server`，你可以为每种 HTTP 方法注册一个处理器。只需向 `Get()`、`Post()`、`Put()` 或 `Delete()` 传入一个模式和一个 lambda 即可。对于内置集合之外的方法，例如 WebDAV 的 `PROPFIND`，请使用 `CustomRoute()`。

## 基本用法

```cpp
#include <httplib.h>

int main() {
  httplib::Server svr;

  svr.Get("/hello", [](const httplib::Request &req, httplib::Response &res) {
    res.set_content("Hello, World!", "text/plain");
  });

  svr.Post("/api/items", [](const httplib::Request &req, httplib::Response &res) {
    // req.body 保存请求体
    res.status = 201;
    res.set_content("Created", "text/plain");
  });

  svr.Put("/api/items/1", [](const httplib::Request &req, httplib::Response &res) {
    res.set_content("Updated", "text/plain");
  });

  svr.Delete("/api/items/1", [](const httplib::Request &req, httplib::Response &res) {
    res.status = 204;
  });

  svr.listen("0.0.0.0", 8080);
}
```

处理器接收 `(const Request&, Response&)`。使用 `res.set_content()` 设置响应体和 Content-Type，使用 `res.status` 设置状态码。`listen()` 会启动服务器并阻塞当前线程。

## 读取查询参数

```cpp
svr.Get("/search", [](const httplib::Request &req, httplib::Response &res) {
  auto q = req.get_param_value("q");
  auto limit = req.get_param_value("limit");
  res.set_content("q=" + q + ", limit=" + limit, "text/plain");
});
```

`req.get_param_value()` 从查询字符串中取出一个值。如果你想先检查是否存在，请使用 `req.has_param("q")`。

## 读取请求头

```cpp
svr.Get("/me", [](const httplib::Request &req, httplib::Response &res) {
  auto ua = req.get_header_value("User-Agent");
  res.set_content("UA: " + ua, "text/plain");
});
```

要添加响应头，请使用 `res.set_header("Name", "Value")`。

> **注意：** `listen()` 是一个阻塞调用。要在其他线程上运行它，请将其包装在 `std::thread` 中。如果你需要非阻塞启动，请参阅 [S18. 使用 `listen_after_bind` 控制启动顺序](../s18-listen-after-bind)。

> 要使用诸如 `/users/:id` 这样的路径参数，请参阅 [S03. 使用路径参数](../s03-path-params)。

> 对于内置集合之外的方法，例如 WebDAV 的 `PROPFIND`，请参阅 [S23. 处理自定义 HTTP 方法](../s23-custom-methods)。
