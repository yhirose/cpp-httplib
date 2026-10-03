---
title: "S23. 处理自定义 HTTP 方法"
order: 42
status: "draft"
---

服务器会以 `400 Bad Request` 拒绝它不认识的方法。要接受扩展方法，例如 RFC 4918 的 WebDAV 方法（`PROPFIND`、`PROPPATCH`、`MKCOL` 等）或 UPnP 的 `SUBSCRIBE`，请用 `CustomRoute()` 注册一个处理器。正是注册处理器这一动作让服务器接受该方法。

## 基本用法

```cpp
svr.CustomRoute("PROPFIND", "/dav/:id",
                [](const httplib::Request &req, httplib::Response &res) {
                  // The request body is available as usual
                  auto id = req.path_params.at("id");
                  res.status = httplib::StatusCode::MultiStatus_207;
                  res.set_content(build_multistatus(req.body), "application/xml");
                });
```

模式的工作方式与 `Get()` 相同。正则表达式和路径参数都可以使用。

## 用 OPTIONS 声明你的方法

WebDAV 客户端在做任何其他事情之前，会先用 `OPTIONS` 询问服务器的能力。cpp-httplib 既不会生成 `DAV:` 响应头，也不会生成 `Allow`，所以请自行返回它们。忘了这一点，即使你的 `PROPFIND` 能正常工作，客户端也会把你拒之门外。

```cpp
svr.Options("/dav/.*", [](const httplib::Request &req, httplib::Response &res) {
  res.set_header("DAV", "1");
  res.set_header("Allow", "OPTIONS, GET, HEAD, PROPFIND, PROPPATCH, MKCOL");
});
```

## 以流的方式读取请求体

有一个内容读取器重载，就和 `Post()` 上的一样。当你不想一次性把大型 XML 文档全部放进内存时，可以使用它。

```cpp
svr.CustomRoute("REPORT", "/dav/.*",
                [](const httplib::Request &req, httplib::Response &res,
                   const httplib::ContentReader &content_reader) {
                  content_reader([&](const char *data, size_t data_length) {
                    // Process it a chunk at a time
                    return true;
                  });
                  res.status = httplib::StatusCode::MultiStatus_207;
                });
```

## 需要牢记的事项

- 方法名必须是合法的 HTTP 方法 token（RFC 9110），并且必须在调用 `listen()` 之前注册
- `GET`、`HEAD`、`POST`、`PUT`、`DELETE`、`CONNECT`、`OPTIONS`、`TRACE`、`PATCH` 和 `PRI` 不能在这里注册。这些请使用各自专用的方法
- 注册被拒绝会让 `is_valid()` 返回 `false`，并使 `listen()` 失败，因此服务器绝不会带着一个永远不会运行的处理器启动
- 静态文件服务和 WebSocket 升级仍然只支持 `GET`/`HEAD`

> **注意：** cpp-httplib 只负责到路由这个方法为止。如果你想称之为 WebDAV，生成 `207 Multi-Status` XML、解析 `Depth` 响应头以及管理锁，全部都需要你自己实现。协议本身位于该库之外。

> 关于注册处理器的基础知识，参见 [S01. 注册 GET / POST / PUT / DELETE 处理器](../s01-handlers)。
