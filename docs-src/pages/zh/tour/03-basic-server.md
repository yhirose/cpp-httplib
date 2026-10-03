---
title: "基础服务器"
order: 3
---

在上一章中，你从客户端向测试服务器发送了请求。现在让我们来逐步了解那个服务器实际上是如何工作的。

## 启动服务器

注册好路由后，调用 `svr.listen()` 启动服务器。

```cpp
svr.listen("0.0.0.0", 8080);
```

第一个参数是主机，第二个参数是端口。`"0.0.0.0"` 会在所有网络接口上监听。如果你只想接受来自本机的连接，请使用 `"127.0.0.1"`。

`listen()` 是一个阻塞调用。在服务器停止之前它不会返回。服务器会一直运行，直到你在终端中按下 `Ctrl+C`，或者从另一个线程调用 `svr.stop()`。

## 路由

路由是任何服务器的核心。它让你告诉 cpp-httplib：当针对这个 URL、使用这个 HTTP 方法的请求到来时，运行这段代码。

```cpp
httplib::Server svr;

svr.Get("/hi", [](const httplib::Request &req, httplib::Response &res) {
    res.set_content("Hello!", "text/plain");
});
```

`svr.Get()` 为 GET 请求注册一个处理器。第一个参数是路径，第二个参数是处理器函数。当 GET 请求到达 `/hi` 时，你的 lambda 就会运行。

每种 HTTP 方法都有一个对应的方法。

```cpp
svr.Get("/path",    handler);  // GET
svr.Post("/path",   handler);  // POST
svr.Put("/path",    handler);  // PUT
svr.Delete("/path", handler);  // DELETE
```

处理器的签名是 `(const httplib::Request &req, httplib::Response &res)`。你可以用 `auto` 让它更简短。

```cpp
svr.Get("/hi", [](const auto &req, auto &res) {
    res.set_content("Hello!", "text/plain");
});
```

处理器只在路径匹配时运行。对未注册路径的请求会自动返回 404。

## 请求对象

第一个参数 `req` 提供了客户端发送的所有内容。

### 请求体

`req.body` 以 `std::string` 的形式保存请求体。

```cpp
svr.Post("/post", [](const auto &req, auto &res) {
    // 将请求体原样返回给客户端
    res.set_content(req.body, "text/plain");
});
```

### 请求头

使用 `req.get_header_value()` 读取请求头。

```cpp
svr.Get("/check", [](const auto &req, auto &res) {
    auto auth = req.get_header_value("Authorization");
    res.set_content("Auth: " + auth, "text/plain");
});
```

### 查询参数与表单数据

`req.get_param_value()` 按名称获取参数。它既适用于 GET 查询参数，也适用于 POST 表单数据。

```cpp
svr.Get("/search", [](const auto &req, auto &res) {
    auto q = req.get_param_value("q");
    res.set_content("Query: " + q, "text/plain");
});
```

对 `/search?q=cpp-httplib` 的请求会为 `q` 返回 `"cpp-httplib"`。

要遍历所有参数，请使用 `req.params`。

```cpp
svr.Post("/submit", [](const auto &req, auto &res) {
    std::string result;
    for (auto &[key, val] : req.params) {
        result += key + " = " + val + "\n";
    }
    res.set_content(result, "text/plain");
});
```

### 文件上传

通过 multipart 表单数据上传的文件可以通过 `req.form.get_file()` 获取。

```cpp
svr.Post("/upload", [](const auto &req, auto &res) {
    auto f = req.form.get_file("file");
    auto content = f.filename + " (" + std::to_string(f.content.size()) + " bytes)";
    res.set_content(content, "text/plain");
});
```

`f.filename` 提供文件名，`f.content` 提供文件数据。

## 路径参数

有时你想把 URL 的一部分捕获为变量 —— 例如 `/users/42` 中的 `42`。使用 `:param` 语法即可做到。

```cpp
svr.Get("/users/:id", [](const auto &req, auto &res) {
    auto id = req.path_params.at("id");
    res.set_content("User ID: " + id, "text/plain");
});
```

对 `/users/42` 的请求会从 `req.path_params.at("id")` 返回 `"42"`。`/users/100` 会返回 `"100"`。

你可以一次捕获多个片段。

```cpp
svr.Get("/users/:user_id/posts/:post_id", [](const auto &req, auto &res) {
    auto user_id = req.path_params.at("user_id");
    auto post_id = req.path_params.at("post_id");
    res.set_content("User: " + user_id + ", Post: " + post_id, "text/plain");
});
```

### 正则表达式

你也可以直接在路径中编写正则表达式，而不使用 `:param`。捕获组的值可以通过 `req.matches` 获取，它是一个 `std::smatch`。

```cpp
// 只接受数字 ID
svr.Get(R"(/files/(\d+))", [](const auto &req, auto &res) {
    auto id = req.matches[1];  // 第一个捕获组
    res.set_content("File ID: " + std::string(id), "text/plain");
});
```

`/files/42` 会匹配，但 `/files/abc` 不会。当你想要约束可接受的值时，这很方便。

## 构建响应

第二个参数 `res` 是你向客户端回传数据的方式。

### 响应体与 Content-Type

`res.set_content()` 设置响应体和 Content-Type。对于 200 响应，这就是你需要的全部。

```cpp
svr.Get("/hi", [](const auto &req, auto &res) {
    res.set_content("Hello!", "text/plain");
});
```

### 状态码

要返回不同的状态码，请给 `res.status` 赋值。

```cpp
svr.Get("/not-found", [](const auto &req, auto &res) {
    res.status = 404;
    res.set_content("Not found", "text/plain");
});
```

### 响应头

使用 `res.set_header()` 添加响应头。

```cpp
svr.Get("/with-header", [](const auto &req, auto &res) {
    res.set_header("X-Custom", "my-value");
    res.set_content("Hello!", "text/plain");
});
```

## 逐步解析测试服务器

现在让我们运用所学知识，通读上一章中的测试服务器。

### GET /hi

```cpp
svr.Get("/hi", [](const auto &, auto &res) {
    res.set_content("Hello!", "text/plain");
});
```

这是最简单的处理器。我们不需要请求中的任何信息，因此 `req` 参数没有命名。它只是返回 `"Hello!"`。

### GET /search

```cpp
svr.Get("/search", [](const auto &req, auto &res) {
    auto q = req.get_param_value("q");
    res.set_content("Query: " + q, "text/plain");
});
```

`req.get_param_value("q")` 取出查询参数 `q`。对 `/search?q=cpp-httplib` 的请求会返回 `"Query: cpp-httplib"`。

### POST /post

```cpp
svr.Post("/post", [](const auto &req, auto &res) {
    res.set_content(req.body, "text/plain");
});
```

一个回显服务器。无论客户端发送什么请求体，`req.body` 都会保存它，我们把它直接发回去。

### POST /submit

```cpp
svr.Post("/submit", [](const auto &req, auto &res) {
    std::string result;
    for (auto &[key, val] : req.params) {
        result += key + " = " + val + "\n";
    }
    res.set_content(result, "text/plain");
});
```

使用结构化绑定（`auto &[key, val]`）遍历 `req.params` 中的表单数据，以解包每个键值对。

### POST /upload

```cpp
svr.Post("/upload", [](const auto &req, auto &res) {
    auto f = req.form.get_file("file");
    auto content = f.filename + " (" + std::to_string(f.content.size()) + " bytes)";
    res.set_content(content, "text/plain");
});
```

接收通过 multipart 表单数据上传的文件。`req.form.get_file("file")` 获取名为 `"file"` 的字段，然后我们返回文件名和大小。

### GET /users/:id

```cpp
svr.Get("/users/:id", [](const auto &req, auto &res) {
    auto id = req.path_params.at("id");
    res.set_content("User ID: " + id, "text/plain");
});
```

`:id` 是路径参数。`req.path_params.at("id")` 获取它的值。`/users/42` 会返回 `"42"`，`/users/alice` 会返回 `"alice"`。

### GET /files/(\d+)

```cpp
svr.Get(R"(/files/(\d+))", [](const auto &req, auto &res) {
    auto id = req.matches[1];
    res.set_content("File ID: " + std::string(id), "text/plain");
});
```

正则表达式 `(\d+)` 只匹配数字 ID。`/files/42` 会命中这个处理器，但 `/files/abc` 会返回 404。`req.matches[1]` 获取第一个捕获组。

## 下一步

现在你已经全面了解了服务器的工作方式。路由、读取请求、构建响应 —— 这些足以构建一个真正的 API 服务器。

接下来，让我们看看如何提供静态文件。我们将构建一个能够提供 HTML 和 CSS 的服务器。

**下一章：** [静态文件服务器](../04-static-file-server)
