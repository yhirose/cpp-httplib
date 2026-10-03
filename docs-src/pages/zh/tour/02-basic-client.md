---
title: "基础客户端"
order: 2
---

cpp-httplib 不只能用于服务器 —— 它还附带一个完整的 HTTP 客户端。让我们用 `httplib::Client` 来发送 GET 和 POST 请求。

## 准备测试服务器

要试用客户端，你需要一个能接受请求的服务器。保存以下代码，然后按照上一章相同的方式编译并运行它。我们将在下一章介绍服务器的细节。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.Get("/hi", [](const auto &, auto &res) {
        res.set_content("Hello!", "text/plain");
    });

    svr.Get("/search", [](const auto &req, auto &res) {
        auto q = req.get_param_value("q");
        res.set_content("Query: " + q, "text/plain");
    });

    svr.Post("/post", [](const auto &req, auto &res) {
        res.set_content(req.body, "text/plain");
    });

    svr.Post("/submit", [](const auto &req, auto &res) {
        std::string result;
        for (auto &[key, val] : req.params) {
            result += key + " = " + val + "\n";
        }
        res.set_content(result, "text/plain");
    });

    svr.Post("/upload", [](const auto &req, auto &res) {
        auto f = req.form.get_file("file");
        auto content = f.filename + " (" + std::to_string(f.content.size()) + " bytes)";
        res.set_content(content, "text/plain");
    });

    svr.Get("/users/:id", [](const auto &req, auto &res) {
        auto id = req.path_params.at("id");
        res.set_content("User ID: " + id, "text/plain");
    });

    svr.Get(R"(/files/(\d+))", [](const auto &req, auto &res) {
        auto id = req.matches[1];
        res.set_content("File ID: " + std::string(id), "text/plain");
    });

    std::cout << "Listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);
}
```

## GET 请求

服务器运行起来后，打开一个单独的终端试试看。我们先从最简单的 GET 请求开始。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("http://localhost:8080");

    auto res = cli.Get("/hi");
    if (res) {
        std::cout << res->status << std::endl;  // 200
        std::cout << res->body << std::endl;    // Hello!
    }
}
```

将服务器地址传给 `httplib::Client` 的构造函数，然后调用 `Get()` 发送请求。你可以从返回的 `res` 中获取状态码和响应体。

等价的 `curl` 命令如下。

```sh
curl http://localhost:8080/hi
# Hello!
```

## 检查响应

响应除了状态码和响应体之外，还包含响应头信息。

```cpp
auto res = cli.Get("/hi");
if (res) {
    // 状态码
    std::cout << res->status << std::endl;  // 200

    // 响应体
    std::cout << res->body << std::endl;  // Hello!

    // 响应头
    std::cout << res->get_header_value("Content-Type") << std::endl;  // text/plain
}
```

`res->body` 是 `std::string`，所以如果你想解析 JSON 响应，可以直接把它传给 [nlohmann/json](https://github.com/nlohmann/json) 之类的 JSON 库。

## 查询参数

要向 GET 请求添加查询参数，你可以直接把它们写在 URL 中，也可以使用 `httplib::Params`。

```cpp
auto res = cli.Get("/search", httplib::Params{{"q", "cpp-httplib"}});
if (res) {
    std::cout << res->body << std::endl;  // Query: cpp-httplib
}
```

`httplib::Params` 会自动为你对特殊字符进行 URL 编码。

```sh
curl "http://localhost:8080/search?q=cpp-httplib"
# Query: cpp-httplib
```

## 路径参数

当值直接嵌入在 URL 路径中时，不需要特殊的客户端 API。只需将路径原样传给 `Get()` 即可。

```cpp
auto res = cli.Get("/users/42");
if (res) {
    std::cout << res->body << std::endl;  // User ID: 42
}
```

```sh
curl http://localhost:8080/users/42
# User ID: 42
```

测试服务器还有一个 `/files/(\d+)` 路由，它使用正则表达式只接受数字 ID。

```cpp
auto res = cli.Get("/files/42");
if (res) {
    std::cout << res->body << std::endl;  // File ID: 42
}
```

```sh
curl http://localhost:8080/files/42
# File ID: 42
```

如果传入 `/files/abc` 这样的非数字 ID，你会得到 404。我们将在下一章介绍它的工作原理。

## 请求头

要添加自定义 HTTP 请求头，请传入一个 `httplib::Headers` 对象。`Get()` 和 `Post()` 都支持这种用法。

```cpp
auto res = cli.Get("/hi", httplib::Headers{
    {"Authorization", "Bearer my-token"}
});
```

```sh
curl -H "Authorization: Bearer my-token" http://localhost:8080/hi
```

## POST 请求

让我们 POST 一些文本数据。将请求体作为 `Post()` 的第二个参数传入，将 Content-Type 作为第三个参数传入。

```cpp
auto res = cli.Post("/post", "Hello, Server!", "text/plain");
if (res) {
    std::cout << res->status << std::endl;  // 200
    std::cout << res->body << std::endl;    // Hello, Server!
}
```

测试服务器的 `/post` 端点会把请求体原样返回，所以你会得到与发送时相同的字符串。

```sh
curl -X POST -H "Content-Type: text/plain" -d "Hello, Server!" http://localhost:8080/post
# Hello, Server!
```

## 发送表单数据

你可以像 HTML 表单那样发送键值对。使用 `httplib::Params` 即可。

```cpp
auto res = cli.Post("/submit", httplib::Params{
    {"name", "Alice"},
    {"age", "30"}
});
if (res) {
    std::cout << res->body << std::endl;
    // age = 30
    // name = Alice
}
```

这会以 `application/x-www-form-urlencoded` 格式发送数据。

```sh
curl -X POST -d "name=Alice&age=30" http://localhost:8080/submit
```

## 通过 POST 上传文件

要上传文件，请使用 `httplib::UploadFormDataItems` 将它作为 multipart 表单数据发送。

```cpp
auto res = cli.Post("/upload", httplib::UploadFormDataItems{
    {"file", "Hello, File!", "hello.txt", "text/plain"}
});
if (res) {
    std::cout << res->body << std::endl;  // hello.txt (12 bytes)
}
```

`UploadFormDataItems` 中的每个元素都有四个字段：`{name, content, filename, content_type}`。

```sh
curl -F "file=Hello, File!;filename=hello.txt;type=text/plain" http://localhost:8080/upload
```

## 错误处理

网络通信可能会失败 —— 服务器可能无法访问。请始终检查 `res` 是否有效。

```cpp
httplib::Client cli("http://localhost:9999");  // 不存在的端口
auto res = cli.Get("/hi");

if (!res) {
    // 连接错误
    std::cout << "Error: " << httplib::to_string(res.error()) << std::endl;
    // Error: Connection
    return 1;
}

// 如果能执行到这里，说明我们收到了响应
if (res->status != 200) {
    std::cout << "HTTP Error: " << res->status << std::endl;
    return 1;
}

std::cout << res->body << std::endl;
```

错误分为两个层级。

- **连接错误**：客户端无法访问服务器。`res` 求值为 false，你可以调用 `res.error()` 来查明出了什么问题。
- **HTTP 错误**：服务器返回了错误状态（404、500 等）。`res` 求值为 true，但你需要检查 `res->status`。

## 下一步

现在你已经知道如何从客户端发送请求了。接下来，让我们更仔细地看看服务器端。我们将深入探讨路由、路径参数等内容。

**下一章：** [基础服务器](../03-basic-server)
