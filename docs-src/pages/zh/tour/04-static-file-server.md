---
title: "静态文件服务器"
order: 4
---

cpp-httplib 也可以提供静态文件服务 —— HTML、CSS、图片，应有尽有。无需复杂的配置，只需调用一次 `set_mount_point()` 即可。

## set_mount_point 的基础

让我们直接开始。`set_mount_point()` 将 URL 路径映射到本地目录。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.set_mount_point("/", "./html");

    std::cout << "Listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);
}
```

第一个参数是 URL 挂载点，第二个参数是本地目录路径。在这个示例中，对 `/` 的请求将由 `./html` 目录提供。

让我们试一下。首先创建一个 `html` 目录，并添加一个 `index.html` 文件。

```sh
mkdir html
```

```html
<!DOCTYPE html>
<html>
<head><title>My Page</title></head>
<body>
    <h1>Hello from cpp-httplib!</h1>
    <p>This is a static file.</p>
</body>
</html>
```

编译并启动服务器。

```sh
g++ -std=c++17 -o server server.cpp -pthread
./server
```

在浏览器中打开 `http://localhost:8080`，你应该会看到 `html/index.html` 的内容。访问 `http://localhost:8080/index.html` 也会返回同一个页面。

你也可以用上一章的客户端代码或者 `curl` 来访问它。

```cpp
httplib::Client cli("http://localhost:8080");
auto res = cli.Get("/");
if (res) {
    std::cout << res->body << std::endl;  // 显示 HTML
}
```

```sh
curl http://localhost:8080
```

## 多个挂载点

你可以根据需要多次调用 `set_mount_point()`。每个 URL 路径都可以对应各自的目录。

```cpp
svr.set_mount_point("/", "./public");
svr.set_mount_point("/assets", "./static/assets");
svr.set_mount_point("/docs", "./documentation");
```

对 `/assets/style.css` 的请求会提供 `./static/assets/style.css`，对 `/docs/guide.html` 的请求会提供 `./documentation/guide.html`。

## 与处理器组合使用

静态文件服务与路由处理器 —— 也就是你在上一章学到的那种 —— 可以协同工作。

```cpp
httplib::Server svr;

// API 端点
svr.Get("/api/hello", [](const auto &, auto &res) {
    res.set_content(R"({"message":"Hello!"})", "application/json");
});

// 静态文件服务
svr.set_mount_point("/", "./public");

svr.listen("0.0.0.0", 8080);
```

处理器优先。处理器会响应 `/api/hello`，而对于其他所有路径，服务器会在 `./public` 中查找文件。

## 添加响应头

把响应头作为第三个参数传给 `set_mount_point()`，它们就会被附加到每个静态文件响应中。这对于缓存控制非常有用。

```cpp
svr.set_mount_point("/", "./public", {
    {"Cache-Control", "max-age=3600"}
});
```

这样一来，浏览器会把提供的文件缓存一小时。

## 用于静态文件服务器的 Dockerfile

cpp-httplib 仓库中包含一个专为静态文件服务构建的 `Dockerfile`。我们还在 Docker Hub 上发布了预构建镜像，因此只需一条命令即可启动并运行。

```sh
> docker run -p 8080:80 -v ./my-site:/html yhirose4dockerhub/cpp-httplib-server
Serving HTTP on 0.0.0.0:80
Mount point: / -> ./html
Press Ctrl+C to shutdown gracefully...
192.168.65.1 - - [22/Feb/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 256 "-" "Mozilla/5.0 ..."
192.168.65.1 - - [22/Feb/2026:12:00:00 +0000] "GET /style.css HTTP/1.1" 200 1024 "-" "Mozilla/5.0 ..."
192.168.65.1 - - [22/Feb/2026:12:00:01 +0000] "GET /favicon.ico HTTP/1.1" 404 152 "-" "Mozilla/5.0 ..."
```

`./my-site` 目录中的所有内容都会在 8080 端口上提供。访问日志采用与 NGINX 相同的格式，因此你可以清楚地看到实际发生了什么。

## 接下来

现在你可以提供静态文件了。一个能提供 HTML、CSS 和 JavaScript 的 Web 服务器 —— 用这么少的代码就构建出来了。

接下来，让我们用 HTTPS 加密你的连接。我们会先从设置 TLS 库开始。

**下一章：** [TLS Setup](../05-tls-setup)
