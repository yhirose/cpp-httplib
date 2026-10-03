---
title: "入门"
order: 1
---

开始使用 cpp-httplib 只需要 `httplib.h` 和一个 C++ 编译器。让我们下载这个文件，并让一个 Hello World 服务器跑起来。

## 获取 httplib.h

你可以直接从 GitHub 下载它。请始终使用最新版本。

```sh
curl -LO https://github.com/yhirose/cpp-httplib/raw/refs/tags/latest/httplib.h
```

把下载好的 `httplib.h` 放到你的项目目录中，就可以开始了。

## 准备编译器

| OS | 开发环境 | 设置 |
| -- | ----------------------- | ----- |
| macOS | Apple Clang | Xcode Command Line Tools (`xcode-select --install`) |
| Ubuntu | clang++ 或 g++ | `apt install clang` 或 `apt install g++` |
| Windows | MSVC | Visual Studio 2022 或更高版本（安装时包含 C++ 组件） |

## Hello World 服务器

将以下代码保存为 `server.cpp`。

```cpp
#include "httplib.h"

int main() {
    httplib::Server svr;

    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("Hello, World!", "text/plain");
    });

    svr.listen("0.0.0.0", 8080);
}
```

只需短短几行，你就得到了一个能响应 HTTP 请求的服务器。

## 编译与运行

本教程中的示例代码使用 C++17 编写，以获得更清晰、更简洁的代码。cpp-httplib 本身也可以用 C++11 编译。

```sh
# macOS
clang++ -std=c++17 -o server server.cpp

# Linux
# `-pthread`：cpp-httplib 内部使用线程
clang++ -std=c++17 -pthread -o server server.cpp

# Windows (Developer Command Prompt)
# `/EHsc`：启用 C++ 异常处理
cl /EHsc /std:c++17 server.cpp
```

编译完成后，运行它。

```sh
# macOS / Linux
./server

# Windows
server.exe
```

在浏览器中打开 `http://localhost:8080`。如果看到 "Hello, World!"，那就一切就绪了。

你也可以用 `curl` 验证。

```sh
curl http://localhost:8080/
# Hello, World!
```

要停止服务器，请在终端中按 `Ctrl+C`。

## 下一步

现在你已经掌握了运行服务器的基本方法。接下来，我们来看看客户端。cpp-httplib 也附带 HTTP 客户端功能。

**下一章：** [基础客户端](../02-basic-client)
