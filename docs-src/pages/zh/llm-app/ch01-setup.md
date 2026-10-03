---
title: "1. 搭建项目环境"
order: 1

---

让我们使用 llama.cpp 作为推理引擎，逐步构建一个文本翻译 REST API 服务器。最终，像下面这样的请求就能返回翻译结果。

```bash
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "The weather is nice today. Shall we go for a walk?", "target_lang": "ja"}'
```

```json
{
  "translation": "今日はいい天気ですね。散歩に行きましょうか？"
}
```

「翻译 API」只是一个例子。只要替换提示词，你就可以把它应用到任何你喜欢的 LLM 应用上，例如摘要、代码生成或聊天机器人。

以下是服务器最终提供的 API 完整列表。

| 方法 | 路径 | 说明 | 章节 |
| -------- | ---- | ---- | -- |
| `GET` | `/health` | 返回服务器状态 | 1 |
| `POST` | `/translate` | 翻译文本并以 JSON 返回 | 2 |
| `POST` | `/translate/stream` | 以 token 为单位进行 SSE 流式输出 | 3 |
| `GET` | `/models` | 模型列表（available / downloaded / selected） | 4 |
| `POST` | `/models/select` | 选择模型（若尚未下载则自动下载） | 4 |

在本章中，我们先搭建项目环境。我们会获取依赖库、创建目录结构、配置构建设置并下载模型文件，这样在下一章就能直接开始写代码了。

## 前置条件

- 支持 C++20 的编译器（GCC 10+、Clang 10+、MSVC 2019 16.8+）
- CMake 3.20 或更高版本
- OpenSSL（第 4 章中用于 HTTPS 客户端。macOS：`brew install openssl`，Ubuntu：`sudo apt install libssl-dev`）
- 足够的磁盘空间（模型文件可能达到数 GB）

## 1.1 我们将使用的库

以下是我们将要使用的库。

| 库 | 作用 |
| ----------- | ------ |
| [cpp-httplib](https://github.com/yhirose/cpp-httplib) | HTTP 服务器/客户端 |
| [nlohmann/json](https://github.com/nlohmann/json) | JSON 解析器 |
| [cpp-llamalib](https://github.com/yhirose/cpp-llamalib) | llama.cpp 封装 |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) | LLM 推理引擎 |
| [webview/webview](https://github.com/webview/webview) | 桌面 WebView（在第 6 章使用） |

cpp-httplib、nlohmann/json 和 cpp-llamalib 都是 header-only 库。你完全可以只用 `curl` 下载一个头文件然后 `#include` 它，但在本书中我们使用 CMake 的 `FetchContent` 来自动获取它们。只需在 `CMakeLists.txt` 中声明，`cmake -B build` 就会为你下载并构建好一切。webview 要到第 6 章才会用到，所以现在不必操心。

## 1.2 目录结构

最终的结构如下所示。

```ascii
translate-app/
├── CMakeLists.txt
├── models/
│   └── (GGUF files)
└── src/
    └── main.cpp
```

我们不会把库的源代码放进项目里。CMake 的 `FetchContent` 会在构建时自动获取它们，所以你只需要自己的代码。

让我们创建项目目录并初始化 git 仓库。

```bash
mkdir translate-app && cd translate-app
mkdir src models
git init
```

## 1.3 获取 GGUF 模型文件

LLM 推理需要模型文件。GGUF 是 llama.cpp 使用的模型格式，你可以在 Hugging Face 上找到许多模型。

我们先从一个小模型开始。Google Gemma 2 2B 的量化版本（约 1.6 GB）是一个不错的起点。它体积轻巧，却支持多种语言，在翻译任务上表现良好。

```bash
curl -L -o models/gemma-2-2b-it-Q4_K_M.gguf \
  https://huggingface.co/bartowski/gemma-2-2b-it-GGUF/resolve/main/gemma-2-2b-it-Q4_K_M.gguf
```

在第 4 章中，我们将使用 cpp-httplib 的客户端功能，为应用添加从应用内部下载模型的能力。

## 1.4 CMakeLists.txt

在项目根目录创建 `CMakeLists.txt`。通过 `FetchContent` 声明依赖后，CMake 会自动为你下载并构建它们。

<!-- data-file="CMakeLists.txt" -->
```cmake
cmake_minimum_required(VERSION 3.20)
project(translate-server CXX)
set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

# llama.cpp（LLM 推理引擎）
FetchContent_Declare(llama
    GIT_REPOSITORY https://github.com/ggml-org/llama.cpp
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(llama)

# cpp-httplib（HTTP 服务器/客户端）
FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib
    GIT_TAG        master
)
FetchContent_MakeAvailable(httplib)

# nlohmann/json（JSON 解析器）
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# cpp-llamalib（header-only 的 llama.cpp 封装）
FetchContent_Declare(cpp_llamalib
    GIT_REPOSITORY https://github.com/yhirose/cpp-llamalib
    GIT_TAG        main
)
FetchContent_MakeAvailable(cpp_llamalib)

add_executable(translate-server src/main.cpp)

target_link_libraries(translate-server PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    cpp-llamalib
)
```

`FetchContent_Declare` 告诉 CMake 每个库的位置，`FetchContent_MakeAvailable` 则负责获取并构建它们。第一次执行 `cmake -B build` 会花一些时间，因为它要下载所有的库并构建 llama.cpp，但之后的运行会使用缓存。

只需用 `target_link_libraries` 链接，各个库的 CMake 配置就会为你设置好 include 路径和构建选项。

## 1.5 创建骨架代码

我们将以这段骨架代码为基础，逐章添加功能。

<!-- data-file="main.cpp" -->
```cpp
// src/main.cpp
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <csignal>
#include <iostream>

using json = nlohmann::json;

httplib::Server svr;

// 收到 `Ctrl+C` 时优雅关闭
void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // 记录请求与响应日志
  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  // 健康检查
  svr.Get("/health", [](const auto &, auto &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // 各端点的桩实现（后续章节会替换为真正的实现）
  svr.Post("/translate",
           [](const auto &req, auto &res) {
    res.set_content(json{{"translation", "TODO"}}.dump(), "application/json");
  });

  svr.Post("/translate/stream",
           [](const auto &req, auto &res) {
    res.set_content("data: \"TODO\"\n\ndata: [DONE]\n\n", "text/event-stream");
  });

  svr.Get("/models",
          [](const auto &req, auto &res) {
    res.set_content(json{{"models", json::array()}}.dump(), "application/json");
  });

  svr.Post("/models/select",
           [](const auto &req, auto &res) {
    res.set_content(json{{"status", "TODO"}}.dump(), "application/json");
  });

  // 允许通过 `Ctrl+C`（`SIGINT`）或 `kill`（`SIGTERM`）停止服务器
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // 启动服务器
  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

## 1.6 构建与验证

构建项目、启动服务器，然后用 curl 验证请求是否正常工作。

```bash
cmake -B build
cmake --build build -j
./build/translate-server
```

在另一个终端里，用 curl 试一下。

```bash
curl http://localhost:8080/health
# => {"status":"ok"}
```

如果能看到 JSON 返回，就说明环境搭建完成了。

## 下一章

环境已经搭好，下一章我们就在这个骨架之上实现翻译 REST API。我们将用 llama.cpp 运行推理，并用 cpp-httplib 把它暴露为 HTTP 端点。

**下一章：**[集成 llama.cpp 构建 REST API](../ch02-rest-api)
