---
title: "4. 添加模型下载与管理"
order: 4

---

到第 3 章结束时，服务器的翻译功能已经完备。然而，唯一可用的模型文件是我们在第 1 章手动下载的那个。在本章中，我们将使用 cpp-httplib 的**客户端功能**，让应用能够下载和切换 Hugging Face 模型。

完成后，你就可以通过类似下面的请求来管理模型：

```bash
# 获取可用模型列表
curl http://localhost:8080/models
```

```json
{
  "models": [
    {"name": "gemma-2-2b-it", "params": "2B", "size": "1.6 GB", "downloaded": true, "selected": true},
    {"name": "gemma-2-9b-it", "params": "9B", "size": "5.8 GB", "downloaded": false, "selected": false},
    {"name": "Llama-3.1-8B-Instruct", "params": "8B", "size": "4.9 GB", "downloaded": false, "selected": false}
  ]
}
```

```bash
# 选择另一个模型（若尚不可用则会自动下载）
curl -N -X POST http://localhost:8080/models/select \
  -H "Content-Type: application/json" \
  -d '{"model": "gemma-2-9b-it"}'
```

```text
data: {"status":"downloading","progress":0}
data: {"status":"downloading","progress":12}
...
data: {"status":"downloading","progress":100}
data: {"status":"loading"}
data: {"status":"ready"}
```

## 4.1 httplib::Client 基础

到目前为止，我们只使用了 `httplib::Server`，但 cpp-httplib 也提供客户端功能。由于 Hugging Face 使用 HTTPS，我们需要一个支持 TLS 的客户端。

```cpp
#include <httplib.h>

// 传入 URL scheme 时会自动使用 SSLClient
httplib::Client cli("https://huggingface.co");

// 自动跟随重定向（Hugging Face 会重定向到 CDN）
cli.set_follow_location(true);

auto res = cli.Get("/api/models");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

要使用 HTTPS，需要在构建时启用 OpenSSL。在你的 `CMakeLists.txt` 中添加以下内容：

```cmake
find_package(OpenSSL REQUIRED)

target_link_libraries(translate-server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(translate-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)

# macOS：加载系统证书所需
if(APPLE)
  target_link_libraries(translate-server PRIVATE "-framework CoreFoundation" "-framework Security")
endif()
```

定义 `CPPHTTPLIB_OPENSSL_SUPPORT` 后，`httplib::Client("https://...")` 就能建立 TLS 连接。在 macOS 上，还需要链接 CoreFoundation 和 Security 框架以访问系统证书存储。完整的 `CMakeLists.txt` 见 4.8 节。

## 4.2 定义模型列表

让我们定义应用可以处理的模型列表。以下是我们为翻译任务验证过的几个模型。

```cpp
struct ModelInfo {
  std::string name;       // 显示名称
  std::string params;     // 参数数量
  std::string size;       // GGUF Q4 大小
  std::string repo;       // Hugging Face 仓库
  std::string filename;   // GGUF 文件名
};

const std::vector<ModelInfo> MODELS = {
  {
    .name     = "gemma-2-2b-it",
    .params   = "2B",
    .size     = "1.6 GB",
    .repo     = "bartowski/gemma-2-2b-it-GGUF",
    .filename = "gemma-2-2b-it-Q4_K_M.gguf",
  },
  {
    .name     = "gemma-2-9b-it",
    .params   = "9B",
    .size     = "5.8 GB",
    .repo     = "bartowski/gemma-2-9b-it-GGUF",
    .filename = "gemma-2-9b-it-Q4_K_M.gguf",
  },
  {
    .name     = "Llama-3.1-8B-Instruct",
    .params   = "8B",
    .size     = "4.9 GB",
    .repo     = "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
    .filename = "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
  },
};
```

## 4.3 模型存储位置

直到第 3 章，我们都把模型存储在项目内的 `models/` 目录中。但在管理多个模型时，使用专用的应用目录更加合适。在 macOS/Linux 上我们使用 `~/.translate-app/models/`，在 Windows 上使用 `%APPDATA%\translate-app\models\`。

```cpp
std::filesystem::path get_models_dir() {
#ifdef _WIN32
  auto env = std::getenv("APPDATA");
  auto base = env ? std::filesystem::path(env) : std::filesystem::path(".");
  return base / "translate-app" / "models";
#else
  auto env = std::getenv("HOME");
  auto base = env ? std::filesystem::path(env) : std::filesystem::path(".");
  return base / ".translate-app" / "models";
#endif
}
```

如果环境变量未设置，则回退到当前目录。应用会在启动时创建该目录（即使目录已存在，`create_directories` 也不会报错）。

## 4.4 重写模型初始化

我们重写 `main()` 开头的模型初始化部分。在第 1 章中我们硬编码了路径，但从现在起我们支持模型切换。我们用 `selected_model` 跟踪当前加载的文件名，并在启动时加载 `MODELS` 中的第一项。`GET /models` 和 `POST /models/select` 处理器会引用并更新这个变量。

由于 cpp-httplib 在线程池上并发运行处理器，如果在另一个线程正在调用 `llm.chat()` 时重新赋值 `llm`，就会崩溃。我们添加一个 `std::mutex` 来防止这种情况。

```cpp
int main() {
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  std::string selected_model = MODELS[0].filename;
  auto path = models_dir / selected_model;

  // 若默认模型尚不存在，则自动下载
  if (!std::filesystem::exists(path)) {
    std::cout << "Downloading " << selected_model << "..." << std::endl;
    if (!download_model(MODELS[0], [](int pct) {
          std::cout << "\r" << pct << "%" << std::flush;
          return true;
        })) {
      std::cerr << "\nFailed to download model." << std::endl;
      return 1;
    }
    std::cout << std::endl;
  }
  auto llm = llamalib::Llama{path};
  std::mutex llm_mutex; // 在模型切换期间保护访问
  // ...
}
```

这样可以确保用户在首次启动时无需用 curl 手动下载模型。它使用了 4.6 节中的 `download_model` 函数，并在控制台上显示进度。

## 4.5 `GET /models` 处理器

它返回模型列表，以及每个模型是否已下载、当前是否被选中的信息。

```cpp
svr.Get("/models",
        [&](const httplib::Request &, httplib::Response &res) {
  auto arr = json::array();
  for (const auto &m : MODELS) {
    auto path = get_models_dir() / m.filename;
    arr.push_back({
      {"name",       m.name},
      {"params",     m.params},
      {"size",       m.size},
      {"downloaded", std::filesystem::exists(path)},
      {"selected",   m.filename == selected_model},
    });
  }
  res.set_content(json{{"models", arr}}.dump(), "application/json");
});
```

## 4.6 下载大文件

GGUF 模型有好几个 GB，因此我们不能把整个文件加载到内存中。通过向 `httplib::Client::Get` 传入回调，我们可以逐块接收数据。

```cpp
// content_receiver：接收数据块的回调
// progress：下载进度回调
cli.Get(url,
  [&](const char *data, size_t len) {       // content_receiver
    ofs.write(data, len);
    return true;  // 返回 false 会中止下载
  },
  [&](size_t current, size_t total) {        // progress
    int pct = total ? (int)(current * 100 / total) : 0;
    std::cout << pct << "%" << std::endl;
    return true;  // 返回 false 会中止下载
  });
```

让我们用它来创建一个从 Hugging Face 下载模型的函数。

```cpp
#include <filesystem>
#include <fstream>

// 下载模型，并通过 progress_cb 报告进度。
// 如果 progress_cb 返回 false，则中止下载。
bool download_model(const ModelInfo &model,
                    std::function<bool(int)> progress_cb) {
  httplib::Client cli("https://huggingface.co");
  cli.set_follow_location(true);
  cli.set_read_timeout(std::chrono::hours(1));

  auto url = "/" + model.repo + "/resolve/main/" + model.filename;
  auto path = get_models_dir() / model.filename;
  auto tmp_path = std::filesystem::path(path).concat(".tmp");

  std::ofstream ofs(tmp_path, std::ios::binary);
  if (!ofs) { return false; }

  auto res = cli.Get(url,
    [&](const char *data, size_t len) {
      ofs.write(data, len);
      return ofs.good();
    },
    [&](size_t current, size_t total) {
      return progress_cb(total ? (int)(current * 100 / total) : 0);
    });

  ofs.close();

  if (!res || res->status != 200) {
    std::filesystem::remove(tmp_path);
    return false;
  }

  // 先写入 .tmp 再重命名，这样即使下载中断，
  // 也不会把不完整的文件误认为可用的模型
  std::filesystem::rename(tmp_path, path);
  return true;
}
```

## 4.7 `/models/select` 处理器

它处理模型选择请求。我们始终以 SSE 响应，并按顺序报告状态：下载进度、加载中、就绪。

```cpp
svr.Post("/models/select",
         [&](const httplib::Request &req, httplib::Response &res) {
  auto input = json::parse(req.body, nullptr, false);
  if (input.is_discarded() || !input.contains("model")) {
    res.status = 400;
    res.set_content(json{{"error", "'model' is required"}}.dump(),
                    "application/json");
    return;
  }

  auto name = input["model"].get<std::string>();

  // 在列表中查找该模型
  auto it = std::find_if(MODELS.begin(), MODELS.end(),
    [&](const ModelInfo &m) { return m.name == name; });

  if (it == MODELS.end()) {
    res.status = 404;
    res.set_content(json{{"error", "Unknown model"}}.dump(),
                    "application/json");
    return;
  }

  const auto &model = *it;

  // 始终以 SSE 响应（无论是否已下载，格式都相同）
  res.set_chunked_content_provider(
      "text/event-stream",
      [&, model](size_t, httplib::DataSink &sink) {
        // SSE 事件发送辅助函数
        auto send = [&](const json &event) {
          sink.os << "data: " << event.dump() << "\n\n";
        };

        // 若尚不存在则下载（通过 SSE 报告进度）
        auto path = get_models_dir() / model.filename;
        if (!std::filesystem::exists(path)) {
          bool ok = download_model(model, [&](int pct) {
            send({{"status", "downloading"}, {"progress", pct}});
            return sink.os.good(); // 客户端断开时中止下载
          });
          if (!ok) {
            send({{"status", "error"}, {"message", "Download failed"}});
            sink.done();
            return true;
          }
        }

        // 加载并切换到该模型
        send({{"status", "loading"}});
        {
          std::lock_guard<std::mutex> lock(llm_mutex);
          llm = llamalib::Llama{path};
          selected_model = model.filename;
        }

        send({{"status", "ready"}});
        sink.done();
        return true;
      });
});
```

几点说明：

- 我们直接从 `download_model` 的进度回调中发送 SSE 事件。这是第 3 章中 `set_chunked_content_provider` + `sink.os` 的一种应用
- 由于回调返回 `sink.os.good()`，当客户端断开时下载会停止。我们在第 5 章添加的取消按钮就利用了这一机制
- 当我们更新 `selected_model` 时，`GET /models` 的 `selected` 标志会反映出来
- `llm` 的重新赋值由 `llm_mutex` 保护。`/translate` 和 `/translate/stream` 处理器也会锁定同一个互斥量，因此在模型切换期间不会执行推理（参见完整代码）

## 4.8 完整代码

以下是在第 3 章代码基础上添加了模型管理的完整代码。

<details>
<summary data-file="CMakeLists.txt">完整代码（CMakeLists.txt）</summary>

```cmake
cmake_minimum_required(VERSION 3.20)
project(translate-server CXX)
set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

# llama.cpp
FetchContent_Declare(llama
    GIT_REPOSITORY https://github.com/ggml-org/llama.cpp
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(llama)

# cpp-httplib
FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib
    GIT_TAG        master
)
FetchContent_MakeAvailable(httplib)

# nlohmann/json
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# cpp-llamalib
FetchContent_Declare(cpp_llamalib
    GIT_REPOSITORY https://github.com/yhirose/cpp-llamalib
    GIT_TAG        main
)
FetchContent_MakeAvailable(cpp_llamalib)

find_package(OpenSSL REQUIRED)

add_executable(translate-server src/main.cpp)

target_link_libraries(translate-server PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    cpp-llamalib
    OpenSSL::SSL OpenSSL::Crypto
)

target_compile_definitions(translate-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)

if(APPLE)
    target_link_libraries(translate-server PRIVATE
        "-framework CoreFoundation"
        "-framework Security"
    )
endif()
```

</details>

<details>
<summary data-file="main.cpp">完整代码（main.cpp）</summary>

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cpp-llamalib.h>

#include <algorithm>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>

using json = nlohmann::json;

// -------------------------------------------------------------------------
// 模型定义
// -------------------------------------------------------------------------

struct ModelInfo {
  std::string name;
  std::string params;
  std::string size;
  std::string repo;
  std::string filename;
};

const std::vector<ModelInfo> MODELS = {
  {
    .name     = "gemma-2-2b-it",
    .params   = "2B",
    .size     = "1.6 GB",
    .repo     = "bartowski/gemma-2-2b-it-GGUF",
    .filename = "gemma-2-2b-it-Q4_K_M.gguf",
  },
  {
    .name     = "gemma-2-9b-it",
    .params   = "9B",
    .size     = "5.8 GB",
    .repo     = "bartowski/gemma-2-9b-it-GGUF",
    .filename = "gemma-2-9b-it-Q4_K_M.gguf",
  },
  {
    .name     = "Llama-3.1-8B-Instruct",
    .params   = "8B",
    .size     = "4.9 GB",
    .repo     = "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
    .filename = "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
  },
};

// -------------------------------------------------------------------------
// 模型存储目录
// -------------------------------------------------------------------------

std::filesystem::path get_models_dir() {
#ifdef _WIN32
  auto env = std::getenv("APPDATA");
  auto base = env ? std::filesystem::path(env) : std::filesystem::path(".");
  return base / "translate-app" / "models";
#else
  auto env = std::getenv("HOME");
  auto base = env ? std::filesystem::path(env) : std::filesystem::path(".");
  return base / ".translate-app" / "models";
#endif
}

// -------------------------------------------------------------------------
// 模型下载
// -------------------------------------------------------------------------

// 如果 progress_cb 返回 false，则中止下载
bool download_model(const ModelInfo &model,
                    std::function<bool(int)> progress_cb) {
  httplib::Client cli("https://huggingface.co");
  cli.set_follow_location(true);  // Hugging Face 会重定向到 CDN
  cli.set_read_timeout(std::chrono::hours(1)); // 为大模型设置较长的超时时间

  auto url = "/" + model.repo + "/resolve/main/" + model.filename;
  auto path = get_models_dir() / model.filename;
  auto tmp_path = std::filesystem::path(path).concat(".tmp");

  std::ofstream ofs(tmp_path, std::ios::binary);
  if (!ofs) { return false; }

  auto res = cli.Get(url,
    // content_receiver：逐块接收数据并写入文件
    [&](const char *data, size_t len) {
      ofs.write(data, len);
      return ofs.good();
    },
    // progress：报告下载进度（返回 false 会中止）
    [&, last_pct = -1](size_t current, size_t total) mutable {
      int pct = total ? (int)(current * 100 / total) : 0;
      if (pct == last_pct) return true; // 数值相同时跳过
      last_pct = pct;
      return progress_cb(pct);
    });

  ofs.close();

  if (!res || res->status != 200) {
    std::filesystem::remove(tmp_path);
    return false;
  }

  // 下载完成后重命名
  std::filesystem::rename(tmp_path, path);
  return true;
}

// -------------------------------------------------------------------------
// 服务器
// -------------------------------------------------------------------------

httplib::Server svr;

void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // 创建模型存储目录
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  // 若默认模型尚不存在，则自动下载
  std::string selected_model = MODELS[0].filename;
  auto path = models_dir / selected_model;
  if (!std::filesystem::exists(path)) {
    std::cout << "Downloading " << selected_model << "..." << std::endl;
    if (!download_model(MODELS[0], [](int pct) {
          std::cout << "\r" << pct << "%" << std::flush;
          return true;
        })) {
      std::cerr << "\nFailed to download model." << std::endl;
      return 1;
    }
    std::cout << std::endl;
  }
  auto llm = llamalib::Llama{path};
  std::mutex llm_mutex; // 在模型切换期间保护访问

  // LLM 推理需要时间，因此设置较长的超时时间（默认为 5 秒）
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // --- 翻译端点（第 2 章）--------------------------------------------------

  svr.Post("/translate",
           [&](const httplib::Request &req, httplib::Response &res) {
    // JSON 解析与校验（详见第 2 章）
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded()) {
      res.status = 400;
      res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                      "application/json");
      return;
    }

    if (!input.contains("text") || !input["text"].is_string() ||
        input["text"].get<std::string>().empty()) {
      res.status = 400;
      res.set_content(json{{"error", "'text' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto text = input["text"].get<std::string>();
    auto target_lang = input.value("target_lang", "ja");

    auto prompt = "Translate the following text to " + target_lang +
                  ". Output only the translation, nothing else.\n\n" + text;

    try {
      std::lock_guard<std::mutex> lock(llm_mutex);
      auto translation = llm.chat(prompt);
      res.set_content(json{{"translation", translation}}.dump(),
                      "application/json");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(json{{"error", e.what()}}.dump(), "application/json");
    }
  });

  // --- SSE 流式翻译（第 3 章）----------------------------------------------

  svr.Post("/translate/stream",
           [&](const httplib::Request &req, httplib::Response &res) {
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded()) {
      res.status = 400;
      res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                      "application/json");
      return;
    }

    if (!input.contains("text") || !input["text"].is_string() ||
        input["text"].get<std::string>().empty()) {
      res.status = 400;
      res.set_content(json{{"error", "'text' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto text = input["text"].get<std::string>();
    auto target_lang = input.value("target_lang", "ja");

    auto prompt = "Translate the following text to " + target_lang +
                  ". Output only the translation, nothing else.\n\n" + text;

    res.set_chunked_content_provider(
        "text/event-stream",
        [&, prompt](size_t, httplib::DataSink &sink) {
          std::lock_guard<std::mutex> lock(llm_mutex);
          try {
            llm.chat(prompt, [&](std::string_view token) {
              sink.os << "data: "
                      << json(std::string(token)).dump(
                           -1, ' ', false, json::error_handler_t::replace)
                      << "\n\n";
              return sink.os.good(); // 客户端断开时中止推理
            });
            sink.os << "data: [DONE]\n\n";
          } catch (const std::exception &e) {
            sink.os << "data: " << json({{"error", e.what()}}).dump() << "\n\n";
          }
          sink.done();
          return true;
        });
  });

  // --- 模型列表（第 4 章）--------------------------------------------------

  svr.Get("/models",
          [&](const httplib::Request &, httplib::Response &res) {
    auto models_dir = get_models_dir();
    auto arr = json::array();
    for (const auto &m : MODELS) {
      auto path = models_dir / m.filename;
      arr.push_back({
        {"name",       m.name},
        {"params",     m.params},
        {"size",       m.size},
        {"downloaded", std::filesystem::exists(path)},
        {"selected",   m.filename == selected_model},
      });
    }
    res.set_content(json{{"models", arr}}.dump(), "application/json");
  });

  // --- 模型选择（第 4 章）--------------------------------------------------

  svr.Post("/models/select",
           [&](const httplib::Request &req, httplib::Response &res) {
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded() || !input.contains("model")) {
      res.status = 400;
      res.set_content(json{{"error", "'model' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto name = input["model"].get<std::string>();

    auto it = std::find_if(MODELS.begin(), MODELS.end(),
      [&](const ModelInfo &m) { return m.name == name; });

    if (it == MODELS.end()) {
      res.status = 404;
      res.set_content(json{{"error", "Unknown model"}}.dump(),
                      "application/json");
      return;
    }

    const auto &model = *it;

    // 始终以 SSE 响应（无论是否已下载，格式都相同）
    res.set_chunked_content_provider(
        "text/event-stream",
        [&, model](size_t, httplib::DataSink &sink) {
          // SSE 事件发送辅助函数
          auto send = [&](const json &event) {
            sink.os << "data: " << event.dump() << "\n\n";
          };

          // 若尚不存在则下载（通过 SSE 报告进度）
          auto path = get_models_dir() / model.filename;
          if (!std::filesystem::exists(path)) {
            bool ok = download_model(model, [&](int pct) {
              send({{"status", "downloading"}, {"progress", pct}});
              return sink.os.good(); // 客户端断开时中止下载
            });
            if (!ok) {
              send({{"status", "error"}, {"message", "Download failed"}});
              sink.done();
              return true;
            }
          }

          // 加载并切换到该模型
          send({{"status", "loading"}});
          {
            std::lock_guard<std::mutex> lock(llm_mutex);
            llm = llamalib::Llama{path};
            selected_model = model.filename;
          }

          send({{"status", "ready"}});
          sink.done();
          return true;
        });
  });

  // 允许通过 `Ctrl+C`（`SIGINT`）或 `kill`（`SIGTERM`）停止服务器
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 4.9 测试

由于我们在 CMakeLists.txt 中添加了 OpenSSL 配置，构建前需要重新运行 CMake。

```bash
cmake -B build
cmake --build build -j
./build/translate-server
```

### 检查模型列表

```bash
curl http://localhost:8080/models
```

在第 1 章下载的 gemma-2-2b-it 模型应显示 `downloaded: true` 和 `selected: true`。

### 切换到其他模型

```bash
curl -N -X POST http://localhost:8080/models/select \
  -H "Content-Type: application/json" \
  -d '{"model": "gemma-2-9b-it"}'
```

下载进度通过 SSE 流式返回，完成后会出现 `"ready"`。

### 比较不同模型的翻译结果

让我们用不同的模型翻译同一句话。

```bash
# 用 gemma-2-9b-it（我们刚切换到的模型）翻译
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "The quick brown fox jumps over the lazy dog.", "target_lang": "ja"}'

# 切换回 gemma-2-2b-it
curl -N -X POST http://localhost:8080/models/select \
  -H "Content-Type: application/json" \
  -d '{"model": "gemma-2-2b-it"}'

# 翻译同一句话
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "The quick brown fox jumps over the lazy dog.", "target_lang": "ja"}'
```

即使代码相同、提示词相同，翻译结果也会因模型而异。由于 cpp-llamalib 会自动为每个模型应用合适的聊天模板，无需修改代码。

## 下一章

服务器的主要功能现已完成：REST API、SSE 流式传输，以及模型下载与切换。在下一章中，我们将添加静态文件服务，并构建一个可在浏览器中使用的 Web UI。

**下一章：** [添加 Web UI](../ch05-web-ui)
