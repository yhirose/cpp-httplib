---
title: "6. 使用 WebView 将其打造成桌面应用"
order: 6

---

在第 5 章中，我们完成了一个可以在浏览器中使用的翻译应用。但每次都要启动服务器、在浏览器中打开 URL……如果能像普通应用一样双击就能直接使用，岂不是更好？

在本章中，我们将做两件事：

1. **WebView 集成** — 使用 [webview/webview](https://github.com/webview/webview) 将其打造成无需浏览器即可运行的桌面应用
2. **单一二进制打包** — 使用 [cpp-embedlib](https://github.com/yhirose/cpp-embedlib) 将 HTML/CSS/JS 嵌入二进制文件，使分发包成为单个文件

完成后，你只需运行 `./translate-app` 即可打开窗口并开始翻译。

![Desktop App](../app.png#large-center)

模型会在首次启动时自动下载，因此你唯一需要交给用户的就是这个单一二进制文件。

## 6.1 引入 webview/webview

[webview/webview](https://github.com/webview/webview) 是一个让你可以从 C/C++ 使用操作系统原生 WebView 组件（macOS 上的 WKWebView、Linux 上的 WebKitGTK、Windows 上的 WebView2）的库。与 Electron 不同，它不会打包自己的浏览器，因此对二进制体积的影响可以忽略不计。

我们将用 CMake 获取它。将以下内容添加到你的 `CMakeLists.txt` 中：

```cmake
# webview/webview
FetchContent_Declare(webview
    GIT_REPOSITORY https://github.com/webview/webview
    GIT_TAG        master
)
FetchContent_MakeAvailable(webview)
```

这会提供 `webview::core` 这个 CMake target。当你用 `target_link_libraries` 链接它时，它会自动设置 include 路径和平台特定的 framework。

> **macOS**：无需额外的依赖。WKWebView 内置于系统中。
>
> **Linux**：需要 WebKitGTK。使用 `sudo apt install libwebkit2gtk-4.1-dev` 安装。
>
> **Windows**：需要 WebView2 运行时。Windows 11 已预装。对于 Windows 10，请从 [Microsoft 官方网站](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) 下载。

## 6.2 在后台线程中运行服务器

直到第 5 章，服务器的 `listen()` 一直阻塞着主线程。要使用 WebView，我们需要在单独的线程上运行服务器，并在主线程上运行 WebView 事件循环。

```cpp
#include "webview/webview.h"
#include <thread>

int main() {
  // ...（服务器设置与第 5 章相同）...

  // 在后台线程中启动服务器
  auto port = svr.bind_to_any_port("127.0.0.1");
  std::thread server_thread([&]() { svr.listen_after_bind(); });

  std::cout << "Listening on http://127.0.0.1:" << port << std::endl;

  // 使用 WebView 显示 UI
  webview::webview w(false, nullptr);
  w.set_title("Translate App");
  w.set_size(1024, 768, WEBVIEW_HINT_NONE);
  w.navigate("http://127.0.0.1:" + std::to_string(port));
  w.run(); // 阻塞直到窗口关闭

  // 窗口关闭时停止服务器
  svr.stop();
  server_thread.join();
}
```

让我们看看关键点：

- **`bind_to_any_port`** — 我们不再使用 `listen("127.0.0.1", 8080)`，而是让操作系统选择一个可用端口。由于桌面应用可能被多次启动，使用固定端口会导致冲突
- **`listen_after_bind`** — 在 `bind_to_any_port` 预留的端口上开始接受请求。虽然 `listen()` 会在一次调用中完成绑定和监听，但我们需要先知道端口号，因此将操作拆分
- **关闭顺序** — 当 WebView 窗口关闭时，我们用 `svr.stop()` 停止服务器，并用 `server_thread.join()` 等待线程结束。如果颠倒顺序，WebView 将无法访问服务器

第 5 章中的 `signal_handler` 不再需要了。在桌面应用中，关闭窗口就意味着终止应用。

## 6.3 使用 cpp-embedlib 嵌入静态文件

在第 5 章中，我们从 `public/` 目录提供文件，因此需要将 `public/` 与二进制文件一起分发。借助 [cpp-embedlib](https://github.com/yhirose/cpp-embedlib)，你可以将 HTML、CSS 和 JavaScript 嵌入二进制文件，从而将分发包打包成单个文件。

### CMakeLists.txt

获取 cpp-embedlib 并嵌入 `public/`：

```cmake
# cpp-embedlib
FetchContent_Declare(cpp-embedlib
    GIT_REPOSITORY https://github.com/yhirose/cpp-embedlib
    GIT_TAG        main
)
FetchContent_MakeAvailable(cpp-embedlib)

# 将 public/ 目录嵌入到二进制文件中
cpp_embedlib_add(WebAssets
    FOLDER    ${CMAKE_CURRENT_SOURCE_DIR}/public
    NAMESPACE Web
)

target_link_libraries(translate-app PRIVATE
    WebAssets                # 嵌入的文件
    cpp-embedlib-httplib     # cpp-httplib 集成
)
```

`cpp_embedlib_add` 会在编译时将 `public/` 下的文件转换为二进制数据，并创建一个名为 `WebAssets` 的静态库。链接后，你可以通过 `Web::FS` 对象访问嵌入的文件。`cpp-embedlib-httplib` 是一个辅助库，提供 `httplib::mount()` 函数。

### 用 httplib::mount 替换 set_mount_point

只需将第 5 章的 `set_mount_point` 替换为 cpp-embedlib 的 `httplib::mount`：

```cpp
#include <cpp-embedlib-httplib.h>
#include "WebAssets.h"

// 第 5 章：
// svr.set_mount_point("/", "./public");

// 第 6 章：
httplib::mount(svr, Web::FS);
```

`httplib::mount` 注册的处理器会通过 HTTP 提供嵌入在 `Web::FS` 中的文件。MIME 类型会根据文件扩展名自动确定，因此无需手动设置 `Content-Type`。

文件内容会被直接映射到二进制文件的数据段，因此不会发生内存拷贝或堆分配。

## 6.4 macOS：添加编辑菜单

如果你尝试用 `Cmd+V` 将文本粘贴到输入框中，你会发现它不起作用。在 macOS 上，诸如 `Cmd+V`（粘贴）和 `Cmd+C`（复制）之类的键盘快捷键是通过应用的菜单栏路由的。由于 webview/webview 不会创建菜单栏，这些快捷键永远不会到达 WebView。我们需要使用 Objective-C 运行时来添加一个 macOS 编辑菜单：

```cpp
#ifdef __APPLE__
#include <objc/objc-runtime.h>

void setup_macos_edit_menu() {
  auto cls    = [](const char *n) { return (id)objc_getClass(n); };
  auto sel    = sel_registerName;
  auto msg    = reinterpret_cast<id (*)(id, SEL)>(objc_msgSend);
  auto msg_s  = reinterpret_cast<id (*)(id, SEL, const char *)>(objc_msgSend);
  auto msg_id = reinterpret_cast<id (*)(id, SEL, id)>(objc_msgSend);
  auto msg_v  = reinterpret_cast<void (*)(id, SEL, id)>(objc_msgSend);
  auto msg_mi = reinterpret_cast<id (*)(id, SEL, id, SEL, id)>(objc_msgSend);

  auto str = [&](const char *s) {
    return msg_s(cls("NSString"), sel("stringWithUTF8String:"), s);
  };

  id app      = msg(cls("NSApplication"), sel("sharedApplication"));
  id mainMenu = msg(msg(cls("NSMenu"), sel("alloc")), sel("init"));
  id editItem = msg(msg(cls("NSMenuItem"), sel("alloc")), sel("init"));
  id editMenu = msg_id(msg(cls("NSMenu"), sel("alloc")),
                       sel("initWithTitle:"), str("Edit"));

  struct { const char *title; const char *action; const char *key; } items[] = {
    {"Undo",       "undo:",      "z"},
    {"Redo",       "redo:",      "Z"},
    {"Cut",        "cut:",       "x"},
    {"Copy",       "copy:",      "c"},
    {"Paste",      "paste:",     "v"},
    {"Select All", "selectAll:", "a"},
  };

  for (auto &[title, action, key] : items) {
    id mi = msg_mi(msg(cls("NSMenuItem"), sel("alloc")),
                   sel("initWithTitle:action:keyEquivalent:"),
                   str(title), sel(action), str(key));
    msg_v(editMenu, sel("addItem:"), mi);
  }

  msg_v(editItem, sel("setSubmenu:"), editMenu);
  msg_v(mainMenu, sel("addItem:"), editItem);
  msg_v(app, sel("setMainMenu:"), mainMenu);
}
#endif
```

在 `w.run()` 之前调用它：

```cpp
#ifdef __APPLE__
  setup_macos_edit_menu();
#endif
  w.run();
```

在 Windows 和 Linux 上，键盘快捷键会直接传递给当前聚焦的控件，而无需经过菜单栏，因此这个变通方法是 macOS 特有的。

## 6.5 完整代码

<details>
<summary data-file="CMakeLists.txt">完整代码（CMakeLists.txt）</summary>

```cmake
cmake_minimum_required(VERSION 3.20)
project(translate-app CXX)
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

# webview/webview
FetchContent_Declare(webview
    GIT_REPOSITORY https://github.com/webview/webview
    GIT_TAG        master
)
FetchContent_MakeAvailable(webview)

# cpp-embedlib
FetchContent_Declare(cpp-embedlib
    GIT_REPOSITORY https://github.com/yhirose/cpp-embedlib
    GIT_TAG        main
)
FetchContent_MakeAvailable(cpp-embedlib)

# 将 public/ 目录嵌入到二进制文件中
cpp_embedlib_add(WebAssets
    FOLDER    ${CMAKE_CURRENT_SOURCE_DIR}/public
    NAMESPACE Web
)

find_package(OpenSSL REQUIRED)

add_executable(translate-app src/main.cpp)

target_link_libraries(translate-app PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    cpp-llamalib
    OpenSSL::SSL OpenSSL::Crypto
    WebAssets
    cpp-embedlib-httplib
    webview::core
)

if(APPLE)
    target_link_libraries(translate-app PRIVATE
        "-framework CoreFoundation"
        "-framework Security"
    )
endif()

target_compile_definitions(translate-app PRIVATE
    CPPHTTPLIB_OPENSSL_SUPPORT
)
```

</details>

<details>
<summary data-file="main.cpp">完整代码（main.cpp）</summary>

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cpp-llamalib.h>
#include <cpp-embedlib-httplib.h>
#include "WebAssets.h"
#include "webview/webview.h"

#ifdef __APPLE__
#include <objc/objc-runtime.h>
#endif

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>

using json = nlohmann::json;

// -------------------------------------------------------------------------
// macOS 编辑菜单（在 macOS 上 Cmd+C/V/X/A 需要编辑菜单）
// -------------------------------------------------------------------------

#ifdef __APPLE__
void setup_macos_edit_menu() {
  auto cls    = [](const char *n) { return (id)objc_getClass(n); };
  auto sel    = sel_registerName;
  auto msg    = reinterpret_cast<id (*)(id, SEL)>(objc_msgSend);
  auto msg_s  = reinterpret_cast<id (*)(id, SEL, const char *)>(objc_msgSend);
  auto msg_id = reinterpret_cast<id (*)(id, SEL, id)>(objc_msgSend);
  auto msg_v  = reinterpret_cast<void (*)(id, SEL, id)>(objc_msgSend);
  auto msg_mi = reinterpret_cast<id (*)(id, SEL, id, SEL, id)>(objc_msgSend);

  auto str = [&](const char *s) {
    return msg_s(cls("NSString"), sel("stringWithUTF8String:"), s);
  };

  id app      = msg(cls("NSApplication"), sel("sharedApplication"));
  id mainMenu = msg(msg(cls("NSMenu"), sel("alloc")), sel("init"));
  id editItem = msg(msg(cls("NSMenuItem"), sel("alloc")), sel("init"));
  id editMenu = msg_id(msg(cls("NSMenu"), sel("alloc")),
                       sel("initWithTitle:"), str("Edit"));

  struct { const char *title; const char *action; const char *key; } items[] = {
    {"Undo",       "undo:",      "z"},
    {"Redo",       "redo:",      "Z"},
    {"Cut",        "cut:",       "x"},
    {"Copy",       "copy:",      "c"},
    {"Paste",      "paste:",     "v"},
    {"Select All", "selectAll:", "a"},
  };

  for (auto &[title, action, key] : items) {
    id mi = msg_mi(msg(cls("NSMenuItem"), sel("alloc")),
                   sel("initWithTitle:action:keyEquivalent:"),
                   str(title), sel(action), str(key));
    msg_v(editMenu, sel("addItem:"), mi);
  }

  msg_v(editItem, sel("setSubmenu:"), editMenu);
  msg_v(mainMenu, sel("addItem:"), editItem);
  msg_v(app, sel("setMainMenu:"), mainMenu);
}
#endif

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
  cli.set_read_timeout(std::chrono::hours(1)); // 针对大模型使用较长的超时时间

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
    // progress：报告下载进度（返回 false 以中止）
    [&, last_pct = -1](size_t current, size_t total) mutable {
      int pct = total ? (int)(current * 100 / total) : 0;
      if (pct == last_pct) return true; // 如果值没有变化则跳过
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

int main() {
  httplib::Server svr;
  // 创建模型存储目录
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  // 如果默认模型尚不存在则自动下载
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
  std::mutex llm_mutex; // 在切换模型时保护访问

  // 由于 LLM 推理需要时间，因此设置较长的超时时间（默认为 5 秒）
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // --- 翻译端点（第 2 章） -------------------------------------------------

  svr.Post("/translate",
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

  // --- SSE 流式翻译（第 3 章） ---------------------------------------------

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
              return sink.os.good(); // 客户端断开连接时中止推理
            });
            sink.os << "data: [DONE]\n\n";
          } catch (const std::exception &e) {
            sink.os << "data: " << json({{"error", e.what()}}).dump() << "\n\n";
          }
          sink.done();
          return true;
        });
  });

  // --- 模型列表（第 4 章） -------------------------------------------------

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

  // --- 模型选择（第 4 章） -------------------------------------------------

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

    // 始终以 SSE 响应（无论是否已下载都使用相同格式）
    res.set_chunked_content_provider(
        "text/event-stream",
        [&, model](size_t, httplib::DataSink &sink) {
          // SSE 事件发送辅助函数
          auto send = [&](const json &event) {
            sink.os << "data: " << event.dump() << "\n\n";
          };

          // 如果尚未下载则下载（通过 SSE 报告进度）
          auto path = get_models_dir() / model.filename;
          if (!std::filesystem::exists(path)) {
            bool ok = download_model(model, [&](int pct) {
              send({{"status", "downloading"}, {"progress", pct}});
              return sink.os.good(); // 客户端断开连接时中止下载
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

  // --- 嵌入文件服务（第 6 章） ----------------------------------------------
  // 第 5 章：svr.set_mount_point("/", "./public");
  httplib::mount(svr, Web::FS);

  // 在后台线程中启动服务器
  auto port = svr.bind_to_any_port("127.0.0.1");
  std::thread server_thread([&]() { svr.listen_after_bind(); });

  std::cout << "Listening on http://127.0.0.1:" << port << std::endl;

  // 使用 WebView 显示 UI
  webview::webview w(false, nullptr);
  w.set_title("Translate App");
  w.set_size(1024, 768, WEBVIEW_HINT_NONE);
  w.navigate("http://127.0.0.1:" + std::to_string(port));

#ifdef __APPLE__
  setup_macos_edit_menu();
#endif
  w.run(); // 阻塞直到窗口关闭

  // 窗口关闭时停止服务器
  svr.stop();
  server_thread.join();
}
```

</details>

总结一下相对第 5 章的改动：

- `#include <csignal>` 替换为 `#include <thread>`、`<cpp-embedlib-httplib.h>`、`"WebAssets.h"`、`"webview/webview.h"`
- 移除了 `signal_handler` 函数
- `svr.set_mount_point("/", "./public")` 替换为 `httplib::mount(svr, Web::FS)`
- `svr.listen("127.0.0.1", 8080)` 替换为 `bind_to_any_port` + `listen_after_bind` + WebView 事件循环

没有一行处理程序代码发生改变。贯穿第 5 章构建的 REST API、SSE 流式传输和模型管理都能原样工作。

## 6.6 构建与测试

```bash
cmake -B build
cmake --build build -j
```

启动应用：

```bash
./build/translate-app
```

无需浏览器。窗口会自动打开。第 5 章的同一个 UI 会原样出现，翻译和模型切换的工作方式完全相同。

当你关闭窗口时，服务器会自动关闭。无需 `Ctrl+C`。

### 需要分发的内容

你只需要分发：

- 单个 `translate-app` 二进制文件

就是这样。你不需要 `public/` 目录。HTML、CSS 和 JavaScript 都已嵌入二进制文件。模型文件会在首次启动时自动下载，因此无需让用户提前准备任何东西。

## 下一章

恭喜！🎉

在第 1 章中，`/health` 只是返回 `{"status":"ok"}`。现在我们有了一个桌面应用：输入文本，翻译会实时流式输出；从下拉菜单中选择另一个模型，它会自动下载；关闭窗口即可干净地关闭一切 —— 所有这些都在一个可分发的二进制文件中。

我们在本章中改动的只是静态文件服务和服务器启动部分。没有一行处理程序代码发生改变。我们贯穿第 5 章构建的 REST API、SSE 流式传输和模型管理都能作为桌面应用原样工作。

在下一章中，我们将转换视角，通读 llama.cpp 自带的 `llama-server` 的代码。让我们把我们这个简单的服务器与生产级的服务器进行比较，看看有哪些设计决策不同，以及原因何在。

**下一篇：** [阅读 llama.cpp 服务器源码](../ch07-code-reading)
