---
title: "6. Turning It into a Desktop App with WebView"
order: 6

---

In Chapter 5, we completed a translation app you can use from a browser. But every time, you have to start the server, open the URL in a browser... Wouldn't it be nice to just double-click and start using it, like a normal app?

In this chapter, we'll do two things:

1. **WebView integration** — Use [webview/webview](https://github.com/webview/webview) to turn it into a desktop app that runs without a browser
2. **Single binary packaging** — Use [cpp-embedlib](https://github.com/yhirose/cpp-embedlib) to embed HTML/CSS/JS into the binary, making the distributable a single file

When finished, you'll be able to just run `./translate-app` to open a window and start translating.

![Desktop App](../app.png#large-center)

The model downloads automatically on first launch, so the only thing you need to give users is the single binary.

## 6.1 Introducing webview/webview

[webview/webview](https://github.com/webview/webview) is a library that lets you use the OS's native WebView component (WKWebView on macOS, WebKitGTK on Linux, WebView2 on Windows) from C/C++. Unlike Electron, it doesn't bundle its own browser, so the impact on binary size is negligible.

We'll fetch it with CMake. Add the following to your `CMakeLists.txt`:

```cmake
# webview/webview
FetchContent_Declare(webview
    GIT_REPOSITORY https://github.com/webview/webview
    GIT_TAG        master
)
FetchContent_MakeAvailable(webview)
```

This makes the `webview::core` CMake target available. When you link it with `target_link_libraries`, it automatically sets up include paths and platform-specific frameworks.

> **macOS**: No additional dependencies are needed. WKWebView is built into the system.
>
> **Linux**: WebKitGTK is required. Install it with `sudo apt install libwebkit2gtk-4.1-dev`.
>
> **Windows**: The WebView2 runtime is required. It comes pre-installed on Windows 11. For Windows 10, download it from the [official Microsoft website](https://developer.microsoft.com/en-us/microsoft-edge/webview2/).

## 6.2 Running the Server on a Background Thread

Up through Chapter 5, the server's `listen()` was blocking the main thread. To use WebView, we need to run the server on a separate thread and run the WebView event loop on the main thread.

```cpp
#include "webview/webview.h"
#include <thread>

int main() {
  // ... (server setup is the same as Chapter 5) ...

  // Start the server on a background thread
  auto port = svr.bind_to_any_port("127.0.0.1");
  std::thread server_thread([&]() { svr.listen_after_bind(); });

  std::cout << "Listening on http://127.0.0.1:" << port << std::endl;

  // Display the UI with WebView
  webview::webview w(false, nullptr);
  w.set_title("Translate App");
  w.set_size(1024, 768, WEBVIEW_HINT_NONE);
  w.navigate("http://127.0.0.1:" + std::to_string(port));
  w.run(); // Block until the window is closed

  // Stop the server when the window is closed
  svr.stop();
  server_thread.join();
}
```

Let's look at the key points:

- **`bind_to_any_port`** — Instead of `listen("127.0.0.1", 8080)`, we let the OS choose an available port. Since desktop apps can be launched multiple times, using a fixed port would cause conflicts
- **`listen_after_bind`** — Starts accepting requests on the port reserved by `bind_to_any_port`. While `listen()` does bind and listen in one call, we need to know the port number first, so we split the operations
- **Shutdown order** — When the WebView window is closed, we stop the server with `svr.stop()` and wait for the thread to finish with `server_thread.join()`. If we reversed the order, WebView would lose access to the server

The `signal_handler` from Chapter 5 is no longer needed. In a desktop app, closing the window means terminating the application.

## 6.3 Embedding Static Files with cpp-embedlib

In Chapter 5, we served files from the `public/` directory, so you'd need to distribute `public/` alongside the binary. With [cpp-embedlib](https://github.com/yhirose/cpp-embedlib), you can embed HTML, CSS, and JavaScript into the binary, packaging the distributable into a single file.

### CMakeLists.txt

Fetch cpp-embedlib and embed `public/`:

```cmake
# cpp-embedlib
FetchContent_Declare(cpp-embedlib
    GIT_REPOSITORY https://github.com/yhirose/cpp-embedlib
    GIT_TAG        main
)
FetchContent_MakeAvailable(cpp-embedlib)

# Embed the public/ directory into the binary
cpp_embedlib_add(WebAssets
    FOLDER    ${CMAKE_CURRENT_SOURCE_DIR}/public
    NAMESPACE Web
)

target_link_libraries(translate-app PRIVATE
    WebAssets                # Embedded files
    cpp-embedlib-httplib     # cpp-httplib integration
)
```

`cpp_embedlib_add` converts the files under `public/` into binary data at compile time and creates a static library called `WebAssets`. When linked, you can access the embedded files through a `Web::FS` object. `cpp-embedlib-httplib` is a helper library that provides the `httplib::mount()` function.

### Replacing set_mount_point with httplib::mount

Simply replace Chapter 5's `set_mount_point` with cpp-embedlib's `httplib::mount`:

```cpp
#include <cpp-embedlib-httplib.h>
#include "WebAssets.h"

// Chapter 5:
// svr.set_mount_point("/", "./public");

// Chapter 6:
httplib::mount(svr, Web::FS);
```

`httplib::mount` registers handlers that serve the files embedded in `Web::FS` over HTTP. MIME types are automatically determined from file extensions, so there's no need to manually set `Content-Type`.

The file contents are directly mapped to the binary's data segment, so no memory copies or heap allocations occur.

## 6.4 macOS: Adding the Edit Menu

If you try to paste text into the input field with `Cmd+V`, you'll find it doesn't work. On macOS, keyboard shortcuts like `Cmd+V` (paste) and `Cmd+C` (copy) are routed through the application's menu bar. Since webview/webview doesn't create one, these shortcuts never reach the WebView. We need to add a macOS Edit menu using the Objective-C runtime:

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

Call this before `w.run()`:

```cpp
#ifdef __APPLE__
  setup_macos_edit_menu();
#endif
  w.run();
```

On Windows and Linux, keyboard shortcuts are delivered directly to the focused control without going through the menu bar, so this workaround is macOS-specific.

## 6.5 Complete Code

<details>
<summary data-file="CMakeLists.txt">Complete code (CMakeLists.txt)</summary>

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

# Embed the public/ directory into the binary
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
<summary data-file="main.cpp">Complete code (main.cpp)</summary>

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
// macOS Edit menu (Cmd+C/V/X/A require an Edit menu on macOS)
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
// Model definitions
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
// Model storage directory
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
// Model download
// -------------------------------------------------------------------------

// Abort the download if progress_cb returns false
bool download_model(const ModelInfo &model,
                    std::function<bool(int)> progress_cb) {
  httplib::Client cli("https://huggingface.co");
  cli.set_follow_location(true);  // Hugging Face redirects to a CDN
  cli.set_read_timeout(std::chrono::hours(1)); // Long timeout for large models

  auto url = "/" + model.repo + "/resolve/main/" + model.filename;
  auto path = get_models_dir() / model.filename;
  auto tmp_path = std::filesystem::path(path).concat(".tmp");

  std::ofstream ofs(tmp_path, std::ios::binary);
  if (!ofs) { return false; }

  auto res = cli.Get(url,
    // content_receiver: Receive data chunk by chunk and write to file
    [&](const char *data, size_t len) {
      ofs.write(data, len);
      return ofs.good();
    },
    // progress: Report download progress (return false to abort)
    [&, last_pct = -1](size_t current, size_t total) mutable {
      int pct = total ? (int)(current * 100 / total) : 0;
      if (pct == last_pct) return true; // Skip if the value hasn't changed
      last_pct = pct;
      return progress_cb(pct);
    });

  ofs.close();

  if (!res || res->status != 200) {
    std::filesystem::remove(tmp_path);
    return false;
  }

  // Rename after download completes
  std::filesystem::rename(tmp_path, path);
  return true;
}

// -------------------------------------------------------------------------
// Server
// -------------------------------------------------------------------------

int main() {
  httplib::Server svr;
  // Create the model storage directory
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  // Auto-download the default model if not already present
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
  std::mutex llm_mutex; // Protect access during model switching

  // Set a long timeout since LLM inference takes time (default is 5 seconds)
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // --- Translation endpoint (Chapter 2) ------------------------------------

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

  // --- SSE streaming translation (Chapter 3) -------------------------------

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
              return sink.os.good(); // Abort inference on disconnect
            });
            sink.os << "data: [DONE]\n\n";
          } catch (const std::exception &e) {
            sink.os << "data: " << json({{"error", e.what()}}).dump() << "\n\n";
          }
          sink.done();
          return true;
        });
  });

  // --- Model list (Chapter 4) ----------------------------------------------

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

  // --- Model selection (Chapter 4) -----------------------------------------

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

    // Always respond with SSE (same format whether downloaded or not)
    res.set_chunked_content_provider(
        "text/event-stream",
        [&, model](size_t, httplib::DataSink &sink) {
          // SSE event sending helper
          auto send = [&](const json &event) {
            sink.os << "data: " << event.dump() << "\n\n";
          };

          // Download if not yet downloaded (report progress via SSE)
          auto path = get_models_dir() / model.filename;
          if (!std::filesystem::exists(path)) {
            bool ok = download_model(model, [&](int pct) {
              send({{"status", "downloading"}, {"progress", pct}});
              return sink.os.good(); // Abort download on client disconnect
            });
            if (!ok) {
              send({{"status", "error"}, {"message", "Download failed"}});
              sink.done();
              return true;
            }
          }

          // Load and switch to the model
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

  // --- Embedded file serving (Chapter 6) ------------------------------------
  // Chapter 5: svr.set_mount_point("/", "./public");
  httplib::mount(svr, Web::FS);

  // Start the server on a background thread
  auto port = svr.bind_to_any_port("127.0.0.1");
  std::thread server_thread([&]() { svr.listen_after_bind(); });

  std::cout << "Listening on http://127.0.0.1:" << port << std::endl;

  // Display the UI with WebView
  webview::webview w(false, nullptr);
  w.set_title("Translate App");
  w.set_size(1024, 768, WEBVIEW_HINT_NONE);
  w.navigate("http://127.0.0.1:" + std::to_string(port));

#ifdef __APPLE__
  setup_macos_edit_menu();
#endif
  w.run(); // Block until the window is closed

  // Stop the server when the window is closed
  svr.stop();
  server_thread.join();
}
```

</details>

To summarize the changes from Chapter 5:

- `#include <csignal>` replaced with `#include <thread>`, `<cpp-embedlib-httplib.h>`, `"WebAssets.h"`, `"webview/webview.h"`
- Removed the `signal_handler` function
- `svr.set_mount_point("/", "./public")` replaced with `httplib::mount(svr, Web::FS)`
- `svr.listen("127.0.0.1", 8080)` replaced with `bind_to_any_port` + `listen_after_bind` + WebView event loop

Not a single line of handler code has changed. The REST API, SSE streaming, and model management built through Chapter 5 all work as-is.

## 6.6 Building and Testing

```bash
cmake -B build
cmake --build build -j
```

Launch the app:

```bash
./build/translate-app
```

No browser is needed. A window opens automatically. The same UI from Chapter 5 appears as-is, and translation and model switching all work just the same.

When you close the window, the server shuts down automatically. There's no need for `Ctrl+C`.

### What Needs to Be Distributed

You only need to distribute:

- The single `translate-app` binary

That's it. You don't need the `public/` directory. HTML, CSS, and JavaScript are embedded in the binary. Model files download automatically on first launch, so there's no need to ask users to prepare anything in advance.

## Next Chapter

Congratulations! 🎉

In Chapter 1, `/health` just returned `{"status":"ok"}`. Now we have a desktop app where you type text and translations stream in real time, pick a different model from a dropdown and it downloads automatically, and closing the window cleanly shuts everything down — all in a single distributable binary.

What we changed in this chapter was just the static file serving and the server startup. Not a single line of handler code changed. The REST API, SSE streaming, and model management we built through Chapter 5 all work as a desktop app, as-is.

In the next chapter, we'll shift perspective and read through the code of llama.cpp's own `llama-server`. Let's compare our simple server with a production-quality one and see what design decisions differ and why.

**Next:** [Reading the llama.cpp Server Source Code](../ch07-code-reading)
