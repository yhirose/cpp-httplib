---
title: "1. Setting Up the Project Environment"
order: 1

---

Let's incrementally build a text translation REST API server using llama.cpp as the inference engine. By the end, a request like this will return a translation result.

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

The "Translation API" is just one example. By swapping out the prompt, you can adapt this to any LLM application you like, such as summarization, code generation, or a chatbot.

Here's the full list of APIs the server will provide.

| Method | Path | Description | Chapter |
| -------- | ---- | ---- | -- |
| `GET` | `/health` | Returns server status | 1 |
| `POST` | `/translate` | Translates text and returns JSON | 2 |
| `POST` | `/translate/stream` | SSE streaming on a per-token basis | 3 |
| `GET` | `/models` | Model list (available / downloaded / selected) | 4 |
| `POST` | `/models/select` | Select a model (automatically downloads if not yet downloaded) | 4 |

In this chapter, let's set up the project environment. We'll fetch the dependency libraries, create the directory structure, configure the build settings, and grab the model file, so that we're ready to start writing code in the next chapter.

## Prerequisites

- A C++20-compatible compiler (GCC 10+, Clang 10+, MSVC 2019 16.8+)
- CMake 3.20 or later
- OpenSSL (used for the HTTPS client in Chapter 4. macOS: `brew install openssl`, Ubuntu: `sudo apt install libssl-dev`)
- Sufficient disk space (model files can be several GB)

## 1.1 What We Will Use

Here are the libraries we'll use.

| Library | Role |
| ----------- | ------ |
| [cpp-httplib](https://github.com/yhirose/cpp-httplib) | HTTP server/client |
| [nlohmann/json](https://github.com/nlohmann/json) | JSON parser |
| [cpp-llamalib](https://github.com/yhirose/cpp-llamalib) | llama.cpp wrapper |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) | LLM inference engine |
| [webview/webview](https://github.com/webview/webview) | Desktop WebView (used in Chapter 6) |

cpp-httplib, nlohmann/json, and cpp-llamalib are header-only libraries. You could just download a single header file with `curl` and `#include` it, but in this book we use CMake's `FetchContent` to fetch them automatically. Declare them in `CMakeLists.txt`, and `cmake -B build` downloads and builds everything for you. webview is used in Chapter 6, so you don't need to worry about it for now.

## 1.2 Directory Structure

The final structure will look like this.

```ascii
translate-app/
├── CMakeLists.txt
├── models/
│   └── (GGUF files)
└── src/
    └── main.cpp
```

We don't include library source code in the project. CMake's `FetchContent` fetches them automatically at build time, so all you need is your own code.

Let's create the project directory and initialize a git repository.

```bash
mkdir translate-app && cd translate-app
mkdir src models
git init
```

## 1.3 Obtaining the GGUF Model File

You need a model file for LLM inference. GGUF is the model format used by llama.cpp, and you can find many models on Hugging Face.

Let's start by trying a small model. The quantized version of Google's Gemma 2 2B (~1.6 GB) is a good starting point. It's lightweight but supports multiple languages and works well for translation tasks.

```bash
curl -L -o models/gemma-2-2b-it-Q4_K_M.gguf \
  https://huggingface.co/bartowski/gemma-2-2b-it-GGUF/resolve/main/gemma-2-2b-it-Q4_K_M.gguf
```

In Chapter 4, we'll add the ability to download models from within the app using cpp-httplib's client functionality.

## 1.4 CMakeLists.txt

Create a `CMakeLists.txt` in the project root. By declaring dependencies with `FetchContent`, CMake will automatically download and build them for you.

<!-- data-file="CMakeLists.txt" -->
```cmake
cmake_minimum_required(VERSION 3.20)
project(translate-server CXX)
set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

# llama.cpp (LLM inference engine)
FetchContent_Declare(llama
    GIT_REPOSITORY https://github.com/ggml-org/llama.cpp
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(llama)

# cpp-httplib (HTTP server/client)
FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib
    GIT_TAG        master
)
FetchContent_MakeAvailable(httplib)

# nlohmann/json (JSON parser)
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# cpp-llamalib (header-only llama.cpp wrapper)
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

`FetchContent_Declare` tells CMake where to find each library, and `FetchContent_MakeAvailable` fetches and builds them. The first `cmake -B build` will take some time because it downloads all libraries and builds llama.cpp, but subsequent runs will use the cache.

Just link with `target_link_libraries`, and each library's CMake configuration sets up include paths and build settings for you.

## 1.5 Creating the Skeleton Code

We'll use this skeleton code as a base and add functionality chapter by chapter.

<!-- data-file="main.cpp" -->
```cpp
// src/main.cpp
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <csignal>
#include <iostream>

using json = nlohmann::json;

httplib::Server svr;

// Graceful shutdown on `Ctrl+C`
void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // Log requests and responses
  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  // Health check
  svr.Get("/health", [](const auto &, auto &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // Stub implementations for each endpoint (replaced with real ones in later chapters)
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

  // Allow the server to be stopped with `Ctrl+C` (`SIGINT`) or `kill` (`SIGTERM`)
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // Start the server
  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

## 1.6 Building and Verifying

Build the project, start the server, and verify that requests work with curl.

```bash
cmake -B build
cmake --build build -j
./build/translate-server
```

From another terminal, try it with curl.

```bash
curl http://localhost:8080/health
# => {"status":"ok"}
```

If you see JSON come back, the setup is complete.

## Next Chapter

Now that the environment is set up, in the next chapter we'll implement the translation REST API on top of this skeleton. We'll run inference with llama.cpp and expose it as an HTTP endpoint with cpp-httplib.

**Next:** [Integrating llama.cpp to Build a REST API](../ch02-rest-api)
