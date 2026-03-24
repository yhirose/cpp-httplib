---
title: "4. Adding Model Download and Management"
order: 4

---

By the end of Chapter 3, the server's translation functionality was fully in place. However, the only model file available is the one we manually downloaded in Chapter 1. In this chapter, we'll use cpp-httplib's **client functionality** to enable downloading and switching Hugging Face models from within the app.

Once complete, you'll be able to manage models with requests like these:

```bash
# Get the list of available models
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
# Select a different model (automatically downloads if not yet available)
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

## 4.1 httplib::Client Basics

So far we've only used `httplib::Server`, but cpp-httplib also provides client functionality. Since Hugging Face uses HTTPS, we need a TLS-capable client.

```cpp
#include <httplib.h>

// Including the URL scheme automatically uses SSLClient
httplib::Client cli("https://huggingface.co");

// Automatically follow redirects (Hugging Face redirects to a CDN)
cli.set_follow_location(true);

auto res = cli.Get("/api/models");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

To use HTTPS, you need to enable OpenSSL at build time. Add the following line to your `CMakeLists.txt`:

```cmake
set(HTTPLIB_REQUIRE_OPENSSL true)
FetchContent_Declare(httplib ...)
```

Defining `HTTPLIB_OPENSSL_SUPPORT` enables `httplib::Client("https://...")` to make TLS connections.

## 4.2 Defining the Model List

Let's define the list of models that the app can handle. Here are four models we've verified for translation tasks.

```cpp
struct ModelInfo {
  std::string name;       // Display name
  std::string params;     // Parameter count
  std::string size;       // GGUF Q4 size
  std::string repo;       // Hugging Face repository
  std::string filename;   // GGUF filename
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

## 4.3 Model Storage Location

Up through Chapter 3, we stored models in the `models/` directory within the project. However, when managing multiple models, a dedicated app directory makes more sense. On macOS/Linux we use `~/.translate-app/models/`, and on Windows we use `%APPDATA%\translate-app\models\`.

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

If the environment variable isn't set, it falls back to the current directory. The app creates this directory at startup (`create_directories` won't error even if it already exists).

## 4.4 Rewriting Model Initialization

We rewrite the model initialization at the beginning of `main()`. In Chapter 1 we hardcoded the path, but from here on we support model switching. We track the currently loaded filename in `selected_model` and load the first entry in `MODELS` at startup. The `GET /models` and `POST /models/select` handlers reference and update this variable.

Since cpp-httplib runs handlers concurrently on a thread pool, reassigning `llm` while another thread is calling `llm.chat()` would crash. We add a `std::mutex` to protect against this.

```cpp
int main() {
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  std::string selected_model = MODELS[0].filename;
  auto path = models_dir / selected_model;

  // Automatically download the default model if not yet present
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
  // ...
}
```

This ensures that users don't need to manually download models with curl on first launch. It uses the `download_model` function from Section 4.6 and displays progress on the console.

## 4.5 The `GET /models` Handler

This returns the model list with information about whether each model has been downloaded and whether it's currently selected.

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

## 4.6 Downloading Large Files

GGUF models are several gigabytes, so we can't load the entire file into memory. By passing callbacks to `httplib::Client::Get`, we can receive data chunk by chunk.

```cpp
// content_receiver: callback that receives data chunks
// progress: download progress callback
cli.Get(url,
  [&](const char *data, size_t len) {       // content_receiver
    ofs.write(data, len);
    return true;  // returning false aborts the download
  },
  [&](size_t current, size_t total) {        // progress
    int pct = total ? (int)(current * 100 / total) : 0;
    std::cout << pct << "%" << std::endl;
    return true;  // returning false aborts the download
  });
```

Let's use this to create a function that downloads models from Hugging Face.

```cpp
#include <filesystem>
#include <fstream>

// Download a model and report progress via progress_cb.
// If progress_cb returns false, the download is aborted.
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

  // Write to .tmp first, then rename, so that an incomplete file
  // is never mistaken for a usable model if the download is interrupted
  std::filesystem::rename(tmp_path, path);
  return true;
}
```

## 4.7 The `/models/select` Handler

This handles model selection requests. We always respond with SSE, reporting status in sequence: download progress, loading, and ready.

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

  // Find the model in the list
  auto it = std::find_if(MODELS.begin(), MODELS.end(),
    [&](const ModelInfo &m) { return m.name == name; });

  if (it == MODELS.end()) {
    res.status = 404;
    res.set_content(json{{"error", "Unknown model"}}.dump(),
                    "application/json");
    return;
  }

  const auto &model = *it;

  // Always respond with SSE (same format whether already downloaded or not)
  res.set_chunked_content_provider(
      "text/event-stream",
      [&, model](size_t, httplib::DataSink &sink) {
        // SSE event sending helper
        auto send = [&](const json &event) {
          sink.os << "data: " << event.dump() << "\n\n";
        };

        // Download if not yet present (report progress via SSE)
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
```

A few notes:

- We send SSE events directly from the `download_model` progress callback. This is an application of `set_chunked_content_provider` + `sink.os` from Chapter 3
- Since the callback returns `sink.os.good()`, the download stops if the client disconnects. The cancel button we add in Chapter 5 uses this
- When we update `selected_model`, it's reflected in the `selected` flag of `GET /models`
- The `llm` reassignment is protected by `llm_mutex`. The `/translate` and `/translate/stream` handlers also lock the same mutex, so inference can't run during a model switch (see the complete code)

## 4.8 Complete Code

Here is the complete code with model management added to the Chapter 3 code.

<details>
<summary data-file="CMakeLists.txt">Complete code (CMakeLists.txt)</summary>

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
set(HTTPLIB_REQUIRE_OPENSSL true)
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

add_executable(translate-server src/main.cpp)

target_link_libraries(translate-server PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    cpp-llamalib
)
```

</details>

<details>
<summary data-file="main.cpp">Complete code (main.cpp)</summary>

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

// If progress_cb returns false, the download is aborted
bool download_model(const ModelInfo &model,
                    std::function<bool(int)> progress_cb) {
  httplib::Client cli("https://huggingface.co");
  cli.set_follow_location(true);  // Hugging Face redirects to a CDN
  cli.set_read_timeout(std::chrono::hours(1)); // Set a long timeout for large models

  auto url = "/" + model.repo + "/resolve/main/" + model.filename;
  auto path = get_models_dir() / model.filename;
  auto tmp_path = std::filesystem::path(path).concat(".tmp");

  std::ofstream ofs(tmp_path, std::ios::binary);
  if (!ofs) { return false; }

  auto res = cli.Get(url,
    // content_receiver: receive data chunk by chunk and write to file
    [&](const char *data, size_t len) {
      ofs.write(data, len);
      return ofs.good();
    },
    // progress: report download progress (returning false aborts)
    [&, last_pct = -1](size_t current, size_t total) mutable {
      int pct = total ? (int)(current * 100 / total) : 0;
      if (pct == last_pct) return true; // Skip if same value
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

httplib::Server svr;

void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // Create the model storage directory
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  // Automatically download the default model if not yet present
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
    // JSON parsing and validation (see Chapter 2 for details)
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

    // Always respond with SSE (same format whether already downloaded or not)
    res.set_chunked_content_provider(
        "text/event-stream",
        [&, model](size_t, httplib::DataSink &sink) {
          // SSE event sending helper
          auto send = [&](const json &event) {
            sink.os << "data: " << event.dump() << "\n\n";
          };

          // Download if not yet present (report progress via SSE)
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

  // Allow the server to be stopped with `Ctrl+C` (`SIGINT`) or `kill` (`SIGTERM`)
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 4.9 Testing

Since we added OpenSSL configuration to CMakeLists.txt, we need to re-run CMake before building.

```bash
cmake -B build
cmake --build build -j
./build/translate-server
```

### Checking the Model List

```bash
curl http://localhost:8080/models
```

The gemma-2-2b-it model downloaded in Chapter 1 should show `downloaded: true` and `selected: true`.

### Switching to a Different Model

```bash
curl -N -X POST http://localhost:8080/models/select \
  -H "Content-Type: application/json" \
  -d '{"model": "gemma-2-9b-it"}'
```

Download progress streams via SSE, and `"ready"` appears when it's done.

### Comparing Translations Across Models

Let's translate the same sentence with different models.

```bash
# Translate with gemma-2-9b-it (the model we just switched to)
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "The quick brown fox jumps over the lazy dog.", "target_lang": "ja"}'

# Switch back to gemma-2-2b-it
curl -N -X POST http://localhost:8080/models/select \
  -H "Content-Type: application/json" \
  -d '{"model": "gemma-2-2b-it"}'

# Translate the same sentence
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "The quick brown fox jumps over the lazy dog.", "target_lang": "ja"}'
```

Translation results vary depending on the model, even with the same code and the same prompt. Since cpp-llamalib automatically applies the appropriate chat template for each model, no code changes are needed.

## Next Chapter

The server's main features are now complete: REST API, SSE streaming, and model download and switching. In the next chapter, we'll add static file serving and build a Web UI you can use from a browser.

**Next:** [Adding a Web UI](../ch05-web-ui)
