---
title: "2. Integrating llama.cpp to Build a REST API"
order: 2

---

In the skeleton from Chapter 1, `/translate` simply returned `"TODO"`. In this chapter we integrate llama.cpp inference and turn it into an API that actually returns translation results.

Calling the llama.cpp API directly makes the code quite long, so we use a thin wrapper library called [cpp-llamalib](https://github.com/yhirose/cpp-llamalib). It lets you load a model and run inference in just a few lines, keeping the focus on cpp-httplib.

## 2.1 Initializing the LLM

Simply pass the path to a model file to `llamalib::Llama`, and model loading, context creation, and sampler configuration are all taken care of. If you downloaded a different model in Chapter 1, adjust the path accordingly.

```cpp
#include <cpp-llamalib.h>

int main() {
  auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf"};

  // LLM inference takes time, so set a longer timeout (default is 5 seconds)
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  // ... Build and start the HTTP server ...
}
```

If you want to change the number of GPU layers, context length, or other settings, you can specify them via `llamalib::Options`.

```cpp
auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf", {
  .n_gpu_layers = 0,  // CPU only
  .n_ctx = 4096,
}};
```

## 2.2 The `/translate` Handler

We replace the handler that returned dummy JSON in Chapter 1 with actual inference.

```cpp
svr.Post("/translate",
         [&](const httplib::Request &req, httplib::Response &res) {
  // Parse JSON (3rd arg `false`: don't throw on failure, check with `is_discarded()`)
  auto input = json::parse(req.body, nullptr, false);
  if (input.is_discarded()) {
    res.status = 400;
    res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                    "application/json");
    return;
  }

  // Validate required fields
  if (!input.contains("text") || !input["text"].is_string() ||
      input["text"].get<std::string>().empty()) {
    res.status = 400;
    res.set_content(json{{"error", "'text' is required"}}.dump(),
                    "application/json");
    return;
  }

  auto text = input["text"].get<std::string>();
  auto target_lang = input.value("target_lang", "ja"); // Default is Japanese

  // Build the prompt and run inference
  auto prompt = "Translate the following text to " + target_lang +
                ". Output only the translation, nothing else.\n\n" + text;

  try {
    auto translation = llm.chat(prompt);
    res.set_content(json{{"translation", translation}}.dump(),
                    "application/json");
  } catch (const std::exception &e) {
    res.status = 500;
    res.set_content(json{{"error", e.what()}}.dump(), "application/json");
  }
});
```

`llm.chat()` can throw exceptions during inference (for example, when the context length is exceeded). By catching them with `try/catch` and returning the error as JSON, we prevent the server from crashing.

## 2.3 Complete Code

Here is the finished code with all the changes so far.

<details>
<summary data-file="main.cpp">Complete code (main.cpp)</summary>

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cpp-llamalib.h>

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
  // Load the model downloaded in Chapter 1
  auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf"};

  // LLM inference takes time, so set a longer timeout (default is 5 seconds)
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  // Log requests and responses
  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  svr.Post("/translate",
           [&](const httplib::Request &req, httplib::Response &res) {
    // Parse JSON (3rd arg `false`: don't throw on failure, check with `is_discarded()`)
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded()) {
      res.status = 400;
      res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                      "application/json");
      return;
    }

    // Validate required fields
    if (!input.contains("text") || !input["text"].is_string() ||
        input["text"].get<std::string>().empty()) {
      res.status = 400;
      res.set_content(json{{"error", "'text' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto text = input["text"].get<std::string>();
    auto target_lang = input.value("target_lang", "ja"); // Default is Japanese

    // Build the prompt and run inference
    auto prompt = "Translate the following text to " + target_lang +
                  ". Output only the translation, nothing else.\n\n" + text;

    try {
      auto translation = llm.chat(prompt);
      res.set_content(json{{"translation", translation}}.dump(),
                      "application/json");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(json{{"error", e.what()}}.dump(), "application/json");
    }
  });

  // Dummy implementations to be replaced with real ones in later chapters
  svr.Get("/models",
          [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"models", json::array()}}.dump(), "application/json");
  });

  svr.Post("/models/select",
           [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "TODO"}}.dump(), "application/json");
  });

  // Allow the server to be stopped with `Ctrl+C` (`SIGINT`) or `kill` (`SIGTERM`)
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // Start the server (blocks until `stop()` is called)
  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 2.4 Testing It Out

Rebuild and start the server, then verify that it now returns actual translation results.

```bash
cmake --build build -j
./build/translate-server
```

```bash
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "I had a great time visiting Tokyo last spring. The cherry blossoms were beautiful.", "target_lang": "ja"}'
# => {"translation":"去年の春に東京を訪れた。桜が綺麗だった。"}
```

In Chapter 1 the response was `"TODO"`, but now you get an actual translation back.

## Next Chapter

The REST API we built in this chapter waits for the entire translation to complete before sending the response, so for long texts the user has to wait with no indication of progress.

In the next chapter, we use SSE (Server-Sent Events) to stream tokens back in real time as they are generated.

**Next:** [Adding Token Streaming with SSE](../ch03-sse-streaming)
