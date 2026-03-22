---
title: "3. Adding Token Streaming with SSE"
order: 3

---

The `/translate` endpoint from Chapter 2 returned the entire translation at once after completion. This is fine for short sentences, but for longer text the user has to wait several seconds with nothing displayed.

In this chapter, we add a `/translate/stream` endpoint that uses SSE (Server-Sent Events) to return tokens in real time as they are generated. This is the same approach used by the ChatGPT and Claude APIs.

## 3.1 What is SSE?

SSE is a way to send HTTP responses as a stream. When a client sends a request, the server keeps the connection open and gradually returns events. The format is simple text.

```text
data: "去年の"
data: "春に"
data: "東京を"
data: [DONE]
```

Each line starts with `data:` and events are separated by blank lines. The Content-Type is `text/event-stream`. Tokens are sent as escaped JSON strings, so they appear enclosed in double quotes (we implement this in Section 3.3).

## 3.2 Streaming with cpp-httplib

In cpp-httplib, you can use `set_chunked_content_provider` to send responses incrementally. Each time you write to `sink.os` inside the callback, data is sent to the client.

```cpp
res.set_chunked_content_provider(
    "text/event-stream",
    [](size_t offset, httplib::DataSink &sink) {
      sink.os << "data: hello\n\n";
      sink.done();
      return true;
    });
```

Calling `sink.done()` ends the stream. If the client disconnects mid-stream, writing to `sink.os` will fail and `sink.os.fail()` will return `true`. You can use this to detect disconnection and abort unnecessary inference.

## 3.3 The `/translate/stream` Handler

JSON parsing and validation are the same as the `/translate` endpoint from Chapter 2. The only difference is how the response is returned. We combine the streaming callback of `llm.chat()` with `set_chunked_content_provider`.

```cpp
svr.Post("/translate/stream",
         [&](const httplib::Request &req, httplib::Response &res) {
  // ... JSON parsing and validation same as /translate ...

  res.set_chunked_content_provider(
      "text/event-stream",
      [&, prompt](size_t, httplib::DataSink &sink) {
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
```

A few key points:

- When you pass a callback to `llm.chat()`, it is called each time a token is generated. If the callback returns `false`, generation is aborted
- After writing to `sink.os`, you can check whether the client is still connected with `sink.os.good()`. If the client has disconnected, it returns `false` to stop inference
- Each token is escaped as a JSON string using `json(token).dump()` before sending. This is safe even for tokens containing newlines or quotes
- The first three arguments of `dump(-1, ' ', false, ...)` are the defaults. What matters is the fourth argument, `json::error_handler_t::replace`. Since the LLM returns tokens at the subword level, multi-byte characters (such as Japanese) can be split mid-character across tokens. Passing an incomplete UTF-8 byte sequence directly to `dump()` would throw an exception, so `replace` safely substitutes them. The browser reassembles the bytes on its end, so everything displays correctly
- The entire lambda is wrapped in `try/catch`. `llm.chat()` can throw exceptions for reasons such as exceeding the context window. If an exception goes uncaught inside the lambda, the server will crash, so we return the error as an SSE event instead
- `data: [DONE]` follows the OpenAI API convention to signal the end of the stream to the client

## 3.4 Complete Code

Here is the complete code with the `/translate/stream` endpoint added to the code from Chapter 2.

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
  // Load the GGUF model
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

  // Standard translation endpoint from Chapter 2
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
      auto translation = llm.chat(prompt);
      res.set_content(json{{"translation", translation}}.dump(),
                      "application/json");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(json{{"error", e.what()}}.dump(), "application/json");
    }
  });

  // SSE streaming translation endpoint
  svr.Post("/translate/stream",
           [&](const httplib::Request &req, httplib::Response &res) {
    // JSON parsing and validation (same as /translate)
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

  // Dummy implementations to be replaced in later chapters
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

## 3.5 Testing It Out

Build and start the server.

```bash
cmake --build build -j
./build/translate-server
```

Using curl's `-N` option to disable buffering, you can see tokens displayed in real time as they arrive.

```bash
curl -N -X POST http://localhost:8080/translate/stream \
  -H "Content-Type: application/json" \
  -d '{"text": "I had a great time visiting Tokyo last spring. The cherry blossoms were beautiful.", "target_lang": "ja"}'
```

```text
data: "去年の"
data: "春に"
data: "東京を"
data: "訪れた"
data: "。"
data: "桜が"
data: "綺麗だった"
data: "。"
data: [DONE]
```

You should see tokens streaming in one by one. The `/translate` endpoint from Chapter 2 continues to work as well.

## Next Chapter

The server's translation functionality is now complete. In the next chapter, we use cpp-httplib's client functionality to add the ability to fetch and manage models from Hugging Face.

**Next:** [Adding Model Download and Management](../ch04-model-management)
