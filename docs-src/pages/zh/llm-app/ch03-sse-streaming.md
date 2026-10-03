---
title: "3. 使用 SSE 添加 Token 流式输出"
order: 3

---

第 2 章的 `/translate` 端点在翻译完成后一次性返回整个结果。对于短句来说这没什么问题，但对于较长的文本，用户就必须等待好几秒，而界面上什么都没有显示。

在本章中，我们添加一个 `/translate/stream` 端点，使用 SSE（Server-Sent Events，服务器发送事件）在 token 生成的同时实时返回它们。这与 ChatGPT 和 Claude API 采用的方式相同。

## 3.1 什么是 SSE？

SSE 是一种将 HTTP 响应以流的方式发送的方法。当客户端发送请求时，服务器保持连接打开，并逐步返回事件。其格式是简单的文本。

```text
data: "去年の"
data: "春に"
data: "東京を"
data: [DONE]
```

每一行都以 `data:` 开头，事件之间用空行分隔。Content-Type 为 `text/event-stream`。token 以经过转义的 JSON 字符串形式发送，因此它们看起来被双引号括起来（我们在 3.3 节中实现这一点）。

## 3.2 使用 cpp-httplib 进行流式传输

在 cpp-httplib 中，你可以使用 `set_chunked_content_provider` 来增量地发送响应。每次在回调中向 `sink.os` 写入数据时，数据都会被发送到客户端。

```cpp
res.set_chunked_content_provider(
    "text/event-stream",
    [](size_t offset, httplib::DataSink &sink) {
      sink.os << "data: hello\n\n";
      sink.done();
      return true;
    });
```

调用 `sink.done()` 会结束流。如果客户端在流中途断开连接，向 `sink.os` 写入将会失败，并且 `sink.os.fail()` 会返回 `true`。你可以借此检测断开连接，并中止不必要的推理。

## 3.3 `/translate/stream` 处理器

JSON 解析和校验与第 2 章的 `/translate` 端点相同。唯一的区别在于响应的返回方式。我们将 `llm.chat()` 的流式回调与 `set_chunked_content_provider` 结合起来。

```cpp
svr.Post("/translate/stream",
         [&](const httplib::Request &req, httplib::Response &res) {
  // ...（JSON 解析与校验与 /translate 相同）...

  res.set_chunked_content_provider(
      "text/event-stream",
      [&, prompt](size_t, httplib::DataSink &sink) {
        try {
          llm.chat(prompt, [&](std::string_view token) {
            sink.os << "data: "
                    << json(std::string(token)).dump(
                         -1, ' ', false, json::error_handler_t::replace)
                    << "\n\n";
            return sink.os.good(); // 断开连接则返回 false → 中止推理
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

几个要点：

- 当你向 `llm.chat()` 传入一个回调时，每生成一个 token 就会调用一次该回调。如果回调返回 `false`，生成就会被中止
- 向 `sink.os` 写入之后，你可以用 `sink.os.good()` 检查客户端是否仍然保持连接。如果客户端已经断开连接，它会返回 `false` 以停止推理
- 每个 token 在发送前都会通过 `json(token).dump()` 转义为 JSON 字符串。即使 token 中包含换行符或引号，这样做也是安全的
- `dump(-1, ' ', false, ...)` 的前三个参数都是默认值。真正重要的是第四个参数 `json::error_handler_t::replace`。由于 LLM 返回的 token 是子词级别的，多字节字符（例如日文）可能会在 token 之间被从字符中间截断。把不完整的 UTF-8 字节序列直接传给 `dump()` 会抛出异常，因此用 `replace` 安全地替换它们。浏览器会在自己那一端重新拼装这些字节，所以一切都能正确显示
- 整个 lambda 都被包裹在 `try/catch` 中。`llm.chat()` 可能会由于超出上下文窗口之类的原因抛出异常。如果异常在 lambda 内部未被捕获，服务器就会崩溃，因此我们改为把错误作为 SSE 事件返回
- `data: [DONE]` 遵循 OpenAI API 的约定，向客户端标识流的结束

## 3.4 完整代码

以下是在第 2 章代码的基础上添加 `/translate/stream` 端点后的完整代码。

<details>
<summary data-file="main.cpp">完整代码（main.cpp）</summary>

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cpp-llamalib.h>

#include <csignal>
#include <iostream>

using json = nlohmann::json;

httplib::Server svr;

// 收到 `Ctrl+C` 时优雅地关闭
void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // 加载 GGUF 模型
  auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf"};

  // LLM 推理比较耗时，因此把超时设置长一些（默认为 5 秒）
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  // 记录请求与响应日志
  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // 第 2 章中普通的翻译端点
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
    // JSON 解析与校验（与 /translate 相同）
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
              return sink.os.good(); // 断开连接则返回 false → 中止推理
            });
            sink.os << "data: [DONE]\n\n";
          } catch (const std::exception &e) {
            sink.os << "data: " << json({{"error", e.what()}}).dump() << "\n\n";
          }
          sink.done();
          return true;
        });
  });

  // 后续章节中会被替换为真实实现的占位实现
  svr.Get("/models",
          [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"models", json::array()}}.dump(), "application/json");
  });

  svr.Post("/models/select",
           [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "TODO"}}.dump(), "application/json");
  });

  // 允许通过 `Ctrl+C`（`SIGINT`）或 `kill`（`SIGTERM`）停止服务器
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // 启动服务器（在调用 `stop()` 之前会一直阻塞）
  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 3.5 实际测试

构建并启动服务器。

```bash
cmake --build build -j
./build/translate-server
```

使用 curl 的 `-N` 选项禁用缓冲，你就可以看到 token 在到达时被实时显示出来。

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

你应该能看到 token 一个接一个地流式传来。第 2 章的 `/translate` 端点也仍然可以正常工作。

## 下一章

服务器的翻译功能现在已完整实现。在下一章中，我们将使用 cpp-httplib 的客户端功能，添加从 Hugging Face 获取和管理模型的能力。

**下一章：** [添加模型下载与管理](../ch04-model-management)
