---
title: "2. 集成 llama.cpp 构建 REST API"
order: 2

---

在第 1 章的骨架中，`/translate` 只是简单地返回 `"TODO"`。本章我们将集成 llama.cpp 推理，把它改造成一个真正返回翻译结果的 API。

直接调用 llama.cpp 的 API 会让代码变得相当冗长，因此我们使用一个名为 [cpp-llamalib](https://github.com/yhirose/cpp-llamalib) 的轻量封装库。它让你只需几行代码就能加载模型并运行推理，从而把注意力集中在 cpp-httplib 上。

## 2.1 初始化 LLM

只需把模型文件的路径传给 `llamalib::Llama`，模型加载、上下文创建和采样器配置都会自动完成。如果你在第 1 章下载的是其他模型，请相应调整路径。

```cpp
#include <cpp-llamalib.h>

int main() {
  auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf"};

  // LLM 推理比较耗时，因此设置更长的超时时间（默认为 5 秒）
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  // ... 构建并启动 HTTP 服务器 ...
}
```

如果你想修改 GPU 层数、上下文长度或其他设置，可以通过 `llamalib::Options` 指定。

```cpp
auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf", {
  .n_gpu_layers = 0,  // 仅使用 CPU
  .n_ctx = 4096,
}};
```

## 2.2 `/translate` 处理函数

我们将第 1 章中返回占位 JSON 的处理函数替换为真正的推理。

```cpp
svr.Post("/translate",
         [&](const httplib::Request &req, httplib::Response &res) {
  // 解析 JSON（第 3 个参数为 `false`：失败时不抛出异常，用 `is_discarded()` 检查）
  auto input = json::parse(req.body, nullptr, false);
  if (input.is_discarded()) {
    res.status = 400;
    res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                    "application/json");
    return;
  }

  // 校验必填字段
  if (!input.contains("text") || !input["text"].is_string() ||
      input["text"].get<std::string>().empty()) {
    res.status = 400;
    res.set_content(json{{"error", "'text' is required"}}.dump(),
                    "application/json");
    return;
  }

  auto text = input["text"].get<std::string>();
  auto target_lang = input.value("target_lang", "ja"); // 默认为日语

  // 构建提示词并运行推理
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

`llm.chat()` 在推理过程中可能会抛出异常（例如超出上下文长度时）。通过 `try/catch` 捕获异常并以 JSON 返回错误，可以避免服务器崩溃。

## 2.3 完整代码

以下是包含目前所有改动的完整代码。

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

// 收到 `Ctrl+C` 时优雅关闭
void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // 加载第 1 章下载的模型
  auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf"};

  // LLM 推理比较耗时，因此设置更长的超时时间（默认为 5 秒）
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

  svr.Post("/translate",
           [&](const httplib::Request &req, httplib::Response &res) {
    // 解析 JSON（第 3 个参数为 `false`：失败时不抛出异常，用 `is_discarded()` 检查）
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded()) {
      res.status = 400;
      res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                      "application/json");
      return;
    }

    // 校验必填字段
    if (!input.contains("text") || !input["text"].is_string() ||
        input["text"].get<std::string>().empty()) {
      res.status = 400;
      res.set_content(json{{"error", "'text' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto text = input["text"].get<std::string>();
    auto target_lang = input.value("target_lang", "ja"); // 默认为日语

    // 构建提示词并运行推理
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

  // 占位实现，后续章节会替换为真正的实现
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

  // 启动服务器（阻塞直到调用 `stop()`）
  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 2.4 动手测试

重新构建并启动服务器，然后验证它现在能返回真正的翻译结果。

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

在第 1 章中响应是 `"TODO"`，而现在你能得到真正的翻译结果。

## 下一章

本章构建的 REST API 会等整段翻译完成后才发送响应，因此对于长文本，用户只能干等，得不到任何进度提示。

下一章我们将使用 SSE（Server-Sent Events），在 token 生成时实时流式返回。

**下一章：**[使用 SSE 添加 token 流式输出](../ch03-sse-streaming)
