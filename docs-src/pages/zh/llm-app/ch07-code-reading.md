---
title: "7. 阅读 llama.cpp 服务器源码"
order: 7

---

在六章的时间里，我们从头构建了一个翻译桌面应用。我们有了一个可以运行的产品，但它归根到底还是一个“以学习为目的”的实现。那么，“生产级”代码又有什么不同呢？让我们阅读 llama.cpp 官方随附的服务器 `llama-server` 的源码，并做个对比。

`llama-server` 位于 `llama.cpp/tools/server/`。它使用的是同一个 cpp-httplib，因此你可以按照与前面章节相同的方式来阅读这些代码。

## 7.1 源码位置

```ascii
llama.cpp/tools/server/
├── server.cpp           # 服务器主实现
├── httplib.h            # cpp-httplib（随附版本）
└── ...
```

代码都放在单个 `server.cpp` 中。它有数千行之多，但一旦理解了整体结构，你就能缩小范围，找到值得阅读的部分。

## 7.2 兼容 OpenAI 的 API

我们构建的服务器与 `llama-server` 之间最大的差异在于 API 设计。

**我们的 API：**

```text
POST /translate          → {"translation": "..."}
POST /translate/stream   → SSE: data: "token"
```

**llama-server 的 API：**

```text
POST /v1/chat/completions  → 兼容 OpenAI 的 JSON
POST /v1/completions       → 兼容 OpenAI 的 JSON
POST /v1/embeddings        → 文本嵌入向量
```

`llama-server` 遵循 [OpenAI 的 API 规范](https://platform.openai.com/docs/api-reference)。这意味着 OpenAI 的官方客户端库（例如 Python 的 `openai` 包）可以开箱即用。

```python
# 使用 OpenAI 客户端连接 llama-server 的示例
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="dummy")

response = client.chat.completions.create(
    model="local-model",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

与现有工具和库的兼容性是一个重大的设计决策。我们设计了一个简单的、专用于翻译的 API，但如果你要构建一个通用服务器，那么兼容 OpenAI 已经成了事实上的标准。

## 7.3 并发请求处理

我们的服务器一次只处理一个请求。如果在翻译进行中又有另一个请求到达，它必须等到前一次推理结束。对于单人使用的桌面应用来说这没什么问题，但对于多个用户共享的服务器来说就成了问题。

`llama-server` 通过一种称为 **slot** 的机制来处理并发请求。

![llama-server 的 slot 管理](../slots.svg#half)

关键在于，每个 slot 的 token 并不是**逐个按顺序**推理的，而是**一次性作为一个批次全部处理**。GPU 擅长并行处理，因此同时处理两个用户所花的时间几乎与处理一个用户相同。这被称为“连续批处理（continuous batching）”。

在我们的服务器中，cpp-httplib 的线程池为每个请求分配一个线程，但推理本身是在 `llm.chat()` 内部单线程运行的。`llama-server` 把这一推理步骤整合进了一个共享的批处理循环中。

## 7.4 SSE 格式的差异

流式传输机制本身是相同的（`set_chunked_content_provider` + SSE），但数据格式不同。

**我们的格式：**

```text
data: "去年の"
data: "春に"
data: [DONE]
```

**llama-server（兼容 OpenAI）：**

```text
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"delta":{"content":"去年の"}}]}
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"delta":{"content":"春に"}}]}
data: [DONE]
```

我们的格式只是直接发送 token。由于 `llama-server` 遵循 OpenAI 规范，即便只有一个 token 也会被包裹在 JSON 中。它看起来可能有些啰嗦，但其中包含了对客户端有用的信息，比如用于标识请求的 `id`，以及表示生成为何停止的 `finish_reason`。

## 7.5 KV cache 复用

在我们的服务器中，每次请求都会从头处理整个 prompt。我们翻译应用的 prompt 很短（"Translate the following text to ja..." + 输入文本），所以这不是问题。

当一个请求与之前的请求共享相同的 prompt 前缀时，`llama-server` 会复用该前缀部分的 KV cache。

![KV cache 复用](../kv-cache.svg#half)

对于每次请求都要发送一长段 system prompt 和 few-shot 示例的聊天机器人来说，仅这一项就能大幅缩短响应时间。每次都处理数千个 token 的 system prompt，与瞬间从缓存中读取它们相比，差别简直天壤之别。

对于我们的翻译应用而言，system prompt 只有一句话，收效有限。不过，当你把它应用到自己的应用中时，这是一个值得记住的优化手段。

## 7.6 结构化输出

由于我们的翻译 API 返回的是纯文本，所以无需约束输出格式。但如果你想让 LLM 以 JSON 响应呢？

```text
提示词：分析下面这段文本的情感，并以 JSON 返回。
LLM 输出（期望）: {"sentiment": "positive", "score": 0.8}
LLM 输出（现实）: 情感分析的结果如下。{"sentiment": ...
```

LLM 有时会无视指令，附加一些多余的文本。`llama-server` 通过 **语法约束** 解决了这个问题。

```bash
curl http://localhost:8080/v1/chat/completions \
  -d '{
    "messages": [{"role": "user", "content": "Analyze sentiment..."}],
    "json_schema": {
      "type": "object",
      "properties": {
        "sentiment": {"type": "string", "enum": ["positive", "negative", "neutral"]},
        "score": {"type": "number"}
      },
      "required": ["sentiment", "score"]
    }
  }'
```

当你指定 `json_schema` 时，在 token 生成过程中，不符合该语法的 token 会被排除。这保证了输出始终是合法的 JSON，因此无需担心 `json::parse` 会失败。

在把 LLM 融入应用时，能否可靠地解析输出直接影响着可靠性。对于翻译这类自由文本输出，语法约束没有必要，但对于需要把结构化数据作为 API 响应返回的用例来说，它是必不可少的。

## 7.7 小结

让我们梳理一下前面讲到的差异。

| 方面 | 我们的服务器 | llama-server |
|------|-------------|--------------|
| API 设计 | 专用于翻译 | 兼容 OpenAI |
| 并发请求 | 顺序处理 | slot + 连续批处理 |
| SSE 格式 | 仅 token | 兼容 OpenAI 的 JSON |
| KV cache | 每次清空 | 前缀复用 |
| 结构化输出 | 无 | JSON Schema / 语法约束 |
| 代码规模 | 约 200 行 | 数千行 |

我们的代码之所以简单，是因为它建立在“由一个人作为桌面应用使用”这一前提之上。如果你要构建一个面向多用户的服务器，或者一个要与既有生态集成的服务器，那么 `llama-server` 的设计就是一个很有价值的参考。

反过来说，即便只有 200 行代码，也足以做出一个功能完备的翻译应用。希望这次源码阅读之旅也传达出了“只构建你所需要的东西”的价值。

## 下一章

在下一章中，我们将介绍替换成你自己的库、并定制应用使之真正成为你自己的东西的要点。

**下一章：** [打造属于你自己的应用](../ch08-customization)
