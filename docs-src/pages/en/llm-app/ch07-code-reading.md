---
title: "7. Reading the llama.cpp Server Source Code"
order: 7

---

Over the course of six chapters, we built a translation desktop app from scratch. We have a working product, but it's ultimately a "learning-oriented" implementation. So how does "production-quality" code differ? Let's read the source code of `llama-server`, the official server bundled with llama.cpp, and compare.

`llama-server` is located at `llama.cpp/tools/server/`. It uses the same cpp-httplib, so you can read the code the same way as in the previous chapters.

## 7.1 Source Code Location

```ascii
llama.cpp/tools/server/
├── server.cpp           # Main server implementation
├── httplib.h            # cpp-httplib (bundled version)
└── ...
```

The code is contained in a single `server.cpp`. It runs to several thousand lines, but once you understand the structure, you can narrow down the parts worth reading.

## 7.2 OpenAI-Compatible API

The biggest difference between the server we built and `llama-server` is the API design.

**Our API:**

```text
POST /translate          → {"translation": "..."}
POST /translate/stream   → SSE: data: "token"
```

**llama-server's API:**

```text
POST /v1/chat/completions  → OpenAI-compatible JSON
POST /v1/completions       → OpenAI-compatible JSON
POST /v1/embeddings        → Text embedding vectors
```

`llama-server` conforms to [OpenAI's API specification](https://platform.openai.com/docs/api-reference). This means OpenAI's official client libraries (such as the Python `openai` package) work out of the box.

```python
# Example of connecting to llama-server with the OpenAI client
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="dummy")

response = client.chat.completions.create(
    model="local-model",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

Compatibility with existing tools and libraries is a big design decision. We designed a simple translation-specific API, but if you're building a general-purpose server, OpenAI compatibility has become the de facto standard.

## 7.3 Concurrent Request Handling

Our server processes requests one at a time. If another request arrives while a translation is in progress, it waits until the previous inference finishes. This is fine for a desktop app used by one person, but it becomes a problem for a server shared by multiple users.

`llama-server` handles concurrent requests through a mechanism called **slots**.

![llama-server's slot management](../slots.svg#half)

The key point is that tokens from each slot are not inferred **one by one in sequence**, but rather **all at once in a single batch**. GPUs excel at parallel processing, so processing two users simultaneously takes almost the same time as processing one. This is called "continuous batching."

In our server, cpp-httplib's thread pool assigns one thread per request, but the inference itself runs single-threaded inside `llm.chat()`. `llama-server` consolidates this inference step into a shared batch processing loop.

## 7.4 Differences in SSE Format

The streaming mechanism itself is the same (`set_chunked_content_provider` + SSE), but the data format differs.

**Our format:**

```text
data: "去年の"
data: "春に"
data: [DONE]
```

**llama-server (OpenAI-compatible):**

```text
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"delta":{"content":"去年の"}}]}
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"delta":{"content":"春に"}}]}
data: [DONE]
```

Our format simply sends the tokens. Because `llama-server` follows the OpenAI specification, even a single token comes wrapped in JSON. It may look verbose, but it includes useful information for clients, like an `id` to identify the request and a `finish_reason` to indicate why generation stopped.

## 7.5 KV Cache Reuse

In our server, we process the entire prompt from scratch on every request. Our translation app's prompt is short ("Translate the following text to ja..." + input text), so this isn't a problem.

`llama-server` reuses the KV cache for the prefix portion when a request shares a common prompt prefix with a previous request.

![KV cache reuse](../kv-cache.svg#half)

For chatbots that send a long system prompt and few-shot examples with every request, this alone dramatically reduces response time. The difference is night and day: processing several thousand tokens of system prompt every time versus reading them from cache in an instant.

For our translation app, where the system prompt is just a single sentence, the benefit is limited. However, it's an optimization worth keeping in mind when applying this to your own applications.

## 7.6 Structured Output

Since our translation API returns plain text, there was no need to constrain the output format. But what if you want the LLM to respond in JSON?

```text
Prompt: Analyze the sentiment of the following text and return it as JSON.
LLM output (expected): {"sentiment": "positive", "score": 0.8}
LLM output (reality): Here are the results of the sentiment analysis. {"sentiment": ...
```

LLMs sometimes ignore instructions and add extraneous text. `llama-server` solves this problem with **grammar constraints**.

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

When you specify `json_schema`, tokens that don't conform to the grammar are excluded during token generation. This guarantees that the output is always valid JSON, so there's no need to worry about `json::parse` failing.

When embedding LLMs into applications, whether you can reliably parse the output directly impacts reliability. Grammar constraints are unnecessary for free-text output like translation, but they're essential for use cases where you need to return structured data as an API response.

## 7.7 Summary

Let's organize the differences we've covered.

| Aspect | Our Server | llama-server |
|------|-------------|--------------|
| API design | Translation-specific | OpenAI-compatible |
| Concurrent requests | Sequential processing | Slots + continuous batching |
| SSE format | Tokens only | OpenAI-compatible JSON |
| KV cache | Cleared each time | Prefix reuse |
| Structured output | None | JSON Schema / grammar constraints |
| Code size | ~200 lines | Several thousand lines |

Our code is simple because of the assumption that "one person uses it as a desktop app." If you're building a server for multiple users or one that integrates with the existing ecosystem, `llama-server`'s design serves as a valuable reference.

Conversely, even 200 lines of code is enough to make a fully functional translation app. I hope this code reading exercise has also conveyed the value of "building only what you need."

## Next Chapter

In the next chapter, we'll cover the key points for swapping in your own library and customizing the app to make it truly yours.

**Next:** [Making It Your Own](../ch08-customization)
