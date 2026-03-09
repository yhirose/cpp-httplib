---
title: "Building a Desktop LLM App with cpp-httplib"
order: 0
---

Build an LLM-powered translation desktop app step by step, learning both the server and client sides of cpp-httplib along the way. Translation is just an example — swap it out to build your own summarizer, code generator, chatbot, or any other LLM application.

## Dependencies

- [llama.cpp](https://github.com/ggml-org/llama.cpp) — LLM inference engine
- [nlohmann/json](https://github.com/nlohmann/json) — JSON parser (header-only)
- [webview/webview](https://github.com/webview/webview) — WebView wrapper (header-only)
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) — HTTP server/client (header-only)

## Chapters

1. **Embed llama.cpp and create a REST API** — Start with a simple API that accepts text via POST and returns a translation as JSON
2. **Add token streaming with SSE** — Stream translation results token by token using the standard LLM API approach
3. **Add model discovery and download** — Use the client to search and download GGUF models from Hugging Face
4. **Add a Web UI** — Serve a translation UI with static file hosting, making the app accessible from a browser
5. **Turn it into a desktop app with WebView** — Wrap the web app with webview/webview to create an Electron-like desktop application
6. **Code reading: llama.cpp's server implementation** — Compare your implementation with production-quality code and learn from the differences
