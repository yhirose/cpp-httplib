---
title: "Building a Desktop LLM App with cpp-httplib"
order: 0

---

Have you ever wanted to add a web API to your own C++ library, or quickly build an Electron-like desktop app? In Rust you might reach for "Tauri + axum," but in C++ it always seemed out of reach.

With [cpp-httplib](https://github.com/yhirose/cpp-httplib), [webview/webview](https://github.com/webview/webview), and [cpp-embedlib](https://github.com/yhirose/cpp-embedlib), you can take the same approach in pure C++ — and produce a small, easy-to-distribute single binary.

In this tutorial we build an LLM-powered translation app using [llama.cpp](https://github.com/ggml-org/llama.cpp), progressing step by step from "REST API" to "SSE streaming" to "Web UI" to "desktop app." Translation is just the vehicle — replace llama.cpp with your own library and the same architecture works for any application.

![Desktop App](app.png#large-center)

If you know basic C++17 and understand the basics of HTTP / REST APIs, you're ready to start.

## Chapters

1. **[Set up the project](ch01-setup)** — Fetch dependencies, configure the build, write scaffold code
2. **[Embed llama.cpp and create a REST API](ch02-rest-api)** — Return translation results as JSON
3. **[Add token streaming with SSE](ch03-sse-streaming)** — Stream responses token by token
4. **[Add model discovery and management](ch04-model-management)** — Download and switch models from Hugging Face
5. **[Add a Web UI](ch05-web-ui)** — A browser-based translation interface
6. **[Turn it into a desktop app with WebView](ch06-desktop-app)** — A single-binary desktop application
7. **[Reading the llama.cpp server source code](ch07-code-reading)** — Compare with production-quality code
8. **[Making it your own](ch08-customization)** — Swap in your own library and customize
