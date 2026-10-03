---
title: "使用 cpp-httplib 构建桌面 LLM 应用"
order: 0

---

你是否想过为自己的 C++ 库添加一个 Web API，或者快速构建一个类似 Electron 的桌面应用？在 Rust 中你可能会选择 "Tauri + axum"，但在 C++ 里这似乎总是遥不可及。

借助 [cpp-httplib](https://github.com/yhirose/cpp-httplib)、[webview/webview](https://github.com/webview/webview) 和 [cpp-embedlib](https://github.com/yhirose/cpp-embedlib)，你可以用纯 C++ 采用同样的思路 —— 并生成一个小巧、易于分发的单一二进制文件。

在本教程中，我们使用 [llama.cpp](https://github.com/ggml-org/llama.cpp) 构建一个由 LLM 驱动的翻译应用，从 "REST API" 到 "SSE 流式"，再到 "Web UI"，最后到 "桌面应用"，一步一步推进。翻译只是一个载体 —— 把 llama.cpp 换成你自己的库，同样的架构适用于任何应用。

![Desktop App](app.png#large-center)

如果你了解 C++17 基础，并且理解 HTTP / REST API 的基本概念，就可以开始了。

## 章节

1. **[搭建项目](ch01-setup)** —— 获取依赖、配置构建、编写脚手架代码
2. **[集成 llama.cpp 并创建 REST API](ch02-rest-api)** —— 以 JSON 返回翻译结果
3. **[使用 SSE 添加 token 流式输出](ch03-sse-streaming)** —— 逐 token 流式返回响应
4. **[添加模型发现与管理](ch04-model-management)** —— 从 Hugging Face 下载并切换模型
5. **[添加 Web UI](ch05-web-ui)** —— 基于浏览器的翻译界面
6. **[使用 WebView 将其变成桌面应用](ch06-desktop-app)** —— 单一二进制的桌面应用
7. **[阅读 llama.cpp 服务器源码](ch07-code-reading)** —— 与生产级代码进行对比
8. **[打造你自己的版本](ch08-customization)** —— 替换为你自己的库并进行定制
