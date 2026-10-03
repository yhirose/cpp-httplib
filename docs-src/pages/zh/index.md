---
title: "cpp-httplib"
order: 0
---

[cpp-httplib](https://github.com/yhirose/cpp-httplib) 是一个用于 C++ 的 HTTP/HTTPS 库。只需复制一个头文件 [`httplib.h`](https://github.com/yhirose/cpp-httplib/raw/refs/tags/latest/httplib.h)，即可开始使用。

当你在 C++ 中需要一个能快速上手的 HTTP 服务器或客户端时，你希望它开箱即用。这正是我开发 cpp-httplib 的原因。只需几行代码，你就能同时编写服务器和客户端。

该 API 采用基于 lambda 的设计，用起来非常自然。只要你有 C++11 或更高版本的编译器，它在任何平台上都能运行。Windows、macOS、Linux —— 用你现有的环境即可。

HTTPS 同样支持。只需链接 OpenSSL 或 mbedTLS，服务器和客户端就都获得了 TLS 支持。Content-Encoding（gzip、Brotli 等）、文件上传，以及在实际开发中真正需要的其他功能一应俱全。WebSocket 也受支持。

在底层，它使用阻塞式 I/O 配合线程池。它并非为处理海量并发连接而设计。但对于 API 服务器、工具中内嵌的 HTTP、用于测试的 mock 服务器以及许多其他场景，它能提供可靠的性能。

“今天的问题，今天就解决。”这正是 cpp-httplib 所追求的简洁。

## 文档

- [cpp-httplib 入门教程](tour/) —— 循序渐进地讲解基础知识的教程。如果你是新手，请从这里开始
- [构建桌面版 LLM 应用](llm-app/) —— 使用 llama.cpp 逐步构建桌面应用的实战指南

## 敬请期待

- [Cookbook](cookbook/) —— 按主题组织的示例集。按需跳转到你需要的内容
