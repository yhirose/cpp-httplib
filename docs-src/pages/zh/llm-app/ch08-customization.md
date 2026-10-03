---
title: "8. 打造属于你自己的应用"
order: 8

---

到第 7 章为止，我们已经构建了一个翻译桌面应用，并研究了生产级代码有何不同。在本章中，让我们梳理一下把**这个应用彻底变成你自己的东西**的要点。

翻译应用只是一个载体。把 llama.cpp 换成你自己的库，同样的架构就能适用于任何应用。

## 8.1 替换构建配置

首先，把 `CMakeLists.txt` 中与 llama.cpp 相关的 `FetchContent` 条目替换成你自己的库。

```cmake
# 删除：llama.cpp 和 cpp-llamalib 的 FetchContent

# 添加：你自己的库
FetchContent_Declare(my_lib
    GIT_REPOSITORY https://github.com/yourname/my-lib
    GIT_TAG        main
)
FetchContent_MakeAvailable(my_lib)

target_link_libraries(my-app PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    my_lib        # 用你自己的库代替 cpp-llamalib
    # ...
)
```

如果你的库不支持 CMake，你可以把头文件和源文件直接放到 `src/` 中，并把它们加入 `add_executable`。cpp-httplib、nlohmann/json 和 webview 保持原样即可。

## 8.2 让 API 适配你的任务

把翻译 API 的端点和参数改成与你任务相匹配的形式。

| 翻译应用 | 你的应用（例如图像处理） |
|---|---|
| `POST /translate` | `POST /process` |
| `{"text": "...", "target_lang": "ja"}` | `{"image": "base64...", "filter": "blur"}` |
| `POST /translate/stream` | `POST /process/stream` |
| `GET /models` | `GET /filters` 或 `GET /presets` |

然后更新每个处理器的实现。例如，只需把 `llm.chat()` 调用替换成你自己的库的 API。

```cpp
// 之前：LLM 翻译
auto translation = llm.chat(prompt);
res.set_content(json{{"translation", translation}}.dump(), "application/json");

// 之后：例如图像处理库
auto result = my_lib::process(input_image, options);
res.set_content(json{{"result", result}}.dump(), "application/json");
```

SSE 流式传输也一样。如果你的库提供了通过回调汇报进度的函数，你就可以沿用第 3 章完全相同的模式来发送增量响应。SSE 并不局限于 LLM —— 对于任何耗时任务都很有用：图像处理进度、数据转换步骤、长时间运行的计算。

## 8.3 设计上的注意事项

### 初始化开销很大的库

在本书中，我们在 `main()` 的开头加载 LLM 模型，并把它保存在一个变量中。这是有意为之。每次请求都加载模型要花好几秒，因此我们在启动时加载一次并复用。如果你的库初始化开销很大（加载大型数据文件、获取 GPU 资源等），同样的做法也同样适用。

### 线程安全

cpp-httplib 使用线程池并发处理请求。在第 4 章中，我们用 `std::mutex` 保护 `llm` 对象，以防止在切换模型时崩溃。在集成你自己的库时，同样的模式也适用。如果你的库不是线程安全的，或者你需要在运行时替换对象，那么就用 `std::mutex` 来保护访问。

## 8.4 定制 UI

编辑 `public/` 中的三个文件。

- **`index.html`** —— 更改输入表单的布局。把 `<textarea>` 换成 `<input type="file">`，添加参数字段，等等。
- **`style.css`** —— 调整布局和配色。保留双栏设计，或者换成单栏
- **`script.js`** —— 更新 `fetch()` 的目标 URL、请求体，以及响应的显示方式

即使完全不改动服务器代码，仅仅替换 HTML 就能让应用看起来截然不同。由于这些都是静态文件，你可以快速迭代 —— 只需刷新浏览器，无需重启服务器。

本书使用的是纯 HTML、CSS 和 JavaScript，但如果把它们与 Vue 或 React 之类的前端框架，或者某个 CSS 框架结合起来，你就能构建出更加精致的应用。

## 8.5 分发相关的注意事项

### 许可证

请检查你所使用库的许可证。cpp-httplib（MIT）、nlohmann/json（MIT）和 webview（MIT）都允许商业使用。别忘了也检查一下你自己的库及其依赖项的许可证。

### 模型与数据文件

我们在第 4 章构建的下载机制并不局限于 LLM 模型。如果你的应用需要大型数据文件，同样的模式可以让你在首次启动时自动下载它们，从而既保持二进制文件小巧，又免去用户手动配置的麻烦。

如果数据很小，你可以用 cpp-embedlib 直接把它嵌入到二进制文件中。

### 跨平台构建

webview 支持 macOS、Linux 和 Windows。为各平台构建时：

- **macOS** —— 无需额外依赖
- **Linux** —— 需要 `libwebkit2gtk-4.1-dev`
- **Windows** —— 需要 WebView2 运行时（Windows 11 已预装）

也可以考虑在 CI（例如 GitHub Actions）中设置跨平台构建。

## 结语

非常感谢你读到最后。🙏

本书从第 1 章 `/health` 返回 `{"status":"ok"}` 开始。此后我们构建了 REST API、加入了 SSE 流式传输、从 Hugging Face 下载模型、创建了基于浏览器的 Web UI，并把这一切打包成了一个单二进制的桌面应用。在第 7 章中，我们通读了 `llama-server` 的代码，了解了生产级服务器在设计上有何不同。这是一段相当长的旅程，真心感谢你一路坚持读到最后。

回顾一下，我们动手实践了 cpp-httplib 的几个关键特性：

- **服务器**：路由、JSON 响应、使用 `set_chunked_content_provider` 的 SSE 流式传输、使用 `set_mount_point` 提供静态文件
- **客户端**：HTTPS 连接、跟随重定向、使用 content receiver 进行大文件下载、进度回调
- **WebView 集成**：`bind_to_any_port` + `listen_after_bind` 实现后台线程化

cpp-httplib 提供的功能远不止我们这里介绍的这些，还包括 multipart 文件上传、身份认证、超时控制、压缩以及 range 请求。详见 [cpp-httplib 导览](../../tour/)。

这些模式并不局限于翻译应用。如果你想为自己的 C++ 库添加 Web API、给它配一个浏览器 UI，或者把它打包成一个易于分发的桌面应用 —— 希望本书能成为有用的参考。

拿上你自己的库，构建你自己的应用，尽情享受这个过程吧。Happy hacking! 🚀
