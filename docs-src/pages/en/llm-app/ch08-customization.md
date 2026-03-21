---
title: "8. Making It Your Own"
order: 8

---

Through Chapter 7, we've built a translation desktop app and studied how production-quality code differs. In this chapter, let's go over the key points for **turning this app into something entirely your own**.

The translation app was just a vehicle. Replace llama.cpp with your own library, and the same architecture works for any application.

## 8.1 Swapping Out the Build Configuration

First, replace the llama.cpp-related `FetchContent` entries in `CMakeLists.txt` with your own library.

```cmake
# Remove: llama.cpp and cpp-llamalib FetchContent

# Add: your own library
FetchContent_Declare(my_lib
    GIT_REPOSITORY https://github.com/yourname/my-lib
    GIT_TAG        main
)
FetchContent_MakeAvailable(my_lib)

target_link_libraries(my-app PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    my_lib        # Your library instead of cpp-llamalib
    # ...
)
```

If your library doesn't support CMake, you can place the header and source files directly in `src/` and add them to `add_executable`. Keep cpp-httplib, nlohmann/json, and webview as they are.

## 8.2 Adapting the API to Your Task

Change the translation API's endpoints and parameters to match your task.

| Translation app | Your app (e.g., image processing) |
|---|---|
| `POST /translate` | `POST /process` |
| `{"text": "...", "target_lang": "ja"}` | `{"image": "base64...", "filter": "blur"}` |
| `POST /translate/stream` | `POST /process/stream` |
| `GET /models` | `GET /filters` or `GET /presets` |

Then update each handler's implementation. For example, just replace the `llm.chat()` calls with your own library's API.

```cpp
// Before: LLM translation
auto translation = llm.chat(prompt);
res.set_content(json{{"translation", translation}}.dump(), "application/json");

// After: e.g., an image processing library
auto result = my_lib::process(input_image, options);
res.set_content(json{{"result", result}}.dump(), "application/json");
```

The same goes for SSE streaming. If your library has a function that reports progress via a callback, you can use the exact same pattern from Chapter 3 to send incremental responses. SSE isn't limited to LLMs — it's useful for any time-consuming task: image processing progress, data conversion steps, long-running computations.

## 8.3 Design Considerations

### Libraries with Expensive Initialization

In this book, we load the LLM model at the top of `main()` and keep it in a variable. This is intentional. Loading the model on every request would take several seconds, so we load it once at startup and reuse it. If your library has expensive initialization (loading large data files, acquiring GPU resources, etc.), the same approach works well.

### Thread Safety

cpp-httplib processes requests concurrently using a thread pool. In Chapter 4 we protected the `llm` object with a `std::mutex` to prevent crashes during model switching. The same pattern applies when integrating your own library. If your library isn't thread-safe or you need to swap objects at runtime, protect access with a `std::mutex`.

## 8.4 Customizing the UI

Edit the three files in `public/`.

- **`index.html`** — Change the input form layout. Swap `<textarea>` for `<input type="file">`, add parameter fields, etc.
- **`style.css`** — Adjust the layout and colors. Keep the two-column design or switch to a single column
- **`script.js`** — Update the `fetch()` target URLs, request bodies, and how responses are displayed

Even without changing any server code, just swapping the HTML makes the app look completely different. Since these are static files, you can iterate quickly — just reload the browser without restarting the server.

This book used plain HTML, CSS, and JavaScript, but combining them with a frontend framework like Vue or React, or a CSS framework, would let you build an even more polished app.

## 8.5 Distribution Considerations

### Licenses

Check the licenses of the libraries you're using. cpp-httplib (MIT), nlohmann/json (MIT), and webview (MIT) all allow commercial use. Don't forget to check the license of your own library and its dependencies too.

### Models and Data Files

The download mechanism we built in Chapter 4 isn't limited to LLM models. If your app needs large data files, the same pattern lets you auto-download them on first launch, keeping the binary small while sparing users the manual setup.

If the data is small, you can embed it directly into the binary with cpp-embedlib.

### Cross-Platform Builds

webview supports macOS, Linux, and Windows. When building for each platform:

- **macOS** — No additional dependencies
- **Linux** — Requires `libwebkit2gtk-4.1-dev`
- **Windows** — Requires the WebView2 runtime (pre-installed on Windows 11)

Consider setting up cross-platform builds in CI (e.g., GitHub Actions) too.

## Closing

Thank you so much for reading to the end. 🙏

This book started with `/health` returning `{"status":"ok"}` in Chapter 1. From there we built a REST API, added SSE streaming, downloaded models from Hugging Face, created a browser-based Web UI, and packaged it all into a single-binary desktop app. In Chapter 7 we read through `llama-server`'s code and learned how production-quality servers differ in their design. It's been quite a journey, and I'm truly grateful you stuck with it all the way through.

Looking back, we used several key cpp-httplib features hands-on:

- **Server**: routing, JSON responses, SSE streaming with `set_chunked_content_provider`, static file serving with `set_mount_point`
- **Client**: HTTPS connections, redirect following, large downloads with content receivers, progress callbacks
- **WebView integration**: `bind_to_any_port` + `listen_after_bind` for background threading

cpp-httplib offers many more features beyond what we covered here, including multipart file uploads, authentication, timeout control, compression, and range requests. See [A Tour of cpp-httplib](../../tour/) for details.

These patterns aren't limited to a translation app. If you want to add a web API to your C++ library, give it a browser UI, or ship it as an easy-to-distribute desktop app — I hope this book serves as a useful reference.

Take your own library, build your own app, and have fun with it. Happy hacking! 🚀
