---
title: "6. WebViewでデスクトップアプリ化する"
order: 6

---

5章で、ブラウザから操作できる翻訳アプリが完成しました。でも使うたびに「サーバーを起動して、ブラウザでURLを開いて…」という手順が必要です。普通のアプリのように、ダブルクリックで起動してすぐ使えるようにしたいですよね。

この章では2つのことをやります。

1. **WebView化** — [webview/webview](https://github.com/webview/webview)でブラウザなしで動くデスクトップアプリにする
2. **シングルバイナリ化** — [cpp-embedlib](https://github.com/yhirose/cpp-embedlib)でHTML/CSS/JSをバイナリに埋め込み、配布物を1ファイルにする

完成すると、`./translate-app`を実行するだけでウインドウが開き、翻訳が使えるようになります。

![Desktop App](../app.png#large-center)

モデルは初回起動時に自動ダウンロードされるので、ユーザーに渡すのはバイナリ1つだけです。

## 6.1 webview/webview を導入する

[webview/webview](https://github.com/webview/webview)は、OS標準のWebViewコンポーネント（macOSならWKWebView、LinuxならWebKitGTK、WindowsならWebView2）をC/C++から使えるようにするライブラリです。Electronのように独自ブラウザを同梱するわけではないので、バイナリサイズへの影響はほぼありません。

CMakeで取得します。`CMakeLists.txt`に以下を追加してください。

```cmake
# webview/webview
FetchContent_Declare(webview
    GIT_REPOSITORY https://github.com/webview/webview
    GIT_TAG        master
)
FetchContent_MakeAvailable(webview)
```

これで`webview::core`というCMakeターゲットが使えるようになります。`target_link_libraries`でリンクすると、インクルードパスやプラットフォーム固有のフレームワークを自動で設定してくれます。

> **macOS**: 追加の依存は不要です。WKWebViewはシステムに組み込まれています。
>
> **Linux**: WebKitGTKが必要です。`sudo apt install libwebkit2gtk-4.1-dev`でインストールしてください。
>
> **Windows**: WebView2ランタイムが必要です。Windows 11には標準搭載されています。Windows 10の場合は[Microsoft公式サイト](https://developer.microsoft.com/en-us/microsoft-edge/webview2/)から入手してください。

## 6.2 サーバーをバックグラウンドスレッドで動かす

5章まではサーバーの`listen()`がメインスレッドをブロックしていました。WebViewを使うには、サーバーを別スレッドで動かし、メインスレッドでWebViewのイベントループを回す必要があります。

```cpp
#include "webview/webview.h"
#include <thread>

int main() {
  // ... (サーバーのセットアップは5章と同じ) ...

  // サーバーをバックグラウンドスレッドで起動
  auto port = svr.bind_to_any_port("127.0.0.1");
  std::thread server_thread([&]() { svr.listen_after_bind(); });

  std::cout << "Listening on http://127.0.0.1:" << port << std::endl;

  // WebViewでUIを表示
  webview::webview w(false, nullptr);
  w.set_title("Translate App");
  w.set_size(1024, 768, WEBVIEW_HINT_NONE);
  w.navigate("http://127.0.0.1:" + std::to_string(port));
  w.run(); // ウインドウが閉じるまでブロック

  // ウインドウが閉じたらサーバーも停止
  svr.stop();
  server_thread.join();
}
```

ポイントを見ていきましょう。

- **`bind_to_any_port`** — `listen("127.0.0.1", 8080)`の代わりに、OSに空いているポートを選んでもらいます。デスクトップアプリは複数起動されることがあるので、ポートを固定するとぶつかります
- **`listen_after_bind`** — `bind_to_any_port`で確保したポートでリクエストの受付を開始します。`listen()`はbindとlistenを一度にやりますが、ポート番号を先に知る必要があるので分けています
- **シャットダウン順序** — WebViewのウインドウが閉じたら`svr.stop()`でサーバーを止め、`server_thread.join()`でスレッドの終了を待ちます。逆順だとWebViewがサーバーにアクセスできなくなります

5章の`signal_handler`は不要になります。デスクトップアプリではウインドウを閉じることがアプリの終了を意味するからです。

## 6.3 cpp-embedlib で静的ファイルを埋め込む

5章では`public/`ディレクトリからファイルを配信していました。これだと配布時に`public/`も一緒に渡す必要があります。[cpp-embedlib](https://github.com/yhirose/cpp-embedlib)を使うと、HTML・CSS・JavaScriptをバイナリに埋め込んで、配布物をバイナリ1つにまとめられます。

### CMakeLists.txt

cpp-embedlibを取得し、`public/`を埋め込みます。

```cmake
# cpp-embedlib
FetchContent_Declare(cpp-embedlib
    GIT_REPOSITORY https://github.com/yhirose/cpp-embedlib
    GIT_TAG        main
)
FetchContent_MakeAvailable(cpp-embedlib)

# public/ ディレクトリをバイナリに埋め込む
cpp_embedlib_add(WebAssets
    FOLDER    ${CMAKE_CURRENT_SOURCE_DIR}/public
    NAMESPACE Web
)

target_link_libraries(translate-app PRIVATE
    WebAssets                # 埋め込みファイル
    cpp-embedlib-httplib     # cpp-httplib連携
)
```

`cpp_embedlib_add`は、`public/`配下のファイルをコンパイル時にバイナリに変換し、`WebAssets`という静的ライブラリを作ります。リンクすると`Web::FS`というオブジェクトから埋め込みファイルにアクセスできます。`cpp-embedlib-httplib`は`httplib::mount()`関数を提供するヘルパーライブラリです。

### set_mount_point を httplib::mount に置き換える

5章の`set_mount_point`をcpp-embedlibの`httplib::mount`に置き換えるだけです。

```cpp
#include <cpp-embedlib-httplib.h>
#include "WebAssets.h"

// 5章:
// svr.set_mount_point("/", "./public");

// 6章:
httplib::mount(svr, Web::FS);
```

`httplib::mount`は、`Web::FS`に埋め込まれたファイルをHTTPで配信するハンドラを登録します。MIMEタイプはファイルの拡張子から自動判定するので、`Content-Type`を手動で設定する必要はありません。

ファイルの中身はバイナリのデータセグメントに直接マップしているので、メモリコピーもヒープ割り当ても発生しません。

## 6.4 macOS: Editメニューの追加

入力欄に`Cmd+V`でテキストをペーストしようとすると、動かないことに気づくはずです。macOSでは、`Cmd+V`（ペースト）や`Cmd+C`（コピー）などのキーボードショートカットは、アプリケーションのメニューバーを経由してWebViewに届きます。webview/webviewはメニューバーを作らないので、これらのショートカットが効きません。Objective-CランタイムAPIを使ってEditメニューを追加する必要があります。

```cpp
#ifdef __APPLE__
#include <objc/objc-runtime.h>

void setup_macos_edit_menu() {
  auto cls    = [](const char *n) { return (id)objc_getClass(n); };
  auto sel    = sel_registerName;
  auto msg    = reinterpret_cast<id (*)(id, SEL)>(objc_msgSend);
  auto msg_s  = reinterpret_cast<id (*)(id, SEL, const char *)>(objc_msgSend);
  auto msg_id = reinterpret_cast<id (*)(id, SEL, id)>(objc_msgSend);
  auto msg_v  = reinterpret_cast<void (*)(id, SEL, id)>(objc_msgSend);
  auto msg_mi = reinterpret_cast<id (*)(id, SEL, id, SEL, id)>(objc_msgSend);

  auto str = [&](const char *s) {
    return msg_s(cls("NSString"), sel("stringWithUTF8String:"), s);
  };

  id app      = msg(cls("NSApplication"), sel("sharedApplication"));
  id mainMenu = msg(msg(cls("NSMenu"), sel("alloc")), sel("init"));
  id editItem = msg(msg(cls("NSMenuItem"), sel("alloc")), sel("init"));
  id editMenu = msg_id(msg(cls("NSMenu"), sel("alloc")),
                       sel("initWithTitle:"), str("Edit"));

  struct { const char *title; const char *action; const char *key; } items[] = {
    {"Undo",       "undo:",      "z"},
    {"Redo",       "redo:",      "Z"},
    {"Cut",        "cut:",       "x"},
    {"Copy",       "copy:",      "c"},
    {"Paste",      "paste:",     "v"},
    {"Select All", "selectAll:", "a"},
  };

  for (auto &[title, action, key] : items) {
    id mi = msg_mi(msg(cls("NSMenuItem"), sel("alloc")),
                   sel("initWithTitle:action:keyEquivalent:"),
                   str(title), sel(action), str(key));
    msg_v(editMenu, sel("addItem:"), mi);
  }

  msg_v(editItem, sel("setSubmenu:"), editMenu);
  msg_v(mainMenu, sel("addItem:"), editItem);
  msg_v(app, sel("setMainMenu:"), mainMenu);
}
#endif
```

`w.run()`の前に呼び出します。

```cpp
#ifdef __APPLE__
  setup_macos_edit_menu();
#endif
  w.run();
```

WindowsとLinuxでは、キーボードショートカットはメニューバーを介さずフォーカスのあるコントロールに直接届くので、この対処はmacOS固有です。

## 6.5 全体のコード

<details>
<summary data-file="CMakeLists.txt">全体のコード（CMakeLists.txt）</summary>

```cmake
cmake_minimum_required(VERSION 3.20)
project(translate-app CXX)
set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

# llama.cpp
FetchContent_Declare(llama
    GIT_REPOSITORY https://github.com/ggml-org/llama.cpp
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(llama)

# cpp-httplib
FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib
    GIT_TAG        master
)
FetchContent_MakeAvailable(httplib)

# nlohmann/json
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# cpp-llamalib
FetchContent_Declare(cpp_llamalib
    GIT_REPOSITORY https://github.com/yhirose/cpp-llamalib
    GIT_TAG        main
)
FetchContent_MakeAvailable(cpp_llamalib)

# webview/webview
FetchContent_Declare(webview
    GIT_REPOSITORY https://github.com/webview/webview
    GIT_TAG        master
)
FetchContent_MakeAvailable(webview)

# cpp-embedlib
FetchContent_Declare(cpp-embedlib
    GIT_REPOSITORY https://github.com/yhirose/cpp-embedlib
    GIT_TAG        main
)
FetchContent_MakeAvailable(cpp-embedlib)

# public/ ディレクトリをバイナリに埋め込む
cpp_embedlib_add(WebAssets
    FOLDER    ${CMAKE_CURRENT_SOURCE_DIR}/public
    NAMESPACE Web
)

find_package(OpenSSL REQUIRED)

add_executable(translate-app src/main.cpp)

target_link_libraries(translate-app PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    cpp-llamalib
    OpenSSL::SSL OpenSSL::Crypto
    WebAssets
    cpp-embedlib-httplib
    webview::core
)

if(APPLE)
    target_link_libraries(translate-app PRIVATE
        "-framework CoreFoundation"
        "-framework Security"
    )
endif()

target_compile_definitions(translate-app PRIVATE
    CPPHTTPLIB_OPENSSL_SUPPORT
)
```

</details>

<details>
<summary data-file="main.cpp">全体のコード（main.cpp）</summary>

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cpp-llamalib.h>
#include <cpp-embedlib-httplib.h>
#include "WebAssets.h"
#include "webview/webview.h"

#ifdef __APPLE__
#include <objc/objc-runtime.h>
#endif

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>

using json = nlohmann::json;

// -------------------------------------------------------------------------
// macOS Editメニュー（Cmd+C/V/X/AにはEditメニューが必要）
// -------------------------------------------------------------------------

#ifdef __APPLE__
void setup_macos_edit_menu() {
  auto cls    = [](const char *n) { return (id)objc_getClass(n); };
  auto sel    = sel_registerName;
  auto msg    = reinterpret_cast<id (*)(id, SEL)>(objc_msgSend);
  auto msg_s  = reinterpret_cast<id (*)(id, SEL, const char *)>(objc_msgSend);
  auto msg_id = reinterpret_cast<id (*)(id, SEL, id)>(objc_msgSend);
  auto msg_v  = reinterpret_cast<void (*)(id, SEL, id)>(objc_msgSend);
  auto msg_mi = reinterpret_cast<id (*)(id, SEL, id, SEL, id)>(objc_msgSend);

  auto str = [&](const char *s) {
    return msg_s(cls("NSString"), sel("stringWithUTF8String:"), s);
  };

  id app      = msg(cls("NSApplication"), sel("sharedApplication"));
  id mainMenu = msg(msg(cls("NSMenu"), sel("alloc")), sel("init"));
  id editItem = msg(msg(cls("NSMenuItem"), sel("alloc")), sel("init"));
  id editMenu = msg_id(msg(cls("NSMenu"), sel("alloc")),
                       sel("initWithTitle:"), str("Edit"));

  struct { const char *title; const char *action; const char *key; } items[] = {
    {"Undo",       "undo:",      "z"},
    {"Redo",       "redo:",      "Z"},
    {"Cut",        "cut:",       "x"},
    {"Copy",       "copy:",      "c"},
    {"Paste",      "paste:",     "v"},
    {"Select All", "selectAll:", "a"},
  };

  for (auto &[title, action, key] : items) {
    id mi = msg_mi(msg(cls("NSMenuItem"), sel("alloc")),
                   sel("initWithTitle:action:keyEquivalent:"),
                   str(title), sel(action), str(key));
    msg_v(editMenu, sel("addItem:"), mi);
  }

  msg_v(editItem, sel("setSubmenu:"), editMenu);
  msg_v(mainMenu, sel("addItem:"), editItem);
  msg_v(app, sel("setMainMenu:"), mainMenu);
}
#endif

// -------------------------------------------------------------------------
// モデル定義
// -------------------------------------------------------------------------

struct ModelInfo {
  std::string name;
  std::string params;
  std::string size;
  std::string repo;
  std::string filename;
};

const std::vector<ModelInfo> MODELS = {
  {
    .name     = "gemma-2-2b-it",
    .params   = "2B",
    .size     = "1.6 GB",
    .repo     = "bartowski/gemma-2-2b-it-GGUF",
    .filename = "gemma-2-2b-it-Q4_K_M.gguf",
  },
  {
    .name     = "gemma-2-9b-it",
    .params   = "9B",
    .size     = "5.8 GB",
    .repo     = "bartowski/gemma-2-9b-it-GGUF",
    .filename = "gemma-2-9b-it-Q4_K_M.gguf",
  },
  {
    .name     = "Llama-3.1-8B-Instruct",
    .params   = "8B",
    .size     = "4.9 GB",
    .repo     = "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
    .filename = "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
  },
};

// -------------------------------------------------------------------------
// モデル保存ディレクトリ
// -------------------------------------------------------------------------

std::filesystem::path get_models_dir() {
#ifdef _WIN32
  auto env = std::getenv("APPDATA");
  auto base = env ? std::filesystem::path(env) : std::filesystem::path(".");
  return base / "translate-app" / "models";
#else
  auto env = std::getenv("HOME");
  auto base = env ? std::filesystem::path(env) : std::filesystem::path(".");
  return base / ".translate-app" / "models";
#endif
}

// -------------------------------------------------------------------------
// モデルダウンロード
// -------------------------------------------------------------------------

// progress_cbがfalseを返したらダウンロードを中断する
bool download_model(const ModelInfo &model,
                    std::function<bool(int)> progress_cb) {
  httplib::Client cli("https://huggingface.co");
  cli.set_follow_location(true);  // Hugging FaceはCDNにリダイレクトする
  cli.set_read_timeout(std::chrono::hours(1)); // 大きなモデルに備えて長めに

  auto url = "/" + model.repo + "/resolve/main/" + model.filename;
  auto path = get_models_dir() / model.filename;
  auto tmp_path = std::filesystem::path(path).concat(".tmp");

  std::ofstream ofs(tmp_path, std::ios::binary);
  if (!ofs) { return false; }

  auto res = cli.Get(url,
    // content_receiver: チャンクごとにデータを受け取ってファイルに書き込む
    [&](const char *data, size_t len) {
      ofs.write(data, len);
      return ofs.good();
    },
    // progress: ダウンロード進捗を通知（falseを返すと中断）
    [&, last_pct = -1](size_t current, size_t total) mutable {
      int pct = total ? (int)(current * 100 / total) : 0;
      if (pct == last_pct) return true; // 同じ値なら通知をスキップ
      last_pct = pct;
      return progress_cb(pct);
    });

  ofs.close();

  if (!res || res->status != 200) {
    std::filesystem::remove(tmp_path);
    return false;
  }

  // ダウンロード完了後にリネーム
  std::filesystem::rename(tmp_path, path);
  return true;
}

// -------------------------------------------------------------------------
// サーバー
// -------------------------------------------------------------------------

int main() {
  httplib::Server svr;
  // モデル保存ディレクトリを作成
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  // デフォルトモデルが未ダウンロードなら自動取得
  std::string selected_model = MODELS[0].filename;
  auto path = models_dir / selected_model;
  if (!std::filesystem::exists(path)) {
    std::cout << "Downloading " << selected_model << "..." << std::endl;
    if (!download_model(MODELS[0], [](int pct) {
          std::cout << "\r" << pct << "%" << std::flush;
          return true;
        })) {
      std::cerr << "\nFailed to download model." << std::endl;
      return 1;
    }
    std::cout << std::endl;
  }
  auto llm = llamalib::Llama{path};
  std::mutex llm_mutex; // モデル切り替え中のアクセスを保護する

  // LLM推論は時間がかかるのでタイムアウトを長めに設定（デフォルトは5秒）
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // --- 翻訳エンドポイント（2章） -----------------------------------------

  svr.Post("/translate",
           [&](const httplib::Request &req, httplib::Response &res) {
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
      std::lock_guard<std::mutex> lock(llm_mutex);
      auto translation = llm.chat(prompt);
      res.set_content(json{{"translation", translation}}.dump(),
                      "application/json");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(json{{"error", e.what()}}.dump(), "application/json");
    }
  });

  // --- SSEストリーミング翻訳（3章）--------------------------------------

  svr.Post("/translate/stream",
           [&](const httplib::Request &req, httplib::Response &res) {
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
          std::lock_guard<std::mutex> lock(llm_mutex);
          try {
            llm.chat(prompt, [&](std::string_view token) {
              sink.os << "data: "
                      << json(std::string(token)).dump(
                           -1, ' ', false, json::error_handler_t::replace)
                      << "\n\n";
              return sink.os.good(); // 切断されたら推論を中断
            });
            sink.os << "data: [DONE]\n\n";
          } catch (const std::exception &e) {
            sink.os << "data: " << json({{"error", e.what()}}).dump() << "\n\n";
          }
          sink.done();
          return true;
        });
  });

  // --- モデル一覧（4章） -------------------------------------------------

  svr.Get("/models",
          [&](const httplib::Request &, httplib::Response &res) {
    auto models_dir = get_models_dir();
    auto arr = json::array();
    for (const auto &m : MODELS) {
      auto path = models_dir / m.filename;
      arr.push_back({
        {"name",       m.name},
        {"params",     m.params},
        {"size",       m.size},
        {"downloaded", std::filesystem::exists(path)},
        {"selected",   m.filename == selected_model},
      });
    }
    res.set_content(json{{"models", arr}}.dump(), "application/json");
  });

  // --- モデル選択（4章） -------------------------------------------------

  svr.Post("/models/select",
           [&](const httplib::Request &req, httplib::Response &res) {
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded() || !input.contains("model")) {
      res.status = 400;
      res.set_content(json{{"error", "'model' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto name = input["model"].get<std::string>();

    auto it = std::find_if(MODELS.begin(), MODELS.end(),
      [&](const ModelInfo &m) { return m.name == name; });

    if (it == MODELS.end()) {
      res.status = 404;
      res.set_content(json{{"error", "Unknown model"}}.dump(),
                      "application/json");
      return;
    }

    const auto &model = *it;

    // 常にSSEで応答する（DL済みでも未DLでも同じ形式）
    res.set_chunked_content_provider(
        "text/event-stream",
        [&, model](size_t, httplib::DataSink &sink) {
          // SSEイベント送信ヘルパー
          auto send = [&](const json &event) {
            sink.os << "data: " << event.dump() << "\n\n";
          };

          // 未ダウンロードならダウンロード（進捗をSSEで通知）
          auto path = get_models_dir() / model.filename;
          if (!std::filesystem::exists(path)) {
            bool ok = download_model(model, [&](int pct) {
              send({{"status", "downloading"}, {"progress", pct}});
              return sink.os.good(); // クライアント切断時にダウンロードを中断
            });
            if (!ok) {
              send({{"status", "error"}, {"message", "Download failed"}});
              sink.done();
              return true;
            }
          }

          // モデルをロードして切り替え
          send({{"status", "loading"}});
          {
            std::lock_guard<std::mutex> lock(llm_mutex);
            llm = llamalib::Llama{path};
            selected_model = model.filename;
          }

          send({{"status", "ready"}});
          sink.done();
          return true;
        });
  });

  // --- 埋め込みファイル配信（6章） ---------------------------------------
  // 5章: svr.set_mount_point("/", "./public");
  httplib::mount(svr, Web::FS);

  // サーバーをバックグラウンドスレッドで起動
  auto port = svr.bind_to_any_port("127.0.0.1");
  std::thread server_thread([&]() { svr.listen_after_bind(); });

  std::cout << "Listening on http://127.0.0.1:" << port << std::endl;

  // WebViewでUIを表示
  webview::webview w(false, nullptr);
  w.set_title("Translate App");
  w.set_size(1024, 768, WEBVIEW_HINT_NONE);
  w.navigate("http://127.0.0.1:" + std::to_string(port));

#ifdef __APPLE__
  setup_macos_edit_menu();
#endif
  w.run(); // ウインドウが閉じるまでブロック

  // ウインドウが閉じたらサーバーも停止
  svr.stop();
  server_thread.join();
}
```

</details>

5章からの変更点をまとめると:

- `#include <csignal>` → `#include <thread>`, `<cpp-embedlib-httplib.h>`, `"WebAssets.h"`, `"webview/webview.h"`
- `signal_handler`関数を削除
- `svr.set_mount_point("/", "./public")` → `httplib::mount(svr, Web::FS)`
- `svr.listen("127.0.0.1", 8080)` → `bind_to_any_port` + `listen_after_bind` + WebViewのイベントループ

ハンドラのコードは1行も変わっていません。5章まで作ってきたREST API・SSEストリーミング・モデル管理がそのまま動きます。

## 6.6 ビルドと動作確認

```bash
cmake -B build
cmake --build build -j
```

起動します。

```bash
./build/translate-app
```

ブラウザは不要です。ウインドウが自動で開きます。5章と同じUIがそのまま表示され、翻訳やモデル切り替えがすべてそのまま動きます。

ウインドウを閉じるとサーバーも自動で終了します。`Ctrl+C`は不要です。

### 何が配布に必要か

配布に必要なのは:

- `translate-app`バイナリ1つ

これだけです。`public/`ディレクトリは不要です。HTML・CSS・JavaScriptはバイナリに埋め込まれています。モデルファイルは初回起動時に自動ダウンロードするので、ユーザーに事前準備を求める必要もありません。

## 次の章へ

お疲れさまでした！🎉

1章では`/health`が`{"status":"ok"}`を返すだけでした。それが今、テキストを入力すればリアルタイムで翻訳が流れ、ドロップダウンからモデルを切り替えれば自動でダウンロードが始まり、ウインドウを閉じればサーバーも一緒に終了する―そんなデスクトップアプリになりました。しかもバイナリ1つで配れます。

6章で変えたのは、静的ファイルの配信方法とサーバーの起動方法だけです。ハンドラのコードは1行も変わっていません。5章までに積み上げてきたREST API・SSEストリーミング・モデル管理が、そのままデスクトップアプリとして動いています。

次の章では視点を変えて、llama.cpp本家の`llama-server`のコードを読みます。本書のシンプルなサーバーと、プロダクション品質のサーバーを比較して、設計判断の違いとその理由を学びましょう。

**Next:** [llama.cpp本家のサーバー実装をコードリーディング](../ch07-code-reading)
