---
title: "1. プロジェクト環境を作る"
order: 1

---

llama.cppを推論エンジンに使って、テキスト翻訳のREST APIサーバーを段階的に作っていきます。最終的にはこんなリクエストで翻訳結果が返ってくるようになります。

```bash
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "The weather is nice today. Shall we go for a walk?", "target_lang": "ja"}'
```

```json
{
  "translation": "今日はいい天気ですね。散歩に行きましょうか？"
}
```

「翻訳API」はあくまで一例です。プロンプトを差し替えれば、要約・コード生成・チャットボットなど、お好きなLLMアプリに応用できます。

最終的にサーバーが提供するAPIの一覧です。

| メソッド | パス | 説明 | 章 |
| -------- | ---- | ---- | -- |
| `GET` | `/health` | サーバーの状態を返す | 1 |
| `POST` | `/translate` | テキストを翻訳してJSONで返す | 2 |
| `POST` | `/translate/stream` | トークン単位でSSEストリーミング | 3 |
| `GET` | `/models` | モデル一覧（available / downloaded / selected） | 4 |
| `POST` | `/models/select` | モデルを選択（未ダウンロードなら自動取得） | 4 |

この章では、まずプロジェクトの環境を整えます。依存ライブラリの取得、ディレクトリ構成、ビルド設定、モデルファイルの入手まで済ませて、次の章ですぐにコードを書き始められるようにしましょう。

## 前提条件

- C++20対応コンパイラ（GCC 10+、Clang 10+、MSVC 2019 16.8+）
- CMake 3.20以上
- OpenSSL（4章でHTTPSクライアントに使用。macOS: `brew install openssl`、Ubuntu: `sudo apt install libssl-dev`）
- 十分なディスク容量（モデルファイルが数GBになります）

## 1.1 何を使うか

使うライブラリはこちらです。

| ライブラリ | 役割 |
| ----------- | ------ |
| [cpp-httplib](https://github.com/yhirose/cpp-httplib) | HTTPサーバー/クライアント |
| [nlohmann/json](https://github.com/nlohmann/json) | JSONパーサー |
| [cpp-llamalib](https://github.com/yhirose/cpp-llamalib) | llama.cppラッパー |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) | LLM推論エンジン |
| [webview/webview](https://github.com/webview/webview) | デスクトップWebView（6章で使用） |

cpp-httplib、nlohmann/json、cpp-llamalibはヘッダーオンリーライブラリです。`curl`でヘッダーファイルを1枚ダウンロードして`#include`するだけでも使えますが、本書ではCMakeの`FetchContent`で自動取得します。`CMakeLists.txt`に書いておけば、`cmake -B build`の時点で全ライブラリが自動でダウンロード・ビルドされるので、手作業の手順が減ります。`webview`は6章で使うので、今は気にしなくて大丈夫です。

## 1.2 ディレクトリ構成

最終的にこんな構成になります。

```ascii
translate-app/
├── CMakeLists.txt
├── models/
│   └── (GGUFファイル)
└── src/
    └── main.cpp
```

ライブラリのソースコードはプロジェクトに含めません。CMakeの`FetchContent`がビルド時に自動で取得するので、必要なのは自分のコードだけです。

プロジェクトディレクトリを作って、gitリポジトリにしましょう。

```bash
mkdir translate-app && cd translate-app
mkdir src models
git init
```

## 1.3 GGUFモデルファイルを入手する

LLMの推論にはモデルファイルが必要です。GGUFはllama.cppが使うモデル形式で、Hugging Faceにたくさんあります。

まずは小さいモデルで試してみましょう。GoogleのGemma 2 2Bの量子化版（約1.6GB）がおすすめです。軽量ですが多言語に対応していて、翻訳タスクにも向いています。

```bash
curl -L -o models/gemma-2-2b-it-Q4_K_M.gguf \
  https://huggingface.co/bartowski/gemma-2-2b-it-GGUF/resolve/main/gemma-2-2b-it-Q4_K_M.gguf
```

4章で、このダウンロード自体をアプリ内からcpp-httplibのクライアント機能で行えるようにします。

## 1.4 CMakeLists.txt

プロジェクトルートに`CMakeLists.txt`を作ります。`FetchContent`で依存ライブラリを宣言しておくと、CMakeが自動でダウンロード・ビルドしてくれます。

<!-- data-file="CMakeLists.txt" -->
```cmake
cmake_minimum_required(VERSION 3.20)
project(translate-server CXX)
set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

# llama.cpp（LLM推論エンジン）
FetchContent_Declare(llama
    GIT_REPOSITORY https://github.com/ggml-org/llama.cpp
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(llama)

# cpp-httplib（HTTPサーバー/クライアント）
FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib
    GIT_TAG        master
)
FetchContent_MakeAvailable(httplib)

# nlohmann/json（JSONパーサー）
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# cpp-llamalib（llama.cppヘッダーオンリーラッパー）
FetchContent_Declare(cpp_llamalib
    GIT_REPOSITORY https://github.com/yhirose/cpp-llamalib
    GIT_TAG        main
)
FetchContent_MakeAvailable(cpp_llamalib)

add_executable(translate-server src/main.cpp)

target_link_libraries(translate-server PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    cpp-llamalib
)
```

`FetchContent_Declare`でライブラリのソース取得先を宣言し、`FetchContent_MakeAvailable`で実際に取得・ビルドします。初回の`cmake -B build`は全ライブラリのダウンロードとllama.cppのビルドが走るので時間がかかりますが、2回目以降はキャッシュが効きます。

`target_link_libraries`でリンクするだけで、インクルードパスやビルド設定は各ライブラリのCMakeが自動で設定してくれます。

## 1.5 雛形コードの作成

この雛形コードをベースに、章ごとに機能を追加していきます。

<!-- data-file="main.cpp" -->
```cpp
// src/main.cpp
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <csignal>
#include <iostream>

using json = nlohmann::json;

httplib::Server svr;

// `Ctrl+C`でgraceful shutdown
void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // リクエストとレスポンスをログに記録
  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  // ヘルスチェック
  svr.Get("/health", [](const auto &, auto &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // 各エンドポイントのダミー実装（以降の章で本物に差し替えていく）
  svr.Post("/translate",
           [](const auto &req, auto &res) {
    res.set_content(json{{"translation", "TODO"}}.dump(), "application/json");
  });

  svr.Post("/translate/stream",
           [](const auto &req, auto &res) {
    res.set_content("data: \"TODO\"\n\ndata: [DONE]\n\n", "text/event-stream");
  });

  svr.Get("/models",
          [](const auto &req, auto &res) {
    res.set_content(json{{"models", json::array()}}.dump(), "application/json");
  });

  svr.Post("/models/select",
           [](const auto &req, auto &res) {
    res.set_content(json{{"status", "TODO"}}.dump(), "application/json");
  });

  // `Ctrl+C` (`SIGINT`)や`kill` (`SIGTERM`)でサーバーを停止できるようにする
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // サーバー起動
  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

## 1.6 ビルドと動作確認

ビルドしてサーバーを起動し、curlでリクエストが通るか確かめます。

```bash
cmake -B build
cmake --build build -j
./build/translate-server
```

別のターミナルからcurlで確認してみましょう。

```bash
curl http://localhost:8080/health
# => {"status":"ok"}
```

JSONが返ってくれば環境構築は完了です。

## 次の章へ

環境が整ったので、次の章ではこの雛形に翻訳REST APIを実装します。llama.cppで推論を行い、cpp-httplibでそれをHTTPエンドポイントとして公開します。

**Next:** [llama.cppを組み込んでREST APIを作る](../ch02-rest-api)
