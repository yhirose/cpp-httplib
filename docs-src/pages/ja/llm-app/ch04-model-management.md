---
title: "4. モデルの取得・管理機能を追加する"
order: 4

---

3章まででサーバーの翻訳機能は一通り揃いました。しかし、モデルファイルは1章で手動ダウンロードした1つだけです。この章ではcpp-httplibの**クライアント機能**を使い、アプリ内からHugging Faceのモデルをダウンロード・切り替えできるようにします。

完成すると、こんなリクエストでモデルを管理できるようになります。

```bash
# 利用可能なモデル一覧を取得
curl http://localhost:8080/models
```

```json
{
  "models": [
    {"name": "gemma-2-2b-it", "params": "2B", "size": "1.6 GB", "downloaded": true, "selected": true},
    {"name": "gemma-2-9b-it", "params": "9B", "size": "5.8 GB", "downloaded": false, "selected": false},
    {"name": "Llama-3.1-8B-Instruct", "params": "8B", "size": "4.9 GB", "downloaded": false, "selected": false}
  ]
}
```

```bash
# 別のモデルを選択（未ダウンロードなら自動で取得）
curl -N -X POST http://localhost:8080/models/select \
  -H "Content-Type: application/json" \
  -d '{"model": "gemma-2-9b-it"}'
```

```text
data: {"status":"downloading","progress":0}
data: {"status":"downloading","progress":12}
...
data: {"status":"downloading","progress":100}
data: {"status":"loading"}
data: {"status":"ready"}
```

## 4.1 httplib::Clientの基本

これまでは`httplib::Server`だけを使ってきましたが、cpp-httplibはクライアント機能も備えています。Hugging FaceはHTTPSなので、TLS対応のクライアントが必要です。

```cpp
#include <httplib.h>

// URLスキームを含めると自動でSSLClientが使われる
httplib::Client cli("https://huggingface.co");

// リダイレクト先を自動で追従（Hugging FaceはCDNにリダイレクトする）
cli.set_follow_location(true);

auto res = cli.Get("/api/models");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

HTTPSを使うには、ビルド時にOpenSSLを有効にする必要があります。`CMakeLists.txt`に以下を追加しましょう。

```cmake
find_package(OpenSSL REQUIRED)

target_link_libraries(translate-server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(translate-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)

# macOS: システム証明書の読み込みに必要
if(APPLE)
  target_link_libraries(translate-server PRIVATE "-framework CoreFoundation" "-framework Security")
endif()
```

`CPPHTTPLIB_OPENSSL_SUPPORT`を定義すると、`httplib::Client("https://...")`がTLS接続を行います。macOSではシステム証明書ストアにアクセスするため、CoreFoundationとSecurityフレームワークのリンクも必要です。完全な`CMakeLists.txt`は4.8節にあります。

## 4.2 モデル一覧を定義する

アプリが扱えるモデルの一覧を定義します。翻訳タスクで検証済みの4モデルを用意しました。

```cpp
struct ModelInfo {
  std::string name;       // 表示名
  std::string params;     // パラメータ数
  std::string size;       // GGUF Q4サイズ
  std::string repo;       // Hugging Faceリポジトリ
  std::string filename;   // GGUFファイル名
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
```

## 4.3 モデルの保存場所

3章まではプロジェクトディレクトリ内の`models/`にモデルを置いていました。しかし複数モデルを管理するなら、アプリ専用のディレクトリに保存する方が適切です。macOS/Linuxでは`~/.translate-app/models/`、Windowsでは`%APPDATA%\translate-app\models\`を使います。

```cpp
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
```

環境変数が未設定の場合はカレントディレクトリにフォールバックします。このディレクトリはアプリ起動時に自動作成します（`create_directories`は既に存在していてもエラーになりません）。

## 4.4 モデルの初期化を書き換える

モデルの初期化を`main()`の先頭で書き換えます。1章ではパスをハードコードしていましたが、ここからはモデルの切り替えに対応します。現在ロード中のファイル名は`selected_model`変数で管理します。起動時は`MODELS`の先頭エントリーをロードします。この変数は`GET /models`や`POST /models/select`のハンドラから参照・更新します。

cpp-httplibはスレッドプールでハンドラを並行実行します。そのため、モデル切り替え中（`llm`の上書き中）に別スレッドで`llm.chat()`が走るとクラッシュします。`std::mutex`で排他制御を入れておきます。

```cpp
int main() {
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  std::string selected_model = MODELS[0].filename;
  auto path = models_dir / selected_model;

  // デフォルトモデルが未ダウンロードなら起動時に自動取得
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
  // ...
}
```

初回起動時にユーザーが`curl`で手動ダウンロードしなくても済むようにしています。4.6節の`download_model`関数を使い、進捗をコンソールに表示します。

## 4.5 `GET /models`ハンドラ

モデル一覧に「ダウンロード済みか」「選択中か」の情報を付けて返します。

```cpp
svr.Get("/models",
        [&](const httplib::Request &, httplib::Response &res) {
  auto arr = json::array();
  for (const auto &m : MODELS) {
    auto path = get_models_dir() / m.filename;
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
```

## 4.6 大きなファイルをダウンロードする

GGUFモデルは数GBあるため、全体をメモリに載せるわけにはいきません。`httplib::Client::Get`にコールバックを渡すと、チャンクごとにデータを受け取れます。

```cpp
// content_receiver: データチャンクを受け取るコールバック
// progress: ダウンロード進捗コールバック
cli.Get(url,
  [&](const char *data, size_t len) {       // content_receiver
    ofs.write(data, len);
    return true;  // falseを返すと中断
  },
  [&](size_t current, size_t total) {        // progress
    int pct = total ? (int)(current * 100 / total) : 0;
    std::cout << pct << "%" << std::endl;
    return true;  // falseを返すと中断
  });
```

これを使ってHugging Faceからモデルをダウンロードする関数を作ります。

```cpp
#include <filesystem>
#include <fstream>

// モデルをダウンロードし、進捗をprogress_cbで通知する
// progress_cbがfalseを返すとダウンロードを中断する
bool download_model(const ModelInfo &model,
                    std::function<bool(int)> progress_cb) {
  httplib::Client cli("https://huggingface.co");
  cli.set_follow_location(true);
  cli.set_read_timeout(std::chrono::hours(1));

  auto url = "/" + model.repo + "/resolve/main/" + model.filename;
  auto path = get_models_dir() / model.filename;
  auto tmp_path = std::filesystem::path(path).concat(".tmp");

  std::ofstream ofs(tmp_path, std::ios::binary);
  if (!ofs) { return false; }

  auto res = cli.Get(url,
    [&](const char *data, size_t len) {
      ofs.write(data, len);
      return ofs.good();
    },
    [&](size_t current, size_t total) {
      return progress_cb(total ? (int)(current * 100 / total) : 0);
    });

  ofs.close();

  if (!res || res->status != 200) {
    std::filesystem::remove(tmp_path);
    return false;
  }

  // .tmpに書いてからリネームすることで、DLが途中で止まっても
  // 不完全なファイルがモデルとして使われるのを防ぐ
  std::filesystem::rename(tmp_path, path);
  return true;
}
```

## 4.7 `/models/select`ハンドラ

モデルの選択リクエストを処理します。レスポンスは常にSSEで返し、ダウンロード進捗 → ロード → 完了のステータスを順に通知します。

```cpp
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

  // モデル一覧から探す
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
```

いくつか補足します。

- `download_model`の進捗コールバックから直接SSEイベントを送っています。3章の`set_chunked_content_provider` + `sink.os`の応用です
- コールバックが`sink.os.good()`を返すので、クライアントが接続を切るとダウンロードも中断します。5章で追加するキャンセルボタンで使います
- `selected_model`を更新すると、`GET /models`の`selected`フラグに反映されます
- `llm`の上書きを`llm_mutex`で保護しています。`/translate`や`/translate/stream`のハンドラも同じ`mutex`でロックするので、モデル切り替え中に推論が走ることはありません（全体コードを参照）

## 4.8 全体のコード

3章のコードにモデル管理機能を追加した完成形です。

<details>
<summary data-file="CMakeLists.txt">全体のコード（CMakeLists.txt）</summary>

```cmake
cmake_minimum_required(VERSION 3.20)
project(translate-server CXX)
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

find_package(OpenSSL REQUIRED)

add_executable(translate-server src/main.cpp)

target_link_libraries(translate-server PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    cpp-llamalib
    OpenSSL::SSL OpenSSL::Crypto
)

target_compile_definitions(translate-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)

if(APPLE)
    target_link_libraries(translate-server PRIVATE
        "-framework CoreFoundation"
        "-framework Security"
    )
endif()
```

</details>

<details>
<summary data-file="main.cpp">全体のコード（main.cpp）</summary>

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cpp-llamalib.h>

#include <algorithm>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>

using json = nlohmann::json;

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

httplib::Server svr;

void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
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
    // JSONパース・バリデーション（詳細は2章を参照）
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

  // `Ctrl+C` (`SIGINT`)や`kill` (`SIGTERM`)でサーバーを停止できるようにする
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 4.9 動作確認

CMakeLists.txtにOpenSSLの設定を追加したので、CMakeを再実行してからビルドします。

```bash
cmake -B build
cmake --build build -j
./build/translate-server
```

### モデル一覧の確認

```bash
curl http://localhost:8080/models
```

1章でダウンロードした`gemma-2-2b-it`が`downloaded: true`、`selected: true`になっているはずです。

### 別のモデルに切り替える

```bash
curl -N -X POST http://localhost:8080/models/select \
  -H "Content-Type: application/json" \
  -d '{"model": "gemma-2-9b-it"}'
```

SSEでダウンロード進捗が流れ、完了すると`"ready"`が返ります。

### 複数モデルで翻訳を比較する

同じ例文を異なるモデルで翻訳してみましょう。

```bash
# gemma-2-9b-itで翻訳（先ほど切り替えたモデル）
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "The quick brown fox jumps over the lazy dog.", "target_lang": "ja"}'

# gemma-2-2b-itに戻す
curl -N -X POST http://localhost:8080/models/select \
  -H "Content-Type: application/json" \
  -d '{"model": "gemma-2-2b-it"}'

# 同じ文を翻訳
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "The quick brown fox jumps over the lazy dog.", "target_lang": "ja"}'
```

同じコード・同じプロンプトでもモデルによって翻訳結果が変わることがわかります。cpp-llamalibがモデルごとのチャットテンプレートを自動適用するので、コード側の変更は不要です。

## 次の章へ

これでサーバーの主要な機能が揃いました。REST API、SSEストリーミング、モデルのダウンロードと切り替え。次の章では静的ファイル配信を追加して、ブラウザから操作できるWeb UIを作ります。

**Next:** [Web UIを追加する](../ch05-web-ui)
