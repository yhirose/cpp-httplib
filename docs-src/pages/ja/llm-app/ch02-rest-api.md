---
title: "2. llama.cppを組み込んでREST APIを作る"
order: 2

---

1章の雛形では`/translate`が`"TODO"`を返すだけでした。この章ではllama.cppの推論を組み込んで、実際に翻訳結果を返すAPIに仕上げます。

llama.cppのAPIを直接扱うとコードが長くなるので、薄いラッパーライブラリ[cpp-llamalib](https://github.com/yhirose/cpp-llamalib)を使います。モデルのロードから推論まで数行で書けるので、cpp-httplibの使い方に集中できます。

## 2.1 LLMの初期化

`llamalib::Llama`にモデルファイルのパスを渡すだけで、モデルのロード・コンテキスト作成・サンプラー設定がすべて済みます。1章で別のモデルをダウンロードした場合は、パスをそのモデルに合わせてください。

```cpp
#include <cpp-llamalib.h>

int main() {
  auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf"};

  // LLM推論は時間がかかるのでタイムアウトを長めに設定（デフォルトは5秒）
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  // ... HTTPサーバーの構築・起動 ...
}
```

GPU層数やコンテキスト長などを変えたい場合は`llamalib::Options`で指定できます。

```cpp
auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf", {
  .n_gpu_layers = 0,  // CPUのみ
  .n_ctx = 4096,
}};
```

## 2.2 `/translate`ハンドラ

1章ではダミーのJSONを返していたハンドラを、実際の推論に差し替えます。

```cpp
svr.Post("/translate",
         [&](const httplib::Request &req, httplib::Response &res) {
  // JSONパース（第3引数`false`: 失敗時に例外を投げず`is_discarded()`で判定）
  auto input = json::parse(req.body, nullptr, false);
  if (input.is_discarded()) {
    res.status = 400;
    res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                    "application/json");
    return;
  }

  // 必須フィールドの検証
  if (!input.contains("text") || !input["text"].is_string() ||
      input["text"].get<std::string>().empty()) {
    res.status = 400;
    res.set_content(json{{"error", "'text' is required"}}.dump(),
                    "application/json");
    return;
  }

  auto text = input["text"].get<std::string>();
  auto target_lang = input.value("target_lang", "ja"); // デフォルトは日本語

  // プロンプトを組み立てて推論
  auto prompt = "Translate the following text to " + target_lang +
                ". Output only the translation, nothing else.\n\n" + text;

  try {
    auto translation = llm.chat(prompt);
    res.set_content(json{{"translation", translation}}.dump(),
                    "application/json");
  } catch (const std::exception &e) {
    res.status = 500;
    res.set_content(json{{"error", e.what()}}.dump(), "application/json");
  }
});
```

`llm.chat()`は推論中に例外を投げることがあります（コンテキスト長の超過など）。`try/catch`で捕捉してエラーをJSONで返すことで、サーバーがクラッシュするのを防ぎます。

## 2.3 全体のコード

ここまでの変更をまとめた完成形です。

<details>
<summary data-file="main.cpp">全体のコード（main.cpp）</summary>

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cpp-llamalib.h>

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
  // 1章でダウンロードしたモデルをロード
  auto llm = llamalib::Llama{"models/gemma-2-2b-it-Q4_K_M.gguf"};

  // LLM推論は時間がかかるのでタイムアウトを長めに設定（デフォルトは5秒）
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  // リクエストとレスポンスをログに記録
  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  svr.Post("/translate",
           [&](const httplib::Request &req, httplib::Response &res) {
    // JSONパース（第3引数`false`: 失敗時に例外を投げず`is_discarded()`で判定）
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded()) {
      res.status = 400;
      res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                      "application/json");
      return;
    }

    // 必須フィールドの検証
    if (!input.contains("text") || !input["text"].is_string() ||
        input["text"].get<std::string>().empty()) {
      res.status = 400;
      res.set_content(json{{"error", "'text' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto text = input["text"].get<std::string>();
    auto target_lang = input.value("target_lang", "ja"); // デフォルトは日本語

    // プロンプトを組み立てて推論
    auto prompt = "Translate the following text to " + target_lang +
                  ". Output only the translation, nothing else.\n\n" + text;

    try {
      auto translation = llm.chat(prompt);
      res.set_content(json{{"translation", translation}}.dump(),
                      "application/json");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(json{{"error", e.what()}}.dump(), "application/json");
    }
  });

  // 以降の章で本物に差し替えるダミー実装
  svr.Get("/models",
          [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"models", json::array()}}.dump(), "application/json");
  });

  svr.Post("/models/select",
           [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "TODO"}}.dump(), "application/json");
  });

  // `Ctrl+C` (`SIGINT`)や`kill` (`SIGTERM`)でサーバーを停止できるようにする
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // サーバー起動（`stop()`が呼ばれるまでブロック）
  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 2.4 動作確認

ビルドし直してサーバーを起動し、今度は実際の翻訳結果が返ってくるか確かめましょう。

```bash
cmake --build build -j
./build/translate-server
```

```bash
curl -X POST http://localhost:8080/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "I had a great time visiting Tokyo last spring. The cherry blossoms were beautiful.", "target_lang": "ja"}'
# => {"translation":"去年の春に東京を訪れた。桜が綺麗だった。"}
```

1章では`"TODO"`が返ってきていましたが、今度は実際の翻訳結果が返ってきます。

## 次の章へ

この章で作ったREST APIは、翻訳が完了するまで全文を待つので、長いテキストだとユーザーは進捗がわからないまま待つことになります。

次の章ではSSE（Server-Sent Events）を使って、トークンが生成されるたびにリアルタイムで返す仕組みにします。

**Next:** [SSEでトークンストリーミングを追加する](../ch03-sse-streaming)
