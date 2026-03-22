---
title: "3. SSEでトークンストリーミングを追加する"
order: 3

---

2章の`/translate`は、翻訳が完了してから結果をまとめて返していました。短い文なら問題ありませんが、長い文だとユーザーは何も表示されないまま何秒も待つことになります。

この章ではSSE（Server-Sent Events）を使って、トークンが生成されるたびにリアルタイムで返す`/translate/stream`エンドポイントを追加します。ChatGPTやClaudeのAPIでおなじみの方式です。

## 3.1 SSEとは

SSEはHTTPのレスポンスをストリームとして送る仕組みです。クライアントがリクエストを送ると、サーバーは接続を保ったままイベントを少しずつ返します。フォーマットはシンプルなテキストです。

```text
data: "去年の"
data: "春に"
data: "東京を"
data: [DONE]
```

各行は`data:`で始まり、空行で区切ります。Content-Typeは`text/event-stream`です。トークンはJSON文字列としてエスケープして送るので、ダブルクォートで囲んだ形式になります（3.3節で実装します）。

## 3.2 cpp-httplibでのストリーミング

cpp-httplibでは`set_chunked_content_provider`を使うと、レスポンスを少しずつ送れます。コールバックの中で`sink.os`に書き込むたびにデータがクライアントに届きます。

```cpp
res.set_chunked_content_provider(
    "text/event-stream",
    [](size_t offset, httplib::DataSink &sink) {
      sink.os << "data: hello\n\n";
      sink.done();
      return true;
    });
```

`sink.done()`を呼ぶとストリームが終了します。クライアントが途中で接続を切った場合、`sink.os`の書き込みが失敗して`sink.os.fail()`が`true`になります。これを使って切断を検知し、不要な推論を中断できます。

## 3.3 `/translate/stream`ハンドラ

JSONパースとバリデーションは2章の`/translate`と同じです。違うのはレスポンスの返し方だけ。`llm.chat()`のストリーミングコールバックと`set_chunked_content_provider`を組み合わせます。

```cpp
svr.Post("/translate/stream",
         [&](const httplib::Request &req, httplib::Response &res) {
  // ... JSONパース・バリデーションは/translateと同じ ...

  res.set_chunked_content_provider(
      "text/event-stream",
      [&, prompt](size_t, httplib::DataSink &sink) {
        try {
          llm.chat(prompt, [&](std::string_view token) {
            sink.os << "data: "
                    << json(std::string(token)).dump(
                         -1, ' ', false, json::error_handler_t::replace)
                    << "\n\n";
            return sink.os.good(); // 切断されたらfalse→推論を中断
          });
          sink.os << "data: [DONE]\n\n";
        } catch (const std::exception &e) {
          sink.os << "data: " << json({{"error", e.what()}}).dump() << "\n\n";
        }
        sink.done();
        return true;
      });
});
```

ポイントをいくつか。

- `llm.chat()`にコールバックを渡すと、トークンが生成されるたびに呼ばれます。コールバックが`false`を返すと生成を中断します
- `sink.os`に書き込んだ後、`sink.os.good()`でクライアントがまだ接続しているかを確認できます。切断されていたら`false`を返して推論を止めます
- 各トークンは`json(token).dump()`でJSON文字列としてエスケープしてから送ります。改行やクォートを含むトークンでも安全です
- `dump(-1, ' ', false, ...)`の最初の3つの引数はデフォルトと同じです。重要なのは第4引数の`json::error_handler_t::replace`です。LLMはトークンをサブワード単位で返すため、マルチバイト文字（日本語など）の途中でトークンが切れることがあります。不完全なUTF-8バイト列をそのまま`dump()`に渡すと例外が飛ぶので、`replace`で安全に置換します。ブラウザ側で結合されるため、表示上の問題はありません
- `try/catch`でラムダ全体を囲んでいます。`llm.chat()`はコンテキストウィンドウの超過などで例外を投げることがあります。ラムダ内で例外が未捕捉だとサーバーがクラッシュするので、エラーをSSEイベントとして返します
- `data: [DONE]`はOpenAI APIと同じ慣習で、ストリームの終了をクライアントに伝えます

## 3.4 全体のコード

2章のコードに`/translate/stream`を追加した完成形です。

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
  // GGUFモデルをロード
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

  // 2章で作った通常の翻訳エンドポイント
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
      auto translation = llm.chat(prompt);
      res.set_content(json{{"translation", translation}}.dump(),
                      "application/json");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(json{{"error", e.what()}}.dump(), "application/json");
    }
  });

  // SSEストリーミング翻訳エンドポイント
  svr.Post("/translate/stream",
           [&](const httplib::Request &req, httplib::Response &res) {
    // JSONパース・バリデーション（/translateと同じ）
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

## 3.5 動作確認

ビルドしてサーバーを起動します。

```bash
cmake --build build -j
./build/translate-server
```

curlの`-N`オプションでバッファリングを無効にすると、トークンが届くたびにリアルタイムで表示されます。

```bash
curl -N -X POST http://localhost:8080/translate/stream \
  -H "Content-Type: application/json" \
  -d '{"text": "I had a great time visiting Tokyo last spring. The cherry blossoms were beautiful.", "target_lang": "ja"}'
```

```text
data: "去年の"
data: "春に"
data: "東京を"
data: "訪れた"
data: "。"
data: "桜が"
data: "綺麗だった"
data: "。"
data: [DONE]
```

トークンがひとつずつ流れてくるのが確認できるはずです。2章の`/translate`も引き続き使えます。

## 次の章へ

サーバーの翻訳機能はこれで一通り揃いました。次の章では、cpp-httplibのクライアント機能を使ってHugging Faceからモデルを取得・管理する機能を追加します。

**Next:** [モデルの取得・管理機能を追加する](../ch04-model-management)
