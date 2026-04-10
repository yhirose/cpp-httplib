---
title: "C10. レスポンスをストリーミングで受信する"
order: 10
status: "draft"
---

レスポンスのボディをチャンクごとに受け取りたいときは、`ContentReceiver`を使います。大きなファイルを扱うときはもちろん、NDJSON（改行区切りJSON）やログストリームのように「届いた分だけ先に処理したい」ケースでも便利です。

## チャンクごとに処理する

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Get("/logs/stream",
  [](const char *data, size_t len) {
    std::cout.write(data, len);
    std::cout.flush();
    return true; // falseを返すと受信を中止
  });
```

サーバーから届いたデータが、到着した順にラムダに渡されます。コールバックが`false`を返すとダウンロードを途中で止められます。

## NDJSONを行単位でパースする

バッファを使って改行区切りのJSONを1行ずつ処理する例です。

```cpp
std::string buffer;

auto res = cli.Get("/events",
  [&](const char *data, size_t len) {
    buffer.append(data, len);
    size_t pos;
    while ((pos = buffer.find('\n')) != std::string::npos) {
      auto line = buffer.substr(0, pos);
      buffer.erase(0, pos + 1);
      if (!line.empty()) {
        auto j = nlohmann::json::parse(line);
        handle_event(j);
      }
    }
    return true;
  });
```

バッファに貯めながら、改行が見つかるたびに1行を取り出してパースします。ストリーミングAPIをリアルタイムに処理する基本パターンです。

> **Warning:** `ContentReceiver`を渡すと、`res->body`は**空のまま**になります。ボディは自分でコールバック内で保存するか処理するかしてください。

> ダウンロードの進捗を知りたい場合はC11. 進捗コールバックを使うと組み合わせましょう。
> Server-Sent Events（SSE）を扱うときはE04. SSEをクライアントで受信するも参考になります。
