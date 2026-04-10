---
title: "E01. SSEサーバーを実装する"
order: 47
status: "draft"
---

Server-Sent Events（SSE）は、サーバーからクライアントへイベントを一方向にプッシュするためのシンプルなプロトコルです。長時間の接続を保ったまま、サーバーが好きなタイミングでデータを送れます。WebSocketより軽量で、HTTPの範囲で完結するのが魅力です。

cpp-httplibにはSSE専用のサーバーAPIはありませんが、`set_chunked_content_provider()`と`text/event-stream`を組み合わせれば実装できます。

## 基本のSSEサーバー

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/event-stream",
    [](size_t offset, httplib::DataSink &sink) {
      std::string message = "data: hello\n\n";
      sink.write(message.data(), message.size());
      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true;
    });
});
```

ポイントは3つです。

1. Content-Typeを`text/event-stream`にする
2. メッセージは`data: <内容>\n\n`の形式で書く（`\n\n`で1イベントの区切り）
3. `sink.write()`で送るたびに、クライアントが受け取る

接続が生きている限り、プロバイダラムダが繰り返し呼ばれ続けます。

## イベントを送り続ける例

サーバーの現在時刻を1秒ごとに送るシンプルな例です。

```cpp
svr.Get("/time", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/event-stream",
    [&req](size_t offset, httplib::DataSink &sink) {
      if (req.is_connection_closed()) {
        sink.done();
        return true;
      }

      auto now = std::chrono::system_clock::now();
      auto t = std::chrono::system_clock::to_time_t(now);
      std::string msg = "data: " + std::string(std::ctime(&t)) + "\n";
      sink.write(msg.data(), msg.size());

      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true;
    });
});
```

クライアントが切断したら`sink.done()`で終了します。詳しくはS16. クライアントが切断したか検出するを参照してください。

## コメント行でハートビート

`:`で始まる行はSSEのコメントで、クライアントは無視しますが、**接続を生かしておく**役割があります。プロキシやロードバランサが無通信接続を切ってしまうのを防げます。

```cpp
// 30秒ごとにハートビート
if (tick_count % 30 == 0) {
  std::string ping = ": ping\n\n";
  sink.write(ping.data(), ping.size());
}
```

## スレッドプールとの関係

SSEは接続がつなぎっぱなしなので、1クライアントあたり1ワーカースレッドを消費します。同時接続数が多くなりそうなら、スレッドプールを動的スケーリングにしておきましょう。

```cpp
svr.new_task_queue = [] {
  return new httplib::ThreadPool(8, 128);
};
```

詳しくはS21. マルチスレッド数を設定するを参照してください。

> **Note:** `data:`の後ろに改行が含まれる場合、各行の先頭に`data: `を付けて複数の`data:`行として送ります。SSEの仕様で決まっているフォーマットです。

> イベント名を使い分けたい場合はE02. SSEでイベント名を使い分けるを、クライアント側はE04. SSEをクライアントで受信するを参照してください。
