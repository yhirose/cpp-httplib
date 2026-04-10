---
title: "E03. SSEの再接続を処理する"
order: 49
status: "draft"
---

SSE接続はネットワークの都合で切れることがあります。クライアントは自動的に再接続を試みるので、サーバー側では「再接続してきたクライアントに、途中から配信を再開する」仕組みを用意しておくと親切です。

## `Last-Event-ID`を受け取る

クライアントが再接続すると、最後に受け取ったイベントのIDを`Last-Event-ID`ヘッダーに入れて送ってきます。サーバー側ではこれを読んで、その続きから配信を再開できます。

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  auto last_id = req.get_header_value("Last-Event-ID");
  int start = last_id.empty() ? 0 : std::stoi(last_id) + 1;

  res.set_chunked_content_provider(
    "text/event-stream",
    [start](size_t offset, httplib::DataSink &sink) mutable {
      static int next_id = 0;
      if (next_id < start) { next_id = start; }

      std::string msg = "id: " + std::to_string(next_id) + "\n"
                      + "data: event " + std::to_string(next_id) + "\n\n";
      sink.write(msg.data(), msg.size());
      ++next_id;

      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true;
    });
});
```

初回接続では`Last-Event-ID`が無いので`0`から送り始め、再接続時は続きのIDから再開します。イベントの保存はサーバー側の責任なので、直近のイベントをキャッシュしておく必要があります。

## 再接続間隔を指定する

`retry:`フィールドを送ると、クライアント側の再接続間隔を指定できます。単位はミリ秒です。

```cpp
std::string msg = "retry: 5000\n\n";  // 5秒後に再接続
sink.write(msg.data(), msg.size());
```

通常は最初に1回送っておけば十分です。混雑時やサーバーメンテナンス時に、リトライ間隔を長めに指定して負荷を減らすといった使い方もできます。

## イベントのバッファリング

再接続のために、直近のイベントをサーバー側でバッファしておく実装が必要です。

```cpp
struct EventBuffer {
  std::mutex mu;
  std::deque<std::pair<int, std::string>> events; // {id, data}
  int next_id = 0;

  void push(const std::string &data) {
    std::lock_guard<std::mutex> lock(mu);
    events.push_back({next_id++, data});
    if (events.size() > 1000) { events.pop_front(); }
  }

  std::vector<std::pair<int, std::string>> since(int id) {
    std::lock_guard<std::mutex> lock(mu);
    std::vector<std::pair<int, std::string>> out;
    for (const auto &e : events) {
      if (e.first >= id) { out.push_back(e); }
    }
    return out;
  }
};
```

再接続してきたクライアントに`since(last_id)`で未送信分をまとめて送ると、取りこぼしを防げます。

## 保存期間のバランス

バッファをどれだけ持つかは、メモリと「どれだけさかのぼって再送できるか」のトレードオフです。用途によって決めましょう。

- リアルタイムチャット: 数分〜数十分
- 通知: 直近のN件
- 取引データ: 永続化して、必要ならDBから取得

> **Warning:** `Last-Event-ID`はクライアントが送ってくる値なので、サーバー側で信用しすぎないようにしましょう。数値として読むなら範囲チェックを、文字列ならサニタイズを忘れずに。
