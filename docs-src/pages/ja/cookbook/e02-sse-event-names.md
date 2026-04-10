---
title: "E02. SSEでイベント名を使い分ける"
order: 48
status: "draft"
---

SSEでは、1本のストリームで複数の種類のイベントを送れます。`event:`フィールドで名前を付けると、クライアント側で種類ごとに別々のハンドラを呼べます。チャットの「新規メッセージ」「入室」「退室」のような場面で便利です。

## イベント名付きで送る

```cpp
auto send_event = [](httplib::DataSink &sink,
                     const std::string &event,
                     const std::string &data) {
  std::string msg = "event: " + event + "\n"
                  + "data: " + data + "\n\n";
  sink.write(msg.data(), msg.size());
};

svr.Get("/chat/stream", [&](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/event-stream",
    [&, send_event](size_t offset, httplib::DataSink &sink) {
      send_event(sink, "message", "Hello!");
      std::this_thread::sleep_for(std::chrono::seconds(2));
      send_event(sink, "join", "alice");
      std::this_thread::sleep_for(std::chrono::seconds(2));
      send_event(sink, "leave", "bob");
      std::this_thread::sleep_for(std::chrono::seconds(2));
      return true;
    });
});
```

1メッセージは`event:` → `data:` → 空行、の形式です。`event:`を書かないと、クライアント側ではデフォルトの`"message"`イベントとして扱われます。

## IDを付けて再接続に備える

`id:`フィールドを一緒に送ると、クライアントが切断→再接続したときに`Last-Event-ID`ヘッダーで「どこまで受け取ったか」を教えてくれます。

```cpp
auto send_event = [](httplib::DataSink &sink,
                     const std::string &event,
                     const std::string &data,
                     const std::string &id) {
  std::string msg = "id: " + id + "\n"
                  + "event: " + event + "\n"
                  + "data: " + data + "\n\n";
  sink.write(msg.data(), msg.size());
};

send_event(sink, "message", "Hello!", "42");
```

IDの付け方は自由です。連番でもUUIDでも、サーバー側で重複せず順序が追えるものを選びましょう。再接続の詳細はE03. SSEの再接続を処理するを参照してください。

## JSONをdataに乗せる

構造化されたデータを送りたいときは、`data:`の中身をJSONにするのが定番です。

```cpp
nlohmann::json payload = {
  {"user", "alice"},
  {"text", "Hello!"},
};
send_event(sink, "message", payload.dump(), "42");
```

クライアント側では受け取った`data`をそのままJSONパースすれば、元のオブジェクトに戻せます。

## データに改行が含まれる場合

`data:`の値に改行が入るときは、各行の先頭に`data: `を付けて複数行に分けて送ります。

```cpp
std::string msg = "data: line1\n"
                  "data: line2\n"
                  "data: line3\n\n";
sink.write(msg.data(), msg.size());
```

クライアント側では、これらが改行でつながった1つの`data`として復元されます。

> **Note:** `event:`を使うとクライアント側のハンドリングがきれいになりますが、ブラウザのDevToolsで見たときに種類別で識別しやすくなるというメリットもあります。デバッグ時に効いてきます。
