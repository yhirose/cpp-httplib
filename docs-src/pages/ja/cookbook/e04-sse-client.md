---
title: "E04. SSEをクライアントで受信する"
order: 50
status: "draft"
---

cpp-httplibには`sse::SSEClient`という専用のクラスが用意されています。自動再接続、イベント名別のハンドラ、`Last-Event-ID`の管理まで面倒を見てくれるので、SSEを受信するときはこれを使うのが一番ラクです。

## 基本の使い方

```cpp
#include <httplib.h>

httplib::Client cli("http://localhost:8080");
httplib::sse::SSEClient sse(cli, "/events");

sse.on_message([](const httplib::sse::SSEMessage &msg) {
  std::cout << "data: " << msg.data << std::endl;
});

sse.start(); // ブロッキング
```

`Client`と接続先パスを渡して`SSEClient`を作り、`on_message()`でコールバックを登録します。`start()`を呼ぶとイベントループが走り、接続が切れると自動で再接続を試みます。

## イベント名で分岐する

サーバー側で`event:`を付けて送られてくる場合は、`on_event()`で名前ごとにハンドラを登録できます。

```cpp
sse.on_event("message", [](const auto &msg) {
  std::cout << "chat: " << msg.data << std::endl;
});

sse.on_event("join", [](const auto &msg) {
  std::cout << msg.data << " joined" << std::endl;
});

sse.on_event("leave", [](const auto &msg) {
  std::cout << msg.data << " left" << std::endl;
});
```

`on_message()`は、名前なし（デフォルトの`message`イベント）を受け取る汎用ハンドラとして使えます。

## 接続イベントとエラーハンドリング

```cpp
sse.on_open([] {
  std::cout << "connected" << std::endl;
});

sse.on_error([](httplib::Error err) {
  std::cerr << "error: " << httplib::to_string(err) << std::endl;
});
```

接続確立時やエラー発生時にもフックを挟めます。エラーハンドラが呼ばれても、`SSEClient`は内部で再接続を試みます。

## 非同期で動かす

メインスレッドを塞ぎたくない場合は`start_async()`を使います。

```cpp
sse.start_async();

// メインスレッドは別の仕事を続ける
do_other_work();

// 終わったら止める
sse.stop();
```

`start_async()`は裏でスレッドを立ち上げてイベントループを回します。`stop()`でクリーンに止められます。

## 再接続の設定

再接続間隔や最大試行回数を調整できます。

```cpp
sse.set_reconnect_interval(5000);    // 5秒
sse.set_max_reconnect_attempts(10);  // 10回まで（0=無制限）
```

サーバー側で`retry:`フィールドを送っていると、そちらが優先されます。

## Last-Event-IDの自動管理

`SSEClient`は受信したイベントの`id`を内部で保持していて、再接続時に`Last-Event-ID`ヘッダーとして送ってくれます。この挙動はサーバー側で`id:`付きイベントを送っていれば自動で有効になります。

```cpp
std::cout << "last id: " << sse.last_event_id() << std::endl;
```

現在のIDは`last_event_id()`で参照できます。

> **Note:** SSEClientの`start()`はブロッキングなので、単発のツールならそのまま使えますが、GUIアプリやサーバーに組み込むときは`start_async()` + `stop()`の組み合わせが基本です。

> サーバー側の実装は[E01. SSEサーバーを実装する](e01-sse-server)を参照してください。
