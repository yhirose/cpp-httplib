---
title: "W06. タイムアウトを設定する"
order: 56
status: "draft"
---

`ws::WebSocketClient`には`Client`と同じ3種類のタイムアウトがあり、意味も同じです。

| 種類 | API | デフォルト |
| --- | --- | --- |
| 接続タイムアウト | `set_connection_timeout` | 300秒 |
| 読み取りタイムアウト | `set_read_timeout` | 300秒（`CPPHTTPLIB_WEBSOCKET_READ_TIMEOUT_SECOND`） |
| 書き込みタイムアウト | `set_write_timeout` | 5秒 |

## 基本の使い方

```cpp
httplib::ws::WebSocketClient ws("ws://localhost:8080/ws");

ws.set_connection_timeout(5, 0);  // 5秒
ws.set_read_timeout(30, 0);       // 30秒
ws.set_write_timeout(10, 0);      // 10秒

if (ws.connect()) {
  ws.send("hello");
}
```

`connect()`を呼ぶ前に設定してください。

## `std::chrono`で指定する

`Client`と同じく、`std::chrono`の期間を直接渡すオーバーロードもあります。

```cpp
using namespace std::chrono_literals;

ws.set_connection_timeout(5s);
ws.set_read_timeout(30s);
ws.set_write_timeout(10s);
```

## 読み取りタイムアウトの意味に注意

`set_read_timeout()`は「1回の`read()`呼び出し」に対するタイムアウトです。メッセージが届かないまま指定時間が経過すると`read()`が`ReadResult::Fail`を返します。通知の待受のように長時間メッセージが来ないことが正常な接続では、意図せず切断されないよう長めに設定するか、切断されたらアプリケーション側で再接続してください。

> Ping/Pongによる無応答ピア検出は別の仕組みです。詳しくは[W02. ハートビートを設定する](../w02-websocket-ping)を参照してください。

## `Client`との違い

`Client`のタイムアウト設定については[C12. タイムアウトを設定する](../c12-timeouts)を参照してください。挙動とAPIはほぼ同じですが、`WebSocketClient`には`set_max_timeout()`に相当するリクエスト全体のタイムアウトはありません。接続を確立したあとは、`read()`のループを回し続ける限り接続が維持されます。
