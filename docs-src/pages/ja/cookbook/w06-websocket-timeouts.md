---
title: "W06. タイムアウトを設定する"
order: 57
status: "draft"
---

`ws::WebSocketClient`には`Client`と同じ3種類のタイムアウトがあり、意味も同じです。

| 種類 | API | デフォルト |
| --- | --- | --- |
| 接続タイムアウト | `set_connection_timeout` | 300秒 |
| 読み取りタイムアウト | `set_read_timeout` | なし。無期限に待つ（`CPPHTTPLIB_WEBSOCKET_CLIENT_READ_TIMEOUT_SECOND`） |
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

接続タイムアウトと書き込みタイムアウトは`connect()`を呼ぶ前に設定してください。読み取りタイムアウトはいつでも変更でき、接続済みの状態で設定した場合は次の`read()`から効きます。

## `std::chrono`で指定する

`Client`と同じく、`std::chrono`の期間を直接渡すオーバーロードもあります。

```cpp
using namespace std::chrono_literals;

ws.set_connection_timeout(5s);
ws.set_read_timeout(30s);
ws.set_write_timeout(10s);
```

## 読み取りタイムアウトの意味

`set_read_timeout()`は「1回の`read()`呼び出し」に対するタイムアウトです。メッセージが届かないまま指定時間が経過すると`read()`は`ReadResult::Timeout`を返します。このとき**接続は開いたまま**で、1バイトも読み進めていないので、そのまま送信して読み直せます。接続が失われたことを意味する`ReadResult::Fail`とはここが違います。

1本の接続を1つのスレッドで双方向に扱えるのはこのためです。

```cpp
using namespace std::chrono_literals;

ws.set_read_timeout(100ms);
std::string msg;
while (ws.is_open()) {
  auto r = ws.read(msg);
  if (r == httplib::ws::Timeout) {
    flush_outgoing(ws);  // 何も届いていない。溜まっている分を送る
    continue;
  }
  if (r == httplib::ws::Fail) { break; }
  handle(msg);
}
```

読み取りタイムアウトを設定しないと`read()`はメッセージが届くまで戻らないので、接続を持っているスレッドは送信に手が回りません。

`Timeout`について2点あります。

- `msg`は書き換えられません。値も0以外なので、読み取りタイムアウトを設定した状態で`while (ws.read(msg))`と書くと、**前回のメッセージ**が`msg`に残ったままループが回り続けます。
- 報告されるのはメッセージの境界だけです。分割されたメッセージの途中でタイムアウトした場合、そのメッセージは再開できないので`read()`は`Fail`を返します。

通知の待受のように長時間メッセージが来ないことが正常な接続では、読み取りタイムアウトを設定しないままにするか、`Timeout`を「まだ何も来ていない」印として扱ってループを続けてください。

## サーバ側

ハンドラが受け取る`ws::WebSocket`にも`set_read_timeout()`があります。ハンドラが`read()`で止まったままにならないので、上と同じ書き方で複数の接続の間をメッセージが中継できます。

サーバ側のデフォルトは「無期限」ではなく300秒（`CPPHTTPLIB_WEBSOCKET_SERVER_READ_TIMEOUT_SECOND`）です。WebSocketのハンドラは接続が続く限りワーカーを1つ占有するので、無言になったピアからワーカーを回収する保険として働きます。

> Ping/Pongによる無応答ピア検出は別の仕組みです。詳しくは[W02. ハートビートを設定する](../w02-websocket-ping)を参照してください。

## `Client`との違い

`Client`のタイムアウト設定については[C12. タイムアウトを設定する](../c12-timeouts)を参照してください。挙動とAPIはほぼ同じですが、`WebSocketClient`には`set_max_timeout()`に相当するリクエスト全体のタイムアウトはありません。接続を確立したあとは、`read()`のループを回し続ける限り接続が維持されます。
