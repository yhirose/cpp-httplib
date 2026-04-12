---
title: "W02. ハートビートを設定する"
order: 52
status: "draft"
---

WebSocket接続は長時間つなぎっぱなしになるので、プロキシやロードバランサが「アイドルだから」と勝手に切ってしまうことがあります。これを防ぐために、定期的にPingフレームを送って接続を生かしておく仕組みがあります。cpp-httplibでは、指定した間隔で自動的にPingを送ってくれます。

## サーバー側の設定

```cpp
svr.set_websocket_ping_interval(30); // 30秒ごとにPing

svr.WebSocket("/chat", [](const auto &req, auto &ws) {
  // ...
});
```

`set_websocket_ping_interval()`に秒数を渡すだけです。このサーバーが受け入れるすべてのWebSocket接続に対して、指定した間隔でPingが送られます。

`std::chrono`の期間を受け取るオーバーロードもあります。

```cpp
using namespace std::chrono_literals;
svr.set_websocket_ping_interval(30s);
```

## クライアント側の設定

クライアント側でも同じAPIがあります。

```cpp
httplib::ws::WebSocketClient cli("ws://localhost:8080/chat");
cli.set_websocket_ping_interval(30);
cli.connect();
```

`connect()`を呼ぶ前に設定しておきましょう。

## デフォルト値

デフォルトのPing間隔は、ビルド時のマクロ`CPPHTTPLIB_WEBSOCKET_PING_INTERVAL_SECOND`で決まります。通常はそのままで問題ありませんが、特別なプロキシ環境に合わせて短くしたい場合は調整してください。

## PongはどうやってpIngに応答するか

WebSocketプロトコルでは、PingフレームにはPongフレームで応答することが決まっています。cpp-httplibは受信したPingに自動でPongを返すので、アプリケーションコード側で気にする必要はありません。

## Pingの間隔をどう決めるか

| 環境 | 推奨 |
| --- | --- |
| 通常のインターネット接続 | 30〜60秒 |
| 厳しいプロキシ（AWS ALBなど） | 15〜30秒 |
| モバイル回線 | 短すぎるとバッテリーを食う、60秒以上 |

短すぎると無駄なトラフィックになり、長すぎると接続が切れます。だいたい**接続が切れる時間の半分**くらいが目安です。

> **Warning:** Ping間隔を極端に短くすると、WebSocket接続ごとにバックグラウンドでスレッドが走るので、CPU負荷が上がります。接続数が多いサーバーでは控えめな値に設定しましょう。

## 無応答のピアを検出する

Pingを送るだけでは、相手が「黙って落ちた」場合に気付けません。TCPの接続自体は生きているように見えるのに、相手のプロセスはもう応答しない、というケースです。これを検出するには、送ったPingに対してPongがN回連続で返ってこなかったら接続を切る、というオプションを有効にします。

```cpp
cli.set_websocket_max_missed_pongs(2); // 2回連続でPongが返ってこなければ切断
```

サーバー側にも同じ`set_websocket_max_missed_pongs()`があります。

たとえばPing間隔が30秒で`max_missed_pongs = 2`なら、無応答のピアは約60秒で検出され、`CloseStatus::GoingAway`（理由は`"pong timeout"`）で接続が閉じられます。

この仕組みは`read()`を呼んでPongフレームを消費したタイミングでカウンタがリセットされます。つまり通常のWebSocketクライアントのように`read()`をループで回していれば、特に意識することなく動きます。

### デフォルトは無効

`max_missed_pongs`のデフォルトは`0`で、これは「Pongが何回返ってこなくてもこの仕組みでは切断しない」という意味です。Ping自体は送られ続けますが、応答の有無はチェックされません。無応答ピアを検出したい場合は明示的に`1`以上を設定してください。

ただし`0`のままでも最終的に接続が残り続けることはありません。`read()`を呼んでいる間は`CPPHTTPLIB_WEBSOCKET_READ_TIMEOUT_SECOND`（デフォルト**300秒 = 5分**）が保険として働き、フレームが一定時間来なければ`read()`が失敗します。つまり`max_missed_pongs`は「**もっと速く**無応答を検出したい」ときに使うオプションだと考えてください。

> 接続が閉じたときの処理は[W03. 接続クローズをハンドリングする](w03-websocket-close)を参照してください。
