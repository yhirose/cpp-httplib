---
title: "C14. 接続の再利用とKeep-Aliveの挙動を理解する"
order: 14
status: "draft"
---

`httplib::Client`は、デフォルトではリクエストのたびに接続を閉じます（`Connection: close`を送ります）。`set_keep_alive(true)`を呼んでおくと、同じインスタンスから送るリクエストは1本のTCP接続を使い回します。TCPやTLSのハンドシェイクを毎回やり直さずに済みます。

## Keep-Aliveを有効にする

```cpp
httplib::Client cli("https://api.example.com");
cli.set_keep_alive(true);

auto res1 = cli.Get("/users/1");
auto res2 = cli.Get("/users/2"); // 同じ接続を再利用
auto res3 = cli.Get("/users/3"); // 同じ接続を再利用
```

あとは`cli`を使い回すだけで、内部的には同じソケットで通信が続きます。とくにHTTPSでは、TLSハンドシェイクのコストが大きいので効果が顕著です。

## Keep-Aliveをオフに戻す

リクエストのたびに接続を張り直す動作（デフォルト）に戻すには、`set_keep_alive(false)`を呼びます。

```cpp
cli.set_keep_alive(false);
```

## リクエストごとに`Client`を作らない

リクエストのたびに`Client`を作っては破棄していると、接続は再利用されません。インスタンスはループの外で作り、中で使い回しましょう。

```cpp
// NG: 毎回接続が切れる
for (auto id : ids) {
  httplib::Client cli("https://api.example.com");
  cli.set_keep_alive(true);
  cli.Get("/users/" + id);
}

// OK: 接続が再利用される
httplib::Client cli("https://api.example.com");
cli.set_keep_alive(true);
for (auto id : ids) {
  cli.Get("/users/" + id);
}
```

## 並行リクエスト

複数のスレッドから並行にリクエストを送りたいときは、スレッドごとに別々の`Client`インスタンスを持つのが無難です。1つの`Client`は1本のTCP接続を使い回すので、同じインスタンスに複数スレッドから同時にリクエストを投げると、結局どこかで直列化されます。

> **Note:** サーバー側のKeep-Aliveタイムアウトを超えると、サーバーが接続を切ります。cpp-httplibは次のリクエストを送る前にそれに気付いて接続し直すので、アプリケーション側で気にする必要はありません。
