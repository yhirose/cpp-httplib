---
title: "C14. 接続の再利用とKeep-Aliveの挙動を理解する"
order: 14
status: "draft"
---

`httplib::Client`は、デフォルトではリクエストごとに接続を閉じます（`Connection: close`を送ります）。`set_keep_alive(true)`を呼ぶと、同じインスタンスで送る複数のリクエストが1本のTCP接続を使い回すようになり、TCPハンドシェイクやTLSハンドシェイクのオーバーヘッドを毎回払わずに済みます。

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

毎回新しい接続を張り直す動作に戻したい場合は、`set_keep_alive(false)`を呼びます。これがデフォルトの動作です。

```cpp
cli.set_keep_alive(false);
```

## リクエストごとに`Client`を作らない

1回のリクエストのたびに`Client`をスコープから抜けて破棄すると、接続の再利用は効きません。ループの外でインスタンスを作り、中で使い回しましょう。

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

> **Note:** サーバー側のKeep-Aliveタイムアウトを超えると、サーバーが接続を切ります。cpp-httplibは次のリクエストを送る前にそれを検出して接続し直すので、アプリケーションコードで気にする必要はありません。
