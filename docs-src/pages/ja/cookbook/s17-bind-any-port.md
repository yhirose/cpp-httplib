---
title: "S17. ポートを動的に割り当てる"
order: 36
status: "draft"
---

テスト用サーバーを立てるとき、ポート番号の衝突が面倒なことがあります。`bind_to_any_port()`を使うと、OSに空いているポートを選ばせて、そのポート番号を受け取れます。

## 基本の使い方

```cpp
httplib::Server svr;

svr.Get("/", [](const auto &req, auto &res) {
  res.set_content("hello", "text/plain");
});

int port = svr.bind_to_any_port("0.0.0.0");
std::cout << "listening on port " << port << std::endl;

svr.listen_after_bind();
```

`bind_to_any_port()`は第2引数で`0`を渡したのと同じ動作で、OSが空きポートを割り当てます。返り値が実際に使われたポート番号です。

その後、`listen_after_bind()`を呼んで待ち受けを開始します。`listen()`のように「bindとlistenをまとめて行う」ことはできないので、bindとlistenが分かれているこの2段階の書き方になります。

## テストでの活用

単体テストで「サーバーを立ててリクエストを投げる」パターンによく使います。

```cpp
httplib::Server svr;
svr.Get("/ping", [](const auto &, auto &res) { res.set_content("pong", "text/plain"); });

int port = svr.bind_to_any_port("127.0.0.1");
std::thread t([&] { svr.listen_after_bind(); });

// 別スレッドでサーバーが動いている間にテストを走らせる
httplib::Client cli("127.0.0.1", port);
auto res = cli.Get("/ping");
assert(res && res->body == "pong");

svr.stop();
t.join();
```

ポート番号がテスト実行時に決まるので、複数のテストが並列実行されても衝突しません。

> **Note:** `bind_to_any_port()`は失敗すると`-1`を返します。権限エラーや利用可能ポートが無いケースなので、返り値のチェックを忘れずに。

> サーバーを止める方法はS19. グレースフルシャットダウンするを参照してください。
