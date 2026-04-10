---
title: "C13. 全体タイムアウトを設定する"
order: 13
status: "draft"
---

C12. タイムアウトを設定するで紹介した3種類のタイムアウトは、いずれも「1回の`send`や`recv`」に対するものです。リクエスト全体の所要時間に上限を設けたい場合は、`set_max_timeout()`を使います。

## 基本の使い方

```cpp
httplib::Client cli("http://localhost:8080");

cli.set_max_timeout(5000); // 5秒（ミリ秒単位）

auto res = cli.Get("/slow-endpoint");
```

ミリ秒単位で指定します。接続、送信、受信をすべて含めて、リクエスト全体が指定時間を超えたら打ち切られます。

## `std::chrono`で指定する

こちらも`std::chrono`の期間を受け取るオーバーロードがあります。

```cpp
using namespace std::chrono_literals;
cli.set_max_timeout(5s);
```

## どう使い分けるか

`set_read_timeout`は「データが来ない時間」のタイムアウトなので、少しずつデータが流れ続ける状況では発火しません。たとえば1秒ごとに1バイト届くようなエンドポイントは、`set_read_timeout`をいくら短くしてもタイムアウトしません。

一方、`set_max_timeout`は「経過時間」に対する上限なので、こうしたケースでも確実に止められます。外部APIを叩くときや、ユーザーを待たせすぎたくないときに重宝します。

```cpp
cli.set_connection_timeout(3s);
cli.set_read_timeout(10s);
cli.set_max_timeout(30s); // 全体で30秒を超えたら中断
```

> **Note:** `set_max_timeout()`は通常のタイムアウトと併用できます。短期的な無反応は`set_read_timeout`で、長時間の処理は`set_max_timeout`で、という二段構えにするのが安全です。
