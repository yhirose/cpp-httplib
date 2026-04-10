---
title: "C12. タイムアウトを設定する"
order: 12
status: "draft"
---

クライアントには3種類のタイムアウトがあります。それぞれ別々に設定できます。

| 種類 | API | デフォルト | 意味 |
| --- | --- | --- | --- |
| 接続タイムアウト | `set_connection_timeout` | 300秒 | TCP接続の確立までの待ち時間 |
| 読み取りタイムアウト | `set_read_timeout` | 300秒 | レスポンスを受信する際の1回の`recv`待ち時間 |
| 書き込みタイムアウト | `set_write_timeout` | 5秒 | リクエストを送信する際の1回の`send`待ち時間 |

## 基本の使い方

```cpp
httplib::Client cli("http://localhost:8080");

cli.set_connection_timeout(5, 0);  // 5秒
cli.set_read_timeout(10, 0);       // 10秒
cli.set_write_timeout(10, 0);      // 10秒

auto res = cli.Get("/api/data");
```

秒数とマイクロ秒を2引数で渡します。細かい指定が不要なら第2引数は省略できます。

## `std::chrono`で指定する

`std::chrono`の期間を直接渡すオーバーロードもあります。こちらのほうが読みやすいのでおすすめです。

```cpp
using namespace std::chrono_literals;

cli.set_connection_timeout(5s);
cli.set_read_timeout(10s);
cli.set_write_timeout(500ms);
```

## デフォルトでは300秒と長めな点に注意

接続タイムアウトと読み取りタイムアウトはデフォルトで**300秒（5分）**です。サーバーが反応しない場合、このままだと5分待たされます。短めに設定したほうが良いことが多いです。

```cpp
cli.set_connection_timeout(3s);
cli.set_read_timeout(10s);
```

> **Warning:** 読み取りタイムアウトは「1回の受信待ち」に対するタイムアウトです。大きなファイルのダウンロードで途中ずっとデータが流れている限り、リクエスト全体で30分かかっても発火しません。リクエスト全体の時間制限を設けたい場合はC13. 全体タイムアウトを設定するを使ってください。
