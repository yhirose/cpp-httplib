---
title: "S10. Post-routing handlerでレスポンスヘッダーを追加する"
order: 29
status: "draft"
---

ハンドラが返したレスポンスに、あとから共通のヘッダーを追加したいことがあります。CORSヘッダー、セキュリティヘッダー、独自のリクエストIDなどです。こういうときは`set_post_routing_handler()`を使います。

## 基本の使い方

```cpp
svr.set_post_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    res.set_header("X-Request-ID", generate_request_id());
  });
```

Post-routingハンドラは、**ルートハンドラが実行された後、レスポンスが送信される前**に呼ばれます。ここで`res.set_header()`や`res.headers.erase()`を使えば、全レスポンスに対して一括でヘッダーの追加・削除ができます。

## CORSヘッダーを付ける

よくある用途がCORSです。

```cpp
svr.set_post_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  });
```

プリフライトリクエスト（`OPTIONS`）には別途ハンドラを登録するか、pre-routingハンドラで処理します。

```cpp
svr.Options("/.*", [](const auto &req, auto &res) {
  res.status = 204;
});
```

## セキュリティヘッダーをまとめて付ける

ブラウザ向けのセキュリティヘッダーを一箇所で管理できます。

```cpp
svr.set_post_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
  });
```

どのハンドラがレスポンスを作っても、同じヘッダーが付くようになります。

> **Note:** Post-routingハンドラは、ルートにマッチしなかったリクエストや、エラーハンドラが返したレスポンスに対しても呼ばれます。ヘッダーをすべてのレスポンスに確実に付けたいときに便利です。
