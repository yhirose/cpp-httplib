---
title: "S01. GET / POST / PUT / DELETEハンドラを登録する"
order: 20
status: "draft"
---

`httplib::Server`では、HTTPメソッドごとにハンドラを登録します。`Get()`、`Post()`、`Put()`、`Delete()`の各メソッドにパターンとラムダを渡すだけです。

## 基本の使い方

```cpp
#include <httplib.h>

int main() {
  httplib::Server svr;

  svr.Get("/hello", [](const httplib::Request &req, httplib::Response &res) {
    res.set_content("Hello, World!", "text/plain");
  });

  svr.Post("/api/items", [](const httplib::Request &req, httplib::Response &res) {
    // req.bodyにリクエストボディが入っている
    res.status = 201;
    res.set_content("Created", "text/plain");
  });

  svr.Put("/api/items/1", [](const httplib::Request &req, httplib::Response &res) {
    res.set_content("Updated", "text/plain");
  });

  svr.Delete("/api/items/1", [](const httplib::Request &req, httplib::Response &res) {
    res.status = 204;
  });

  svr.listen("0.0.0.0", 8080);
}
```

ハンドラは`(const Request&, Response&)`の2引数を受け取ります。`res.set_content()`でレスポンスボディとContent-Typeを設定し、`res.status`でステータスコードを指定します。`listen()`を呼ぶとサーバーが起動し、ブロックされます。

## クエリパラメーターを取得する

```cpp
svr.Get("/search", [](const httplib::Request &req, httplib::Response &res) {
  auto q = req.get_param_value("q");
  auto limit = req.get_param_value("limit");
  res.set_content("q=" + q + ", limit=" + limit, "text/plain");
});
```

`req.get_param_value()`でクエリ文字列の値を取り出せます。存在するかどうかを先に調べたいなら`req.has_param("q")`を使います。

## リクエストヘッダーを読む

```cpp
svr.Get("/me", [](const httplib::Request &req, httplib::Response &res) {
  auto ua = req.get_header_value("User-Agent");
  res.set_content("UA: " + ua, "text/plain");
});
```

レスポンスヘッダーを追加したいときは`res.set_header("Name", "Value")`です。

> **Note:** `listen()`はブロックする関数です。別スレッドで動かしたいときは`std::thread`で包むか、ノンブロッキング起動が必要なら[S18. `listen_after_bind`で起動順序を制御する](s18-listen-after-bind)を参照してください。

> パスパラメーター（`/users/:id`）を使いたい場合は[S03. パスパラメーターを使う](s03-path-params)を参照してください。
