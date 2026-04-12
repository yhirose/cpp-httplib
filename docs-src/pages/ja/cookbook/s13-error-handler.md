---
title: "S13. カスタムエラーページを返す"
order: 32
status: "draft"
---

404や500のような**ハンドラが返したエラーレスポンス**を加工したいときは、`set_error_handler()`を使います。デフォルトの味気ないエラーページを、独自のHTMLやJSONに差し替えられます。

## 基本の使い方

```cpp
svr.set_error_handler([](const httplib::Request &req, httplib::Response &res) {
  auto body = "<h1>Error " + std::to_string(res.status) + "</h1>";
  res.set_content(body, "text/html");
});
```

エラーハンドラは、`res.status`が4xxまたは5xxでレスポンスが返る直前に呼ばれます。`res.set_content()`で差し替えれば、すべてのエラーレスポンスで同じテンプレートが使えます。

## ステータスコード別の処理

```cpp
svr.set_error_handler([](const httplib::Request &req, httplib::Response &res) {
  if (res.status == 404) {
    res.set_content("<h1>Not Found</h1><p>" + req.path + "</p>", "text/html");
  } else if (res.status >= 500) {
    res.set_content("<h1>Server Error</h1>", "text/html");
  }
});
```

`res.status`を見て分岐すれば、404には専用のメッセージを、5xxにはサポート窓口のリンクを、といった使い分けができます。

## JSON APIのエラーレスポンス

APIサーバーなら、エラーもJSONで返したいことが多いはずです。

```cpp
svr.set_error_handler([](const httplib::Request &req, httplib::Response &res) {
  nlohmann::json j = {
    {"error", true},
    {"status", res.status},
    {"path", req.path},
  };
  res.set_content(j.dump(), "application/json");
});
```

これで全エラーが統一されたJSONで返ります。

> **Note:** `set_error_handler()`は、ルートハンドラが例外を投げた場合の500エラーにも呼ばれます。例外そのものの情報を取り出したい場合は`set_exception_handler()`を組み合わせましょう。[S14. 例外をキャッチする](s14-exception-handler)を参照してください。
