---
title: "S02. JSONリクエストを受け取りJSONレスポンスを返す"
order: 21
status: "draft"
---

cpp-httplibにはJSONパーサーが含まれていません。サーバー側でも[nlohmann/json](https://github.com/nlohmann/json)などを組み合わせて使います。ここでは`nlohmann/json`を例に説明します。

## JSONを受け取って返す

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>

int main() {
  httplib::Server svr;

  svr.Post("/api/users", [](const httplib::Request &req, httplib::Response &res) {
    try {
      auto in = nlohmann::json::parse(req.body);

      nlohmann::json out = {
        {"id", 42},
        {"name", in["name"]},
        {"created_at", "2026-04-10T12:00:00Z"},
      };

      res.status = 201;
      res.set_content(out.dump(), "application/json");
    } catch (const std::exception &e) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid json\"}", "application/json");
    }
  });

  svr.listen("0.0.0.0", 8080);
}
```

`req.body`はそのまま`std::string`なので、JSONライブラリに渡してパースします。レスポンスは`dump()`で文字列にして、Content-Typeに`application/json`を指定して返します。

## Content-Typeをチェックする

```cpp
svr.Post("/api/users", [](const httplib::Request &req, httplib::Response &res) {
  auto content_type = req.get_header_value("Content-Type");
  if (content_type.find("application/json") == std::string::npos) {
    res.status = 415; // Unsupported Media Type
    return;
  }
  // ...
});
```

厳密にJSONだけを受け付けたいときは、Content-Typeを確認してから処理しましょう。

## JSONを返すヘルパーを作る

同じパターンを何度も書くなら、小さなヘルパーを用意すると楽です。

```cpp
auto send_json = [](httplib::Response &res, int status, const nlohmann::json &j) {
  res.status = status;
  res.set_content(j.dump(), "application/json");
};

svr.Get("/api/health", [&](const auto &req, auto &res) {
  send_json(res, 200, {{"status", "ok"}});
});
```

> **Note:** 大きなJSONボディを受け取ると、`req.body`がまるごとメモリに載ります。巨大なペイロードを扱うときは[S07. マルチパートデータをストリーミングで受け取る](s07-multipart-reader)のように、ストリーミング受信も検討しましょう。

> クライアント側の書き方は[C02. JSONを送受信する](c02-json)を参照してください。
