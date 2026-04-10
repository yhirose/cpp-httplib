---
title: "S09. 全ルートに共通の前処理をする"
order: 28
status: "draft"
---

すべてのリクエストに対して共通の処理を走らせたいことがあります。認証チェック、ロギング、レート制限などです。こうした処理は`set_pre_routing_handler()`で登録します。

## 基本の使い方

```cpp
svr.set_pre_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    std::cout << req.method << " " << req.path << std::endl;
    return httplib::Server::HandlerResponse::Unhandled;
  });
```

Pre-routingハンドラは、**ルーティングよりも前**に呼ばれます。どのハンドラにもマッチしないリクエストも含めて、すべてのリクエストを捕まえられます。

戻り値の`HandlerResponse`がポイントです。

- `Unhandled`を返す: 通常の処理を続行（ルーティングとハンドラ呼び出し）
- `Handled`を返す: ここでレスポンスが完了したとみなし、以降の処理をスキップ

## 認証チェックに使う

全ルート共通の認証を一箇所でかけられます。

```cpp
svr.set_pre_routing_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    if (req.path.rfind("/public", 0) == 0) {
      return httplib::Server::HandlerResponse::Unhandled; // 認証不要
    }

    auto auth = req.get_header_value("Authorization");
    if (auth.empty()) {
      res.status = 401;
      res.set_content("unauthorized", "text/plain");
      return httplib::Server::HandlerResponse::Handled;
    }

    return httplib::Server::HandlerResponse::Unhandled;
  });
```

認証が通らなければ`Handled`を返してその場で401を返し、通れば`Unhandled`を返して通常のルーティングに進ませます。

## 特定ルートだけに認証をかけたい場合

全ルート共通ではなく、ルート単位で認証を分けたいときは、S11. Pre-request handlerでルート単位の認証を行うのほうが適しています。

> **Note:** レスポンスを加工したいだけなら、`set_post_routing_handler()`のほうが適切です。S10. Post-routing handlerでレスポンスヘッダーを追加するを参照してください。
