---
title: "S11. Pre-request handlerでルート単位の認証を行う"
order: 30
status: "draft"
---

S09で紹介した`set_pre_routing_handler()`はルーティングの**前**に呼ばれるので、「どのルートにマッチしたか」を知れません。ルートによって認証の有無を変えたい場合は、`set_pre_request_handler()`のほうが便利です。

## Pre-routingとの違い

| フック | 呼ばれるタイミング | ルート情報 |
| --- | --- | --- |
| `set_pre_routing_handler` | ルーティングの前 | 取得できない |
| `set_pre_request_handler` | ルーティング後、ルートハンドラの直前 | `req.matched_route`で取得可能 |

Pre-requestハンドラなら、`req.matched_route`に「マッチしたパターン文字列」が入っているので、ルートに応じて処理を変えられます。

## ルートごとに認証を切り替える

```cpp
svr.set_pre_request_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    // /adminで始まるルートだけ認証を要求
    if (req.matched_route.rfind("/admin", 0) == 0) {
      auto token = req.get_header_value("Authorization");
      if (!is_admin_token(token)) {
        res.status = 403;
        res.set_content("forbidden", "text/plain");
        return httplib::Server::HandlerResponse::Handled;
      }
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });
```

`matched_route`はパスパラメーターを展開する**前**のパターン文字列（例: `/admin/users/:id`）です。特定の値ではなく、ルート定義のパターンで判定できるので、IDや名前に左右されません。

## 戻り値の意味

Pre-routingハンドラと同じく、`HandlerResponse`を返します。

- `Unhandled`: 通常の処理を続行（ルートハンドラが呼ばれる）
- `Handled`: ここで完了、ルートハンドラはスキップされる

## 認証情報を後続のハンドラに渡す

認証で取り出したユーザー情報などをルートハンドラに渡したいときは、`res.user_data`を使います。詳しくはS12. `res.user_data`でハンドラ間データを渡すを参照してください。
