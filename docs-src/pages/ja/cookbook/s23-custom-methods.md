---
title: "S23. カスタムHTTPメソッドを扱う"
order: 42
status: "draft"
---

サーバーは知らないHTTPメソッドを`400 Bad Request`で弾きます。RFC 4918のWebDAVメソッド（`PROPFIND`、`PROPPATCH`、`MKCOL`など）やUPnPの`SUBSCRIBE`のような拡張メソッドを受け付けたいときは、`CustomRoute()`でハンドラを登録してください。登録したことがそのまま「このメソッドを受け付ける」という意味になります。

## 基本の使い方

```cpp
svr.CustomRoute("PROPFIND", "/dav/:id",
                [](const httplib::Request &req, httplib::Response &res) {
                  // リクエストボディも通常どおり読める
                  auto id = req.path_params.at("id");
                  res.status = httplib::StatusCode::MultiStatus_207;
                  res.set_content(build_multistatus(req.body), "application/xml");
                });
```

パターンの書き方は`Get()`などと同じです。正規表現もパスパラメーターもそのまま使えます。

## OPTIONSで対応メソッドを知らせる

WebDAVクライアントは接続すると、まず`OPTIONS`でサーバーの能力を問い合わせます。cpp-httplibは`DAV:`ヘッダーも`Allow`ヘッダーも自動生成しないので、自分で返してください。ここを忘れると、`PROPFIND`が正しく動いてもクライアントに拒否されます。

```cpp
svr.Options("/dav/.*", [](const httplib::Request &req, httplib::Response &res) {
  res.set_header("DAV", "1");
  res.set_header("Allow", "OPTIONS, GET, HEAD, PROPFIND, PROPPATCH, MKCOL");
});
```

## ボディをストリーミングで受け取る

`Post()`などと同じく、Content Reader版のオーバーロードがあります。大きなXMLを一度にメモリへ載せたくないときに使ってください。

```cpp
svr.CustomRoute("REPORT", "/dav/.*",
                [](const httplib::Request &req, httplib::Response &res,
                   const httplib::ContentReader &content_reader) {
                  content_reader([&](const char *data, size_t data_length) {
                    // 少しずつ処理する
                    return true;
                  });
                  res.status = httplib::StatusCode::MultiStatus_207;
                });
```

## 覚えておくこと

- メソッド名はHTTPのトークン（RFC 9110）である必要があります。`listen()`より前に登録してください
- `GET`、`HEAD`、`POST`、`PUT`、`DELETE`、`CONNECT`、`OPTIONS`、`TRACE`、`PATCH`、`PRI`は登録できません。これらには専用のメソッドを使ってください
- 登録が拒否されると`is_valid()`が`false`になり、`listen()`が失敗します。呼ばれないハンドラを抱えたままサーバーが起動することはありません
- 静的ファイルの配信とWebSocketのアップグレードは`GET`/`HEAD`のままです

> **Note:** cpp-httplibが用意するのはメソッドのルーティングまでです。WebDAVを名乗るなら、`207 Multi-Status`のXML生成、`Depth`ヘッダーの解釈、ロックの管理は自分で実装することになります。プロトコルの本体はライブラリの外側です。

> ハンドラ登録の基本は[S01. GET / POST / PUT / DELETEハンドラを登録する](../s01-handlers)を参照してください。
