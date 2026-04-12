---
title: "C06. BearerトークンでAPIを呼ぶ"
order: 6
status: "draft"
---

OAuth 2.0やモダンなWeb APIでよく使われるBearerトークン認証には、`set_bearer_token_auth()`を使います。トークンを渡すと、cpp-httplibが`Authorization: Bearer <token>`ヘッダーを自動で組み立ててくれます。

## 基本の使い方

```cpp
httplib::Client cli("https://api.example.com");
cli.set_bearer_token_auth("eyJhbGciOiJIUzI1NiIs...");

auto res = cli.Get("/me");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

一度設定すれば、以降のリクエストすべてにトークンが付きます。GitHub APIやSlack API、自前のOAuthサービスなど、トークンベースのAPIを叩くときの定番です。

## リクエスト単位で使う

特定のリクエストだけにトークンを付けたい、あるいはリクエストごとに違うトークンを使いたいときは、Headersで直接渡せます。

```cpp
httplib::Headers headers = {
  httplib::make_bearer_token_authentication_header(token),
};
auto res = cli.Get("/me", headers);
```

`make_bearer_token_authentication_header()`が`Authorization`ヘッダーを組み立ててくれます。

## トークンをリフレッシュする

トークンの有効期限が切れたら、新しいトークンで`set_bearer_token_auth()`を呼び直すだけで更新できます。

```cpp
if (res && res->status == 401) {
  auto new_token = refresh_token();
  cli.set_bearer_token_auth(new_token);
  res = cli.Get("/me");
}
```

> **Warning:** Bearerトークンはそれ自体が認証情報です。必ずHTTPS経由で送ってください。また、ソースコードや設定ファイルにトークンをハードコードしないようにしましょう。

> 複数のヘッダーをまとめて設定したいときは[C03. デフォルトヘッダーを設定する](c03-default-headers)も便利です。
