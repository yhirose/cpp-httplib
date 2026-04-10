---
title: "C05. Basic認証を使う"
order: 5
status: "draft"
---

Basic認証が必要なエンドポイントには、`set_basic_auth()`でユーザー名とパスワードを渡します。cpp-httplibが自動で`Authorization: Basic ...`ヘッダーを組み立ててくれます。

## 基本の使い方

```cpp
httplib::Client cli("https://api.example.com");
cli.set_basic_auth("alice", "s3cret");

auto res = cli.Get("/private");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

一度設定すれば、そのクライアントから送るすべてのリクエストに認証情報が付きます。毎回ヘッダーを組み立てる必要はありません。

## リクエスト単位で使う

特定のリクエストだけに認証情報を付けたいときは、Headersを直接渡す方法もあります。

```cpp
httplib::Headers headers = {
  httplib::make_basic_authentication_header("alice", "s3cret"),
};
auto res = cli.Get("/private", headers);
```

`make_basic_authentication_header()`がBase64エンコード済みのヘッダーを作ってくれます。

> **Warning:** Basic認証は資格情報をBase64で**エンコード**するだけで、暗号化しません。必ずHTTPS経由で使ってください。平文HTTPで使うと、パスワードがネットワーク上を丸見えで流れます。

## Digest認証

より安全なDigest認証を使いたいときは`set_digest_auth()`を使います。こちらはOpenSSL（または他のTLSバックエンド）付きでビルドしたときだけ利用できます。

```cpp
cli.set_digest_auth("alice", "s3cret");
```

> BearerトークンでAPIを呼びたい場合はC06. BearerトークンでAPIを呼ぶを参照してください。
