---
title: "C16. プロキシを経由してリクエストを送る"
order: 16
status: "draft"
---

社内ネットワークや特定の経路を通したい場合、HTTPプロキシを経由してリクエストを送れます。`set_proxy()`でプロキシのホストとポートを指定するだけです。

## 基本の使い方

```cpp
httplib::Client cli("https://api.example.com");
cli.set_proxy("proxy.internal", 8080);

auto res = cli.Get("/users");
```

プロキシ経由でリクエストが送られます。HTTPSの場合はCONNECTメソッドでトンネルが張られるので、cpp-httplib側で特別な設定は要りません。

## プロキシに認証を設定する

プロキシ自体が認証を要求する場合は、`set_proxy_basic_auth()`や`set_proxy_bearer_token_auth()`を使います。

```cpp
cli.set_proxy("proxy.internal", 8080);
cli.set_proxy_basic_auth("user", "password");
```

```cpp
cli.set_proxy_bearer_token_auth("token");
```

OpenSSL（または他のTLSバックエンド）付きでビルドしていれば、Digest認証も使えます。

```cpp
cli.set_proxy_digest_auth("user", "password");
```

## エンドのサーバー認証と組み合わせる

プロキシ認証と、エンドサーバーへの認証（[C05. Basic認証を使う](c05-basic-auth)や[C06. BearerトークンでAPIを呼ぶ](c06-bearer-token)）は別物です。両方が必要なら、両方設定します。

```cpp
cli.set_proxy("proxy.internal", 8080);
cli.set_proxy_basic_auth("proxy-user", "proxy-pass");

cli.set_bearer_token_auth("api-token"); // エンドサーバー向け
```

プロキシには`Proxy-Authorization`、エンドサーバーには`Authorization`ヘッダーが送られます。

> **Note:** 環境変数の`HTTP_PROXY`や`HTTPS_PROXY`は自動的には読まれません。必要ならアプリケーション側で読み取って`set_proxy()`に渡してください。
