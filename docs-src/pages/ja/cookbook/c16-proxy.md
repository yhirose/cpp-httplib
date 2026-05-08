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

## 特定のホストだけプロキシをバイパスする

社内エンドポイントなどはプロキシを経由させたくないことがあります。`set_no_proxy()`で除外リストを指定できます。

```cpp
cli.set_proxy("proxy.internal", 8080);
cli.set_no_proxy({"internal.corp", "10.0.0.0/8", "*.dev.local"});
```

エントリは次のいずれかです。

- `*` — すべてのホストでバイパス
- ホスト名サフィックス（例: `example.com`）— `example.com`本体と任意のサブドメイン（`foo.example.com`）にマッチ。先頭にドットを付けても同じ意味です（`.example.com`）。
- 単一のIPリテラル（例: `192.168.1.1`、`::1`）
- CIDRブロック（例: `10.0.0.0/8`、`fe80::/10`）

ホスト名のマッチは大文字小文字を区別せず、ドット境界でしか一致しません。たとえば`example.com`というエントリは`evilexample.com`にはマッチしません。IPの比較は`inet_pton`で正規化されるので、`127.0.0.1`を`127.000.000.001`のような別表記でバイパスすることはできません。マッチした場合、`Proxy-Authorization`ヘッダーも自動的に外れます。

不正な書式のエントリは黙って捨てられます。`example.com:8080`のようなポート指定エントリはサポート外です（cpp-httplibの他のホストキーAPIもホスト名のみを扱う設計のため）。

## 環境変数からプロキシ設定を読み込む

`set_proxy_from_env()`を呼ぶと、起動時の環境変数からプロキシ設定をまとめて取り込めます。

```cpp
httplib::Client cli("https://api.example.com");
cli.set_proxy_from_env();
```

読み込まれる変数:

- `https_proxy` / `HTTPS_PROXY` — HTTPSクライアントが使用
- `http_proxy`（**小文字のみ**、後述）— HTTPクライアントが使用
- `no_proxy` / `NO_PROXY` — カンマ区切りのバイパスリスト

少なくとも1つの変数が見つかって適用されたら`true`を返します。

> **Security Note:** 大文字の`HTTP_PROXY`は意図的に**読まれません**。CGI/FastCGI環境では`HTTP_*`という名前空間がHTTPリクエストヘッダーの公開に使われており、攻撃者が`Proxy:`リクエストヘッダーで任意のプロキシURLを差し込めてしまうためです（[CVE-2016-5385 / "httpoxy"](https://httpoxy.org/)）。curl・Go・Python `requests`と同じく、cpp-httplibも小文字の`http_proxy`しか採用しません。`HTTPS_PROXY`や`NO_PROXY`は名前が`HTTP_`で始まらないので、どちらの大文字小文字でも安全です。

> **Note:** `set_proxy_from_env()`は同期的に`getenv`を呼ぶだけなので、起動時に1回呼ぶことを想定しています。他スレッドが同時に`setenv`しているケースは未定義です。
