---
title: "T02. SSL証明書の検証を制御する"
order: 43
status: "draft"
---

HTTPSクライアントは、デフォルトでサーバー証明書を検証します。OSのルート証明書ストアを使って、証明書チェーンの有効性とホスト名の一致を確認します。この挙動を変えたいときに使うAPIを紹介します。

## 独自のCA証明書を指定する

社内認証局（CA）で署名された証明書を使うサーバーに接続するときは、`set_ca_cert_path()`でCA証明書を指定します。

```cpp
httplib::Client cli("https://internal.example.com");
cli.set_ca_cert_path("/etc/ssl/certs/internal-ca.pem");

auto res = cli.Get("/");
```

第1引数がCA証明書ファイル、第2引数がCA証明書ディレクトリ（省略可）です。OpenSSLバックエンドなら、`set_ca_cert_store()`で`X509_STORE*`を直接渡すこともできます。

## 証明書検証を無効にする（非推奨）

開発用のサーバーや自己署名証明書にアクセスしたいときは、検証を無効にできます。

```cpp
httplib::Client cli("https://self-signed.example.com");
cli.enable_server_certificate_verification(false);

auto res = cli.Get("/");
```

これだけで、証明書チェーンの検証がスキップされます。

> **Warning:** 証明書検証を無効にすると、中間者攻撃（MITM）を防げなくなります。本番環境では**絶対に使わない**でください。開発やテスト以外で無効化する必要が出たら、「もう一度やり方を間違えていないか確認する」という癖をつけましょう。

## ホスト名検証だけを無効にする

証明書チェーンは検証したいけれど、ホスト名の一致だけスキップしたい、という中間的な設定もあります。証明書のCN/SANとリクエスト先のホスト名が食い違うサーバーにアクセスするときに使います。

```cpp
cli.enable_server_hostname_verification(false);
```

証明書そのものは有効かどうか検証するので、「検証完全無効」よりは少し安全です。ただ、これも本番ではおすすめしません。

## OSの証明書ストアをそのまま使う

多くのLinuxディストリビューションでは、`/etc/ssl/certs/ca-certificates.crt`などにルート証明書がまとまっています。cpp-httplibは起動時にOSのデフォルトストアを自動で読みにいくので、普通のサーバーならとくに設定不要です。

> mbedTLSやwolfSSLバックエンドでも同じAPIが使えます。バックエンドの選び方はT01. OpenSSL・mbedTLS・wolfSSLの選択指針を参照してください。

> 失敗したときの詳細を調べる方法はC18. SSLエラーをハンドリングするを参照してください。
