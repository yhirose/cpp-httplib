---
title: "HTTPS Client"
order: 6
---

前章でOpenSSLのセットアップが済んだので、さっそくHTTPSクライアントを使ってみましょう。2章で使った `httplib::Client` がそのまま使えます。コンストラクタに `https://` 付きのURLを渡すだけです。

## GETリクエスト

実在するHTTPSサイトにアクセスしてみましょう。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://nghttp2.org");

    auto res = cli.Get("/");
    if (res) {
        std::cout << res->status << std::endl;           // 200
        std::cout << res->body.substr(0, 100) << std::endl;  // HTMLの先頭部分
    } else {
        std::cout << "Error: " << httplib::to_string(res.error()) << std::endl;
    }
}
```

2章では `httplib::Client cli("http://localhost:8080")` と書きましたよね。スキームを `https://` に変えるだけです。`Get()` や `Post()` など、2章で学んだAPIはすべてそのまま使えます。

```sh
curl https://nghttp2.org/
```

## ポートの指定

HTTPSのデフォルトポートは443です。別のポートを使いたい場合は、URLにポートを含めます。

```cpp
httplib::Client cli("https://localhost:8443");
```

## CA証明書の検証

`httplib::Client` はHTTPS接続時、デフォルトでサーバー証明書を検証します。信頼できるCA（認証局）が発行した証明書を持つサーバーにしか接続しません。

CA証明書は、macOSならKeychain、LinuxならシステムのCA証明書ストア、WindowsならWindowsの証明書ストアから自動で読み込みます。ほとんどの場合、追加の設定は要りません。

### CA証明書ファイルの指定

環境によってはシステムのCA証明書が見つからないこともあります。そのときは `set_ca_cert_path()` でパスを直接指定してください。

```cpp
httplib::Client cli("https://nghttp2.org");
cli.set_ca_cert_path("/etc/ssl/certs/ca-certificates.crt");

auto res = cli.Get("/");
```

```sh
curl --cacert /etc/ssl/certs/ca-certificates.crt https://nghttp2.org/
```

### 証明書検証の無効化

開発中、自己署名証明書のサーバーに接続したいときは、検証を無効にできます。

```cpp
httplib::Client cli("https://localhost:8443");
cli.enable_server_certificate_verification(false);

auto res = cli.Get("/");
```

```sh
curl -k https://localhost:8443/
```

本番では絶対に無効にしないでください。中間者攻撃のリスクがあります。

## リダイレクトの追跡

HTTPSサイトへのアクセスでは、リダイレクトに遭遇することがよくあります。たとえば `http://` から `https://` へ、あるいは `www` なしから `www` ありへ転送されるケースです。

デフォルトではリダイレクトを追跡しません。リダイレクト先は `Location` ヘッダーで確認できます。

```cpp
httplib::Client cli("https://nghttp2.org");

auto res = cli.Get("/httpbin/redirect/3");
if (res) {
    std::cout << res->status << std::endl;  // 302
    std::cout << res->get_header_value("Location") << std::endl;
}
```

```sh
curl https://nghttp2.org/httpbin/redirect/3
```

`set_follow_location(true)` を設定すると、リダイレクトを自動で追跡して、最終的なレスポンスを返してくれます。

```cpp
httplib::Client cli("https://nghttp2.org");
cli.set_follow_location(true);

auto res = cli.Get("/httpbin/redirect/3");
if (res) {
    std::cout << res->status << std::endl;  // 200（最終的なレスポンス）
}
```

```sh
curl -L https://nghttp2.org/httpbin/redirect/3
```

## 次のステップ

HTTPSクライアントの使い方がわかりましたね。次は自分でHTTPSサーバーを立ててみましょう。自己署名証明書の作り方から始めます。

**次:** [HTTPS Server](../07-https-server)
