---
title: "HTTPS Server"
order: 7
---

前章ではHTTPSクライアントを使いました。今度は自分でHTTPSサーバーを立ててみましょう。3章の `httplib::Server` を `httplib::SSLServer` に置き換えるだけです。

ただし、TLSサーバーにはサーバー証明書と秘密鍵が必要です。まずはそこから準備しましょう。

## 自己署名証明書の作成

開発やテスト用なら、自己署名証明書（いわゆるオレオレ証明書）で十分です。OpenSSLのコマンドでサクッと作れます。

```sh
openssl req -x509 -noenc -keyout key.pem -out cert.pem -subj /CN=localhost
```

これで2つのファイルができます。

- **`cert.pem`** — サーバー証明書
- **`key.pem`** — 秘密鍵

## 最小のHTTPSサーバー

証明書ができたら、さっそくサーバーを書いてみましょう。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::SSLServer svr("cert.pem", "key.pem");

    svr.Get("/", [](const auto &, auto &res) {
        res.set_content("Hello, HTTPS!", "text/plain");
    });

    std::cout << "Listening on https://localhost:8443" << std::endl;
    svr.listen("0.0.0.0", 8443);
}
```

`httplib::SSLServer` のコンストラクタに証明書と秘密鍵のパスを渡すだけです。ルーティングの書き方は3章の `httplib::Server` とまったく同じですよ。

コンパイルして起動しましょう。

## 動作確認

サーバーが起動したら、`curl` でアクセスしてみましょう。自己署名証明書なので、`-k` オプションで証明書検証をスキップします。

```sh
curl -k https://localhost:8443/
# Hello, HTTPS!
```

ブラウザで `https://localhost:8443` を開くと、「この接続は安全ではありません」と警告が出ます。自己署名証明書なので正常です。気にせず進めてください。

## クライアントからの接続

前章の `httplib::Client` で接続してみましょう。自己署名証明書のサーバーに接続するには、2つの方法があります。

### 方法1: 証明書検証を無効にする

開発時の手軽な方法です。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://localhost:8443");
    cli.enable_server_certificate_verification(false);

    auto res = cli.Get("/");
    if (res) {
        std::cout << res->body << std::endl;  // Hello, HTTPS!
    }
}
```

### 方法2: 自己署名証明書をCA証明書として指定する

こちらのほうが安全です。`cert.pem` をCA証明書として信頼するよう指定します。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://localhost:8443");
    cli.set_ca_cert_path("cert.pem");

    auto res = cli.Get("/");
    if (res) {
        std::cout << res->body << std::endl;  // Hello, HTTPS!
    }
}
```

この方法なら、指定した証明書のサーバーにだけ接続を許可して、なりすましを防げます。テスト環境でもなるべくこちらを使いましょう。

## Server と SSLServer の比較

3章で学んだ `httplib::Server` のAPIは、`httplib::SSLServer` でもそのまま使えます。違いはコンストラクタだけです。

| | `httplib::Server` | `httplib::SSLServer` |
| -- | ------------------ | -------------------- |
| コンストラクタ | 引数なし | 証明書と秘密鍵のパス |
| プロトコル | HTTP | HTTPS |
| ポート（慣例） | 8080 | 8443 |
| ルーティング | 共通 | 共通 |

HTTPサーバーをHTTPSに切り替えるには、コンストラクタを変えるだけです。

## 次のステップ

HTTPSサーバーが動きましたね。これでHTTP/HTTPSのクライアントとサーバー、両方の基本がそろいました。

次は、cpp-httplibに新しく加わったWebSocket機能を見てみましょう。

**次:** [WebSocket](../08-websocket)
