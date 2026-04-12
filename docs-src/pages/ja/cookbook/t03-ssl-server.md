---
title: "T03. SSL/TLSサーバーを立ち上げる"
order: 44
status: "draft"
---

HTTPSサーバーを立ち上げるには、`httplib::Server`の代わりに`httplib::SSLServer`を使います。サーバー証明書と秘密鍵をコンストラクタに渡せば、あとは`Server`とまったく同じように使えます。

## 基本の使い方

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

int main() {
  httplib::SSLServer svr("cert.pem", "key.pem");

  svr.Get("/", [](const auto &req, auto &res) {
    res.set_content("hello over TLS", "text/plain");
  });

  svr.listen("0.0.0.0", 443);
}
```

コンストラクタにサーバー証明書（PEM形式）と秘密鍵のファイルパスを渡します。これだけでTLS対応のサーバーが立ちます。ハンドラの登録も`listen()`の呼び方も、通常の`Server`と同じです。

## 秘密鍵がパスワード保護されている場合

第5引数に秘密鍵のパスワードを渡せます。

```cpp
httplib::SSLServer svr("cert.pem", "key.pem",
                       nullptr, nullptr, "password");
```

第3、第4引数はクライアント証明書検証用（mTLS、[T04. mTLSを設定する](t04-mtls)参照）なので、今は`nullptr`を指定します。

## メモリ上のPEMから立ち上げる

ファイルではなくメモリ上のPEMデータから起動したいときは、`PemMemory`構造体を使います。

```cpp
httplib::SSLServer::PemMemory pem{};
pem.cert_pem = cert_data.data();
pem.cert_pem_len = cert_data.size();
pem.key_pem = key_data.data();
pem.key_pem_len = key_data.size();

httplib::SSLServer svr(pem);
```

環境変数やシークレットマネージャから証明書を取得する場合に便利です。

## 証明書の更新

証明書の有効期限が切れる前に、サーバーを再起動せずに新しい証明書に差し替えたいことがあります。`update_certs_pem()`が使えます。

```cpp
svr.update_certs_pem(new_cert_pem, new_key_pem);
```

既存の接続はそのまま、これから確立する接続は新しい証明書で動きます。

## 証明書の準備

テスト用の自己署名証明書は、OpenSSLのコマンドで作れます。

```sh
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout key.pem -out cert.pem -subj "/CN=localhost"
```

本番では、Let's Encryptや社内CAから発行された証明書を使いましょう。

> **Warning:** HTTPSサーバーを443番ポートで立ち上げるにはroot権限が必要です。安全に立ち上げる方法は[S18. `listen_after_bind`で起動順序を制御する](s18-listen-after-bind)の「特権降格」を参照してください。

> クライアント証明書による相互認証（mTLS）は[T04. mTLSを設定する](t04-mtls)を参照してください。
