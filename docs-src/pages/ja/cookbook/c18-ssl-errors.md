---
title: "C18. SSLエラーをハンドリングする"
order: 18
status: "draft"
---

HTTPSリクエストで失敗したとき、`res.error()`は`Error::SSLConnection`や`Error::SSLServerVerification`といった値を返します。ただ、これだけだと原因の切り分けが難しいこともあります。そんなときは`Result::ssl_error()`と`Result::ssl_backend_error()`が役に立ちます。

## SSLエラーの詳細を取得する

```cpp
httplib::Client cli("https://api.example.com");
auto res = cli.Get("/");

if (!res) {
  auto err = res.error();
  std::cerr << "error: " << httplib::to_string(err) << std::endl;

  if (err == httplib::Error::SSLConnection ||
      err == httplib::Error::SSLServerVerification) {
    std::cerr << "ssl_error: " << res.ssl_error() << std::endl;
    std::cerr << "ssl_backend_error: " << res.ssl_backend_error() << std::endl;
  }
}
```

`ssl_error()`は、どのTLSバックエンドでも共通のエラー種別（`httplib::tls::ErrorCode`）を`int`で返します。`ssl_backend_error()`は、バックエンドが返したエラー値そのものです。OpenSSLなら、ハンドシェイクの失敗では`ERR_get_error()`の値が、証明書検証の失敗では検証結果のコード（`X509_V_ERR_*`）が入ります。

## OpenSSLのエラーを文字列化する

`ssl_backend_error()`の値は、OpenSSLの関数で文字列にしておくとデバッグに便利です。使う関数は失敗の種類によって変わります。

```cpp
#include <openssl/err.h>
#include <openssl/x509.h>

if (res.error() == httplib::Error::SSLConnection) {
  char buf[256];
  ERR_error_string_n(res.ssl_backend_error(), buf, sizeof(buf));
  std::cerr << "openssl: " << buf << std::endl;
} else if (res.error() == httplib::Error::SSLServerVerification ||
           res.error() == httplib::Error::SSLServerHostnameVerification) {
  auto code = static_cast<long>(res.ssl_backend_error());
  std::cerr << "openssl: " << X509_verify_cert_error_string(code) << std::endl;
}
```

## よくある原因

| 症状 | ありがちな原因 |
| --- | --- |
| `SSLServerVerification` | CA証明書のパスが通っていない、自己署名証明書 |
| `SSLServerHostnameVerification` | 証明書のCN/SANとホスト名が一致しない |
| `SSLConnection` | TLSバージョンの不一致、対応スイートが無い |

> 証明書の検証設定を変えたい場合は[T02. SSL証明書の検証を制御する](../t02-cert-verification)を参照してください。
