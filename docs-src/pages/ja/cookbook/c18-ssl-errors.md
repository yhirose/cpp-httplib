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

`ssl_error()`はSSLライブラリが返したエラーコード（OpenSSLの`SSL_get_error()`の値など）、`ssl_backend_error()`はバックエンドがさらに詳しく提供するエラー値です。OpenSSLなら`ERR_get_error()`の値が入ります。

## OpenSSLのエラーを文字列化する

`ssl_backend_error()`で取得した値を、OpenSSLの`ERR_error_string()`で文字列にするとデバッグに便利です。

```cpp
#include <openssl/err.h>

if (res.ssl_backend_error() != 0) {
  char buf[256];
  ERR_error_string_n(res.ssl_backend_error(), buf, sizeof(buf));
  std::cerr << "openssl: " << buf << std::endl;
}
```

## よくある原因

| 症状 | ありがちな原因 |
| --- | --- |
| `SSLServerVerification` | CA証明書のパスが通っていない、自己署名証明書 |
| `SSLServerHostnameVerification` | 証明書のCN/SANとホスト名が一致しない |
| `SSLConnection` | TLSバージョンの不一致、対応スイートが無い |

> **Note:** `ssl_backend_error()`は以前は`ssl_openssl_error()`と呼ばれていました。後者はdeprecatedで、現在は`ssl_backend_error()`を使ってください。

> 証明書の検証設定を変えたい場合は[T02. SSL証明書の検証を制御する](t02-cert-verification)を参照してください。
