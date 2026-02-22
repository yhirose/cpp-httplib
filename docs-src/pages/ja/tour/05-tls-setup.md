---
title: "TLS Setup"
order: 5
---

ここまではHTTP（平文）でやってきましたが、実際のWebではHTTPS（暗号化通信）が当たり前ですよね。cpp-httplibでHTTPSを使うには、TLSライブラリが必要です。

このTourではOpenSSLを使います。最も広く使われていて、情報も豊富です。

## OpenSSLのインストール

お使いのOSに合わせてインストールしましょう。

| OS | インストール方法 |
| -- | ---------------- |
| macOS | [Homebrew](https://brew.sh/) (`brew install openssl`) |
| Ubuntu / Debian | `sudo apt install libssl-dev` |
| Windows | [vcpkg](https://vcpkg.io/) (`vcpkg install openssl`) |

## コンパイルオプション

TLS機能を有効にするには、`CPPHTTPLIB_OPENSSL_SUPPORT` マクロを定義してコンパイルします。前章までのコンパイルコマンドに、いくつかオプションが増えます。

```sh
# macOS (Homebrew)
clang++ -std=c++17 -DCPPHTTPLIB_OPENSSL_SUPPORT \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -lssl -lcrypto \
    -framework CoreFoundation -framework Security \
    -o server server.cpp

# Linux
clang++ -std=c++17 -pthread -DCPPHTTPLIB_OPENSSL_SUPPORT \
    -lssl -lcrypto \
    -o server server.cpp

# Windows (Developer Command Prompt)
cl /EHsc /std:c++17 /DCPPHTTPLIB_OPENSSL_SUPPORT server.cpp libssl.lib libcrypto.lib
```

それぞれのオプションの役割を見てみましょう。

- **`-DCPPHTTPLIB_OPENSSL_SUPPORT`** — TLS機能を有効にするマクロ定義
- **`-lssl -lcrypto`** — OpenSSLのライブラリをリンク
- **`-I` / `-L`**（macOSのみ）— Homebrew版OpenSSLのパスを指定
- **`-framework CoreFoundation -framework Security`**（macOSのみ）— Keychainからシステム証明書を自動で読み込むために必要です

## 動作確認

ちゃんと動くか確認してみましょう。`httplib::Client` にHTTPSのURLを渡してアクセスするだけのプログラムです。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("https://www.google.com");

    auto res = cli.Get("/");
    if (res) {
        std::cout << "Status: " << res->status << std::endl;
    } else {
        std::cout << "Error: " << httplib::to_string(res.error()) << std::endl;
    }
}
```

コンパイルして実行してみてください。`Status: 200` と表示されれば、セットアップ完了です。

## 他のTLSバックエンド

cpp-httplibはOpenSSL以外にも、Mbed TLSとwolfSSLに対応しています。マクロ定義とリンクするライブラリを変えるだけで切り替えられます。

| バックエンド | マクロ定義 | リンクするライブラリ |
| :--- | :--- | :--- |
| OpenSSL | `CPPHTTPLIB_OPENSSL_SUPPORT` | `libssl`, `libcrypto` |
| Mbed TLS | `CPPHTTPLIB_MBEDTLS_SUPPORT` | `libmbedtls`, `libmbedx509`, `libmbedcrypto` |
| wolfSSL | `CPPHTTPLIB_WOLFSSL_SUPPORT` | `libwolfssl` |

このTourではOpenSSLを前提に進めますが、APIはどのバックエンドでも共通です。

## 次のステップ

TLSの準備ができましたね。次は、HTTPSサイトにリクエストを送ってみましょう。

**次:** [HTTPS Client](../06-https-client)
