---
title: "T01. OpenSSL・mbedTLS・wolfSSLの選択指針"
order: 42
status: "draft"
---

cpp-httplibはTLSの実装を自前では持たず、3つのバックエンドの中から1つを選んで使います。ビルド時に有効にするマクロで切り替えます。

| バックエンド | マクロ | 特徴 |
| --- | --- | --- |
| OpenSSL | `CPPHTTPLIB_OPENSSL_SUPPORT` | 最も広く使われている、機能が豊富 |
| mbedTLS | `CPPHTTPLIB_MBEDTLS_SUPPORT` | 軽量、組み込み向け |
| wolfSSL | `CPPHTTPLIB_WOLFSSL_SUPPORT` | 組み込み向け、商用サポートあり |

## ビルド時の指定

`httplib.h`をインクルードする前に、使いたいバックエンドのマクロを定義します。

```cpp
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
```

リンク時にそのバックエンドのライブラリ（`libssl`、`libcrypto`、`libmbedtls`、`libwolfssl`など）も必要です。

## どれを選ぶか

**迷ったらOpenSSL**  
機能が一番豊富で、情報も多いです。通常のサーバー用途やLinuxデスクトップ向けなら、まずこれで始めて問題ありません。

**バイナリサイズを抑えたい、組み込みで使う**  
mbedTLSかwolfSSLが向いています。OpenSSLよりずっとコンパクトで、メモリ制約のあるデバイスでも動きます。

**商用サポートが必要**  
wolfSSLには商用ライセンスとサポートがあります。製品に組み込むなら選択肢に入ります。

## 複数バックエンドを切り替えたい場合

ビルドバリアントとして切り分けて、同じソースをマクロ切替でコンパイルし直すのが一般的です。APIの違いは、cpp-httplib側でかなり吸収してくれますが、完全に同じ挙動ではないのでテストは必須です。

## どのバックエンドでも使えるAPI

証明書の検証制御、SSLServerの立ち上げ、ピア証明書の取得などは、どのバックエンドでも同じAPIで呼べます。

- [T02. SSL証明書の検証を制御する](t02-cert-verification)
- [T03. SSL/TLSサーバーを立ち上げる](t03-ssl-server)
- [T05. サーバー側でピア証明書を参照する](t05-peer-cert)

> **Note:** macOSでは、OpenSSL系のバックエンドを使う場合、システムのキーチェーンからルート証明書を自動で読む設定（`CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN`）がデフォルトで有効です。無効にしたい場合は`CPPHTTPLIB_DISABLE_MACOSX_AUTOMATIC_ROOT_CERTIFICATES`を定義してください。
